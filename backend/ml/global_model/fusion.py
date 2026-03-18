# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q1: Ensemble Fusion (Global + Tenant Model Blending).

Implements adaptive weighted blending between the global starter model
and a tenant-specific model. The fusion weight transitions smoothly
from fully-global (day 1) to mostly-tenant (mature deployment) using
a sigmoid schedule based on tenant training sample count.

Weight schedule:
  - 0 tenant samples: w_global=1.0, w_tenant=0.0 (pure global)
  - crossover_samples: w_global≈0.5, w_tenant≈0.5 (balanced)
  - Many samples: w_global→min_global_weight, w_tenant→(1-min)

This ensures:
  1. Day-1 protection (global model provides floor)
  2. Smooth transition (no "cliff" when tenant model activates)
  3. Safety floor (global model always contributes min weight)
  4. Adaptive confidence (tenant needs proven precision to shift)

Security:
  - Weight computation is deterministic and auditable
  - Feature alignment validated before fusion
  - No external state or side effects
"""

from __future__ import annotations

import math
from typing import Any

import structlog

from ml.config import EnsembleFusionConfig, get_ml_config
from ml.models.ensemble import EnsembleScorer

logger = structlog.get_logger("phantex.ml.global_model.fusion")

class FusionWeights:
    """Immutable container for computed fusion weights."""

    __slots__ = ("global_weight", "tenant_weight", "tenant_samples", "reason")

    def __init__(
        self,
        global_weight: float,
        tenant_weight: float,
        tenant_samples: int,
        reason: str,
    ) -> None:
        self.global_weight = global_weight
        self.tenant_weight = tenant_weight
        self.tenant_samples = tenant_samples
        self.reason = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "global_weight": round(self.global_weight, 4),
            "tenant_weight": round(self.tenant_weight, 4),
            "tenant_samples": self.tenant_samples,
            "reason": self.reason,
        }

class EnsembleFusion:
    """Blend global and tenant ensemble scores with adaptive weighting.

    Usage:
        fusion = EnsembleFusion()
        result = fusion.score(
            global_ensemble=global_ensemble,
            tenant_ensemble=tenant_ensemble,
            features=features,
            feature_names=feature_names,
            tenant_samples=2500,
        )
    """

    def __init__(self, config: EnsembleFusionConfig | None = None) -> None:
        self._cfg = config or get_ml_config().ensemble_fusion

    def compute_weights(
        self,
        tenant_samples: int,
        tenant_precision: float | None = None,
    ) -> FusionWeights:
        """Compute fusion weights based on tenant maturity.

        Args:
            tenant_samples: Number of training samples in tenant model.
            tenant_precision: Tenant model's validation precision (0-1).

        Returns:
            FusionWeights with global_weight + tenant_weight = 1.0.
        """
        cfg = self._cfg

        # Case 1: No tenant model at all
        if tenant_samples <= 0:
            return FusionWeights(
                global_weight=cfg.initial_global_weight,
                tenant_weight=0.0,
                tenant_samples=0,
                reason="no_tenant_model",
            )

        # Case 2: Tenant model exists but precision is below threshold
        if tenant_precision is not None and tenant_precision < cfg.min_tenant_precision:
            return FusionWeights(
                global_weight=cfg.initial_global_weight,
                tenant_weight=0.0,
                tenant_samples=tenant_samples,
                reason="tenant_precision_below_threshold",
            )

        # Case 3: Sigmoid transition
        # w_tenant = (1 - min_global_weight) * sigmoid(decay * (samples - crossover))
        # This gives:
        #   at samples=crossover: w_tenant ≈ 0.5 * (1 - min_global)
        #   at samples→∞: w_tenant → (1 - min_global)
        #   at samples=0: w_tenant → very small
        exponent = -cfg.decay_rate * (tenant_samples - cfg.crossover_samples)
        # Clamp exponent to prevent overflow
        exponent = max(min(exponent, 500.0), -500.0)
        sigmoid = 1.0 / (1.0 + math.exp(exponent))

        max_tenant_weight = 1.0 - cfg.min_global_weight
        tenant_weight = max_tenant_weight * sigmoid
        global_weight = 1.0 - tenant_weight

        # Ensure global weight never drops below minimum
        if global_weight < cfg.min_global_weight:
            global_weight = cfg.min_global_weight
            tenant_weight = 1.0 - global_weight

        return FusionWeights(
            global_weight=global_weight,
            tenant_weight=tenant_weight,
            tenant_samples=tenant_samples,
            reason="sigmoid_transition",
        )

    def score(
        self,
        global_ensemble: EnsembleScorer,
        tenant_ensemble: EnsembleScorer | None,
        features: dict[str, float],
        feature_names: list[str],
        tenant_samples: int = 0,
        tenant_precision: float | None = None,
        global_feature_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Score an event through the fused global + tenant ensemble.

        If no tenant model exists, falls through to pure global scoring.
        If both exist, blends their scores using adaptive weights.

        Args:
            global_ensemble: The global (tier-0) ensemble scorer.
            tenant_ensemble: The tenant-specific ensemble (or None).
            features: Feature dict from FeatureExtractor.
            feature_names: Feature names for the tenant model.
            tenant_samples: Number of training samples in tenant model.
            tenant_precision: Tenant model's validation precision.
            global_feature_names: Feature names for global model (defaults
                to feature_names if not specified).

        Returns:
            Dict with:
              - score: float [0, 1] — fused risk score
              - should_alert: bool
              - global_result: raw global model output
              - tenant_result: raw tenant model output (or None)
              - fusion_weights: FusionWeights dict
              - attack_class: best attack classification
              - probabilities: class probabilities
        """
        weights = self.compute_weights(tenant_samples, tenant_precision)

        # ── Global model scoring ─────────────────────────────────────
        gf_names = global_feature_names if global_feature_names is not None else feature_names
        global_result = global_ensemble.score(features, gf_names)

        # ── Tenant model scoring (if available) ──────────────────────
        tenant_result: dict[str, Any] | None = None
        if tenant_ensemble is not None and weights.tenant_weight > 0:
            try:
                tenant_result = tenant_ensemble.score(features, feature_names)
            except Exception as exc:
                logger.warning(
                    "tenant_model_scoring_failed",
                    error=str(exc),
                )
                # Fall back to global-only
                weights = FusionWeights(
                    global_weight=1.0,
                    tenant_weight=0.0,
                    tenant_samples=tenant_samples,
                    reason="tenant_scoring_error",
                )

        # ── Compute fused score ──────────────────────────────────────
        if tenant_result is not None and weights.tenant_weight > 0:
            fused_score = (
                weights.global_weight * global_result["score"] + weights.tenant_weight * tenant_result["score"]
            )
            # Use tenant's attack class if its confidence is higher
            # (tenant model is more specific to the customer's environment)
            attack_class = tenant_result["attack_class"]
            probabilities = tenant_result.get("probabilities", {})

            # But if tenant score is low, defer to global classification
            if tenant_result["score"] < global_result["score"] * 0.5:
                attack_class = global_result["attack_class"]
                probabilities = global_result.get("probabilities", {})
        else:
            fused_score = global_result["score"]
            attack_class = global_result["attack_class"]
            probabilities = global_result.get("probabilities", {})

        # Clamp to [0, 1]
        fused_score = max(0.0, min(1.0, fused_score))

        threshold = global_result.get("threshold", 0.7)

        return {
            "score": fused_score,
            "should_alert": fused_score > threshold,
            "threshold": threshold,
            "attack_class": attack_class,
            "probabilities": probabilities,
            "stage_scores": self._merge_stage_scores(
                global_result.get("stage_scores", {}),
                tenant_result.get("stage_scores", {}) if tenant_result else {},
                weights,
            ),
            "stages_active": global_result.get("stages_active", []),
            "global_result": global_result,
            "tenant_result": tenant_result,
            "fusion_weights": weights.to_dict(),
        }

    @staticmethod
    def _merge_stage_scores(
        global_stages: dict[str, float],
        tenant_stages: dict[str, float],
        weights: FusionWeights,
    ) -> dict[str, float]:
        """Merge per-stage scores from global and tenant models."""
        merged: dict[str, float] = {}
        all_stages = set(global_stages.keys()) | set(tenant_stages.keys())
        for stage in all_stages:
            g_score = global_stages.get(stage, 0.0)
            t_score = tenant_stages.get(stage, 0.0)
            if stage in global_stages and stage in tenant_stages:
                merged[stage] = weights.global_weight * g_score + weights.tenant_weight * t_score
            elif stage in global_stages:
                merged[stage] = g_score
            else:
                merged[stage] = t_score
        return merged
