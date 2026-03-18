# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Online Inference Pipeline (J3 + J5 + Q1 Integration).

Reads features from Redis, runs through the ensemble scorer, generates
per-alert explanations (J5c), monitors for evasion patterns (J5d),
and produces ML alerts for events exceeding the threshold.

Q1 Enhancement: Uses EnsembleFusion for global + tenant model blending.
Every event is scored — no more silent drops on cold start.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from ml.explainability.ensemble_explainer import EnsembleExplainer
from ml.features.extractor import FeatureExtractor
from ml.meta.evasion_detector import EvasionDetector
from ml.serving.model_loader import ModelLoader

logger = structlog.get_logger("phantex.ml.serving.inference")

# How often (in scored events) we run evasion check
_EVASION_CHECK_INTERVAL = 50

class InferencePipeline:
    """Score events through the ML ensemble and generate alerts.

    J5 enhancements:
      - EnsembleExplainer produces a per-alert explanation dict.
      - EvasionDetector records every score and periodically checks
        for adversarial near-threshold clustering.
    """

    def __init__(
        self,
        feature_extractor: FeatureExtractor,
        model_loader: ModelLoader,
        explainer: EnsembleExplainer | None = None,
        evasion_detector: EvasionDetector | None = None,
    ) -> None:
        self._features = feature_extractor
        self._loader = model_loader
        self._explainer = explainer or EnsembleExplainer()
        self._evasion = evasion_detector or EvasionDetector()
        self._score_counter: int = 0

    # ── Public API ──────────────────────────────────────────────────

    async def score_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Score a single event and return an ML alert dict if threshold exceeded.

        Returns None if:
          - No model loaded (cold start / graceful degradation)
          - Score below threshold
        """
        tenant_id = event.get("tenant_id")
        agent_id = event.get("agent_id")
        if not tenant_id or not agent_id:
            return None

        # Get the ensemble for this tenant (Q1: try fused scoring first)
        # Q1: Use fused global + tenant scoring path
        features = await self._features.get_features(tenant_id, agent_id)
        feature_names = self._loader.get_feature_names(tenant_id)
        if not feature_names:
            # Fallback: use all feature keys
            feature_names = sorted(features.keys())

        # Q1: Try fused scoring (global + tenant model blending)
        start = time.monotonic()
        result = self._loader.get_fused_ensemble_result(
            tenant_id,
            features,
            feature_names,
        )
        if result is None:
            # Absolute fallback: try legacy tenant-only path
            ensemble = self._loader.get_ensemble(tenant_id)
            if ensemble is None:
                return None  # No global OR tenant model — graceful degradation
            result = ensemble.score(features, feature_names)
        elapsed_ms = (time.monotonic() - start) * 1000

        # ── J5d: Record score for evasion monitoring ─────────────────
        self._evasion.record_score(result["score"])
        self._score_counter += 1
        evasion_alert = None
        if self._score_counter % _EVASION_CHECK_INTERVAL == 0:
            evasion_alert = self._evasion.check()
            if evasion_alert.detected:
                logger.warning(
                    "evasion_detected",
                    near_threshold=evasion_alert.near_threshold_count,
                    ratio=round(evasion_alert.ratio, 2),
                    tenant_id=tenant_id,
                )

        # ── Shadow model scoring (non-alerting) ─────────────────────
        shadow_ensemble = self._loader.get_shadow_ensemble(tenant_id)
        if shadow_ensemble is not None:
            try:
                shadow_result = shadow_ensemble.score(features, feature_names)
                self._loader.shadow_tracker.record_score(
                    tenant_id,
                    shadow_result["score"],
                    shadow_result["should_alert"],
                )
            except Exception:
                logger.debug("shadow_score_error", tenant_id=tenant_id)

        if not result["should_alert"]:
            return None

        # ── J5c: Generate explanation for this alert ─────────────────
        explanation_dict: dict[str, Any] = {}
        try:
            explanation = self._explainer.explain(
                features=features,
                ordered_names=feature_names,
                ensemble_result=result,
            )
            explanation_dict = explanation.to_dict()
        except Exception as exc:
            logger.warning("explanation_generation_failed", error=str(exc))

        # Build ML alert
        alert: dict[str, Any] = {
            "alert_type": "ml_ensemble",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "event_id": event.get("event_id"),
            "score": result["score"],
            "threshold": result["threshold"],
            "attack_class": result["attack_class"],
            "stage_scores": result["stage_scores"],
            "stages_active": result["stages_active"],
            "probabilities": result.get("probabilities", {}),
            "inference_ms": round(elapsed_ms, 2),
            "timestamp": event.get("timestamp"),
            # J5c — human-readable explanation
            "explanation": explanation_dict,
            # Q1 — fusion weight diagnostics
            "fusion_weights": result.get("fusion_weights"),
        }

        # Attach evasion warning if it fired on this event
        if evasion_alert and evasion_alert.detected:
            alert["evasion_warning"] = evasion_alert.to_dict()

        logger.info(
            "ml_alert_generated",
            tenant_id=tenant_id,
            agent_id=agent_id,
            score=result["score"],
            attack_class=result["attack_class"],
            confidence=explanation_dict.get("confidence", "unknown"),
            inference_ms=round(elapsed_ms, 2),
        )

        return alert

    async def score_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score a batch of events concurrently.

        Returns list of ML alerts (only those exceeding threshold).
        """
        tasks = [self.score_event(event) for event in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        alerts: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                logger.warning("batch_score_error", error=str(r))
            elif r is not None:
                alerts.append(r)
        return alerts

    # ── Meta-detection accessors ────────────────────────────────────

    @property
    def evasion_detector(self) -> EvasionDetector:
        """Access the evasion detector for external inspection/alerts."""
        return self._evasion

    @property
    def explainer(self) -> EnsembleExplainer:
        """Access the ensemble explainer."""
        return self._explainer
