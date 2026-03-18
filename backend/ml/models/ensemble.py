# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Ensemble Scorer (J2).

Weighted combination of all 3 ML stages to produce a final risk score.
If a stage is unavailable (not trained yet), it is skipped and remaining
weights are renormalized.
"""

from __future__ import annotations

from typing import Any

from ml.config import get_ml_config

class EnsembleScorer:
    """
    Combine Stage 1 (Isolation Forest), Stage 2 (XGBoost), Stage 3 (Autoencoder)
    into a single risk score and attack classification.
    """

    def __init__(
        self,
        stage1=None,
        stage2=None,
        stage3=None,
    ) -> None:
        """
        Args:
            stage1: IsolationForestModel (or None if not available).
            stage2: XGBoostModel (or None).
            stage3: AutoencoderModel (or None).
        """
        self._stage1 = stage1
        self._stage2 = stage2
        self._stage3 = stage3
        cfg = get_ml_config().ensemble
        self._w1 = cfg.weight_stage1
        self._w2 = cfg.weight_stage2
        self._w3 = cfg.weight_stage3
        self._threshold = cfg.alert_threshold

    @property
    def alert_threshold(self) -> float:
        return self._threshold

    def score(
        self,
        features: dict[str, float],
        ordered_names: list[str],
    ) -> dict[str, Any]:
        """Score a single feature vector through the ensemble.

        Returns dict with:
            - score: float [0, 1] — ensemble anomaly score
            - should_alert: bool — score > threshold
            - stage_scores: dict of stage → individual score
            - attack_class: str — predicted attack class (from Stage 2)
            - probabilities: dict of class → prob (from Stage 2)
        """
        stage_scores: dict[str, float] = {}
        weights: dict[str, float] = {}
        attack_class = "unknown"
        probabilities: dict[str, float] = {}

        # Stage 1: Isolation Forest (unsupervised)
        if self._stage1 is not None and self._stage1.is_fitted:
            s1 = self._stage1.predict_single(features, ordered_names)
            stage_scores["isolation_forest"] = s1
            weights["isolation_forest"] = self._w1

        # Stage 2: XGBoost (supervised)
        if self._stage2 is not None and self._stage2.is_fitted:
            result = self._stage2.predict_single(features, ordered_names)
            stage_scores["xgboost"] = result["score"]
            weights["xgboost"] = self._w2
            attack_class = result["attack_class"]
            probabilities = result["probabilities"]

        # Stage 3: Autoencoder (reconstruction)
        if self._stage3 is not None and self._stage3.is_fitted:
            s3 = self._stage3.predict_single(features, ordered_names)
            stage_scores["autoencoder"] = s3
            weights["autoencoder"] = self._w3

        # Compute weighted ensemble score
        total_weight = sum(weights.values())
        if total_weight > 0:
            score = sum(stage_scores[stage] * weights[stage] for stage in stage_scores) / total_weight
        else:
            # No models available — pass through
            score = 0.0

        return {
            "score": score,
            "should_alert": score > self._threshold,
            "stage_scores": stage_scores,
            "attack_class": attack_class,
            "probabilities": probabilities,
            "threshold": self._threshold,
            "stages_active": list(stage_scores.keys()),
        }
