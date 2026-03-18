# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Autoencoder Explainer (J5c).

Explains Stage 3 (Autoencoder) predictions via per-feature
reconstruction error — the features with the highest reconstruction
error are the most anomalous dimensions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.explainability.autoencoder_explainer")

@dataclass
class AutoencoderExplanation:
    """Explanation for a single autoencoder prediction."""

    score: float
    top_features: list[dict[str, Any]]
    total_reconstruction_error: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": "autoencoder",
            "score": self.score,
            "top_features": self.top_features,
            "total_reconstruction_error": self.total_reconstruction_error,
        }

class AutoencoderExplainer:
    """Explain autoencoder predictions via reconstruction error breakdown.

    The autoencoder reconstructs the input — features where the
    reconstruction differs most from the input are the anomalous
    dimensions driving the score.
    """

    def __init__(self, model: Any) -> None:
        """
        Args:
            model: Fitted AutoencoderModel instance.
        """
        if not model.is_fitted:
            raise ValueError("Model must be fitted")
        self._model = model

    def explain(
        self,
        features: dict[str, float],
        ordered_names: list[str],
        top_k: int = 3,
    ) -> AutoencoderExplanation:
        """Explain a single prediction via per-feature reconstruction error.

        Args:
            features: Feature dict.
            ordered_names: Feature names in model training order.
            top_k: Number of top features to return.

        Returns:
            AutoencoderExplanation with top anomalous features.
        """
        # Get per-feature reconstruction errors
        per_feature = self._model.reconstruction_errors_per_feature(features, ordered_names)
        score = self._model.predict_single(features, ordered_names)

        total_error = sum(err for _, err in per_feature)

        top_features = []
        for name, error in per_feature[:top_k]:
            pct_contribution = error / total_error if total_error > 0 else 0.0
            top_features.append(
                {
                    "name": name,
                    "value": float(features.get(name, 0.0)),
                    "reconstruction_error": error,
                    "pct_contribution": pct_contribution,
                    "direction": "increased_risk",
                }
            )

        return AutoencoderExplanation(
            score=score,
            top_features=top_features,
            total_reconstruction_error=total_error,
        )
