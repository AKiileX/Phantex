# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Isolation Forest Explainer (J5c).

Explains Stage 1 (Isolation Forest) predictions via path-length analysis
and permutation-based feature importance for individual predictions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.explainability.isolation_explainer")

@dataclass
class IsolationExplanation:
    """Explanation for a single Isolation Forest prediction."""

    score: float
    top_features: list[dict[str, Any]]
    n_features_checked: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": "isolation_forest",
            "score": self.score,
            "top_features": self.top_features,
            "n_features_checked": self.n_features_checked,
        }

class IsolationForestExplainer:
    """Explain Isolation Forest predictions via feature perturbation.

    Since Isolation Forest lacks built-in feature attribution,
    we use single-feature perturbation: mask each feature to its
    mean value and measure score change. The features whose masking
    reduces the anomaly score the most are the primary drivers.
    """

    def __init__(self, model: Any) -> None:
        """
        Args:
            model: Fitted IsolationForestModel instance.
        """
        if not model.is_fitted:
            raise ValueError("Model must be fitted")
        self._model = model

    def explain(
        self,
        features: dict[str, float],
        ordered_names: list[str],
        baseline: dict[str, float] | None = None,
        top_k: int = 3,
    ) -> IsolationExplanation:
        """Explain a single prediction.

        Args:
            features: Feature dict.
            ordered_names: Feature names in model training order.
            baseline: Reference values (typically mean). If None, uses zeros.
            top_k: Number of top features to return.

        Returns:
            IsolationExplanation with feature contributions.
        """
        X_orig = np.array([[features.get(n, 0.0) for n in ordered_names]])
        base_score = float(self._model.predict_score(X_orig)[0])

        if baseline is None:
            baseline = {n: 0.0 for n in ordered_names}

        contributions = []
        for i, name in enumerate(ordered_names):
            # Replace feature with baseline value
            X_masked = X_orig.copy()
            X_masked[0, i] = baseline.get(name, 0.0)
            masked_score = float(self._model.predict_score(X_masked)[0])

            # Score drop when we mask this feature = its contribution
            contribution = base_score - masked_score
            contributions.append(
                {
                    "name": name,
                    "value": float(features.get(name, 0.0)),
                    "contribution": contribution,
                    "direction": "increased_risk" if contribution > 0 else "decreased_risk",
                }
            )

        # Sort by absolute contribution
        contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)

        return IsolationExplanation(
            score=base_score,
            top_features=contributions[:top_k],
            n_features_checked=len(ordered_names),
        )

    def batch_feature_importance(
        self,
        X: NDArray[np.floating],
        ordered_names: list[str],
    ) -> list[dict[str, Any]]:
        """Global feature importance via mean perturbation impact.

        Args:
            X: Feature matrix (representative sample).
            ordered_names: Feature names.

        Returns:
            Sorted list of {name, importance}.
        """
        base_scores = self._model.predict_score(X)
        base_mean = float(base_scores.mean())
        importances = []

        for i, name in enumerate(ordered_names):
            X_perm = X.copy()
            np.random.shuffle(X_perm[:, i])
            perm_mean = float(self._model.predict_score(X_perm).mean())
            importances.append(
                {
                    "name": name,
                    "importance": abs(perm_mean - base_mean),
                }
            )

        importances.sort(key=lambda x: x["importance"], reverse=True)
        return importances
