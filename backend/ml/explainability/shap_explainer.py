# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SHAP Explainer for XGBoost (J5c).

Uses TreeExplainer for exact Shapley values on XGBoost predictions.
Per-feature contribution to each alert — deterministic and auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.explainability.shap_explainer")

try:
    import shap
except ImportError:
    shap = None  # type: ignore[assignment]

@dataclass
class ShapExplanation:
    """SHAP explanation for a single prediction."""

    feature_contributions: list[dict[str, Any]]
    base_value: float
    predicted_value: float
    top_features: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_contributions": self.feature_contributions,
            "base_value": self.base_value,
            "predicted_value": self.predicted_value,
            "top_features": self.top_features,
        }

class ShapExplainer:
    """SHAP TreeExplainer wrapper for XGBoost Stage 2."""

    def __init__(self, xgboost_model: Any) -> None:
        """
        Args:
            xgboost_model: Fitted XGBoostModel instance.
        """
        if shap is None:
            raise ImportError("shap is required: pip install shap")

        if not xgboost_model.is_fitted:
            raise ValueError("XGBoost model must be fitted before creating explainer")

        self._model = xgboost_model
        self._explainer = shap.TreeExplainer(xgboost_model._model)
        self._feature_names: list[str] = xgboost_model._feature_names

    def explain(
        self,
        features: dict[str, float],
        ordered_names: list[str],
        top_k: int = 3,
    ) -> ShapExplanation:
        """Generate SHAP explanation for a single prediction.

        Args:
            features: Feature dict.
            ordered_names: Feature names in model training order.
            top_k: Number of top contributing features to highlight.

        Returns:
            ShapExplanation with per-feature SHAP values.
        """
        X = np.array([[features.get(n, 0.0) for n in ordered_names]])
        shap_values = self._explainer.shap_values(X)

        # shap_values shape for multiclass: list of (1, n_features) arrays
        # For binary or when we care about the "risk" class, take the max non-benign
        if isinstance(shap_values, list):
            # Multi-class: pick the class with highest predicted prob
            probs = self._model.predict_proba(X)[0]
            # Ignore class 0 (benign) if possible
            target_class = int(np.argmax(probs[1:])) + 1 if len(probs) > 1 else 0
            sv = shap_values[target_class][0]
            base_val = float(self._explainer.expected_value[target_class])
        else:
            sv = shap_values[0]
            base_val = float(
                self._explainer.expected_value
                if np.isscalar(self._explainer.expected_value)
                else self._explainer.expected_value[0]
            )

        # Build per-feature contribution list
        contributions = []
        for i, name in enumerate(ordered_names):
            contributions.append(
                {
                    "name": name,
                    "value": float(features.get(name, 0.0)),
                    "shap_value": float(sv[i]),
                    "direction": "increased_risk" if sv[i] > 0 else "decreased_risk",
                }
            )

        # Sort by absolute SHAP value for top features
        sorted_contribs = sorted(contributions, key=lambda c: abs(c["shap_value"]), reverse=True)
        top_features = sorted_contribs[:top_k]

        predicted = base_val + float(sv.sum())

        return ShapExplanation(
            feature_contributions=contributions,
            base_value=base_val,
            predicted_value=predicted,
            top_features=top_features,
        )

    def explain_batch(
        self,
        X: NDArray[np.floating],
        ordered_names: list[str],
        top_k: int = 3,
    ) -> list[ShapExplanation]:
        """Explain a batch of predictions."""
        shap_values = self._explainer.shap_values(X)

        results = []
        for idx in range(len(X)):
            if isinstance(shap_values, list):
                probs = self._model.predict_proba(X[idx : idx + 1])[0]
                target_class = int(np.argmax(probs[1:])) + 1 if len(probs) > 1 else 0
                sv = shap_values[target_class][idx]
                base_val = float(self._explainer.expected_value[target_class])
            else:
                sv = shap_values[idx]
                base_val = float(
                    self._explainer.expected_value
                    if np.isscalar(self._explainer.expected_value)
                    else self._explainer.expected_value[0]
                )

            contribs = []
            for i, name in enumerate(ordered_names):
                contribs.append(
                    {
                        "name": name,
                        "value": float(X[idx, i]),
                        "shap_value": float(sv[i]),
                        "direction": "increased_risk" if sv[i] > 0 else "decreased_risk",
                    }
                )

            sorted_c = sorted(contribs, key=lambda c: abs(c["shap_value"]), reverse=True)

            results.append(
                ShapExplanation(
                    feature_contributions=contribs,
                    base_value=base_val,
                    predicted_value=base_val + float(sv.sum()),
                    top_features=sorted_c[:top_k],
                )
            )

        return results

    def global_feature_importance(
        self,
        X: NDArray[np.floating],
        ordered_names: list[str],
    ) -> list[dict[str, Any]]:
        """Compute global feature importance via mean |SHAP| values.

        Args:
            X: Representative sample of data.
            ordered_names: Feature names.

        Returns:
            List of {name, importance} sorted descending.
        """
        shap_values = self._explainer.shap_values(X)

        # For multiclass, average across all classes
        if isinstance(shap_values, list):
            mean_abs = np.mean([np.abs(sv) for sv in shap_values], axis=0)
        else:
            mean_abs = np.abs(shap_values)

        importance = mean_abs.mean(axis=0)

        result = [{"name": name, "importance": float(importance[i])} for i, name in enumerate(ordered_names)]
        result.sort(key=lambda x: x["importance"], reverse=True)
        return result
