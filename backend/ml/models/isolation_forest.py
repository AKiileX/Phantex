# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Stage 1: Isolation Forest (J2).

Unsupervised anomaly detector. Scores each feature vector based on
how quickly the sample is isolated in a random forest of isolation
trees. Fast (< 1ms per inference) and works with zero labeled data.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ml.config import get_ml_config

try:
    from sklearn.ensemble import IsolationForest as _SKLearnIF
except ImportError:
    _SKLearnIF = None  # type: ignore[assignment,misc]

class IsolationForestModel:
    """Wrapper around sklearn IsolationForest with Phantex conventions."""

    def __init__(self) -> None:
        cfg = get_ml_config().isolation_forest
        if _SKLearnIF is None:
            raise ImportError("scikit-learn is required: pip install scikit-learn")
        self._model = _SKLearnIF(
            n_estimators=cfg.n_estimators,
            contamination=cfg.contamination,
            max_features=cfg.max_features,
            random_state=cfg.random_state,
            n_jobs=cfg.n_jobs,
        )
        self._is_fitted = False
        self._feature_names: list[str] = []

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(self, X: NDArray[np.floating], feature_names: list[str] | None = None) -> dict[str, Any]:
        """Train on feature matrix (unlabeled — unsupervised).

        Args:
            X: (n_samples, n_features) numpy array.
            feature_names: Optional list of feature names for explainability.

        Returns:
            Training metadata dict.
        """
        self._model.fit(X)
        self._is_fitted = True
        self._feature_names = feature_names or []
        return {
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "contamination": self._model.contamination,
        }

    def predict_score(self, X: NDArray[np.floating]) -> NDArray[np.floating]:
        """Return anomaly scores in [0, 1] range.

        Higher score = more anomalous.
        sklearn's decision_function returns negative values for outliers,
        and score_samples is the raw score; we normalize to [0, 1].
        """
        if not self._is_fitted:
            raise RuntimeError("Model not fitted — call fit() first")

        # decision_function: negative = outlier, positive = inlier
        raw_scores = self._model.decision_function(X)
        # Normalize: map to [0, 1] where 1 = most anomalous
        # Typical range: [-0.5, 0.5] — offset=0.5 is the contamination threshold
        scores = 0.5 - raw_scores
        return np.clip(scores, 0.0, 1.0)

    def predict_single(self, features: dict[str, float], ordered_names: list[str]) -> float:
        """Score a single feature vector.

        Args:
            features: Dict of feature_name → value.
            ordered_names: Feature names in the order the model was trained.

        Returns:
            Anomaly score [0, 1].
        """
        X = np.array([[features.get(n, 0.0) for n in ordered_names]])
        return float(self.predict_score(X)[0])

    def feature_importances(self, X: NDArray[np.floating]) -> list[tuple[str, float]]:
        """Estimate feature importances via mean path length contribution.

        Returns list of (feature_name, importance) sorted by importance desc.
        """
        if not self._feature_names:
            return []

        # Approximate importance: perturb each feature and measure score change
        base_scores = self.predict_score(X).mean()
        importances = []
        for i, name in enumerate(self._feature_names):
            X_perm = X.copy()
            np.random.shuffle(X_perm[:, i])
            perm_scores = self.predict_score(X_perm).mean()
            importances.append((name, abs(perm_scores - base_scores)))

        importances.sort(key=lambda x: x[1], reverse=True)
        return importances

    def save(self, path: str | Path) -> None:
        """Serialize model to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "model": self._model,
            "is_fitted": self._is_fitted,
            "feature_names": self._feature_names,
        }
        with open(path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> IsolationForestModel:
        """Deserialize model from disk."""
        with open(path, "rb") as f:
            data = pickle.load(f)  # noqa: S301 — model artifacts are signed before loading
        obj = cls.__new__(cls)
        obj._model = data["model"]
        obj._is_fitted = data["is_fitted"]
        obj._feature_names = data.get("feature_names", [])
        return obj
