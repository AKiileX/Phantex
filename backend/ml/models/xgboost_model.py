# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Stage 2: XGBoost Supervised Classifier (J2).

Gradient-boosted trees that classify events into attack classes.
Requires labeled data (from confirmed alerts). Output is a dict
of attack_class → probability, plus an overall risk score.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ml.config import get_ml_config

try:
    import xgboost as xgb
except ImportError:
    xgb = None  # type: ignore[assignment]

# Default attack classes supported
ATTACK_CLASSES: list[str] = [
    "benign",
    "credential_theft",
    "data_exfiltration",
    "dos",
    "lateral_movement",
    "privilege_escalation",
    "prompt_injection",
    "supply_chain",
]

class XGBoostModel:
    """Wrapper around XGBoost multi-class classifier."""

    def __init__(self, attack_classes: list[str] | None = None) -> None:
        cfg = get_ml_config().xgboost
        if xgb is None:
            raise ImportError("xgboost is required: pip install xgboost")

        self._attack_classes = attack_classes or ATTACK_CLASSES
        self._model = xgb.XGBClassifier(
            max_depth=cfg.max_depth,
            learning_rate=cfg.learning_rate,
            n_estimators=cfg.n_estimators,
            eval_metric=cfg.eval_metric,
            tree_method=cfg.tree_method,
            random_state=cfg.random_state,
            n_jobs=cfg.n_jobs,
            objective="multi:softprob",
            num_class=len(self._attack_classes),
        )
        self._is_fitted = False
        self._feature_names: list[str] = []
        # Label remapping for non-contiguous class labels (e.g. after sanitizer
        # removes all samples of a class). Maps original → packed indices.
        self._label_map: dict[int, int] | None = None
        self._inv_label_map: dict[int, int] | None = None

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    @property
    def attack_classes(self) -> list[str]:
        return self._attack_classes

    def fit(
        self,
        X: NDArray[np.floating],
        y: NDArray[np.integer],
        feature_names: list[str] | None = None,
        eval_set: list[tuple[NDArray, NDArray]] | None = None,
    ) -> dict[str, Any]:
        """Train on labeled feature matrix.

        Args:
            X: (n_samples, n_features).
            y: (n_samples,) integer class labels (index into attack_classes).
            feature_names: Feature names in column order.
            eval_set: Optional validation set for early stopping.

        Returns:
            Training metadata dict.
        """
        fit_kwargs: dict[str, Any] = {}
        if eval_set:
            fit_kwargs["eval_set"] = eval_set
            fit_kwargs["verbose"] = False

        # Defence-in-depth: remap labels to contiguous 0..K-1 range.
        # After sanitization, some classes may be entirely removed,
        # leaving gaps (e.g. [0,1,2,4,5,6,7]). XGBoost requires
        # labels in [0, num_class-1] without gaps.
        unique_labels = np.unique(y)
        n_unique = len(unique_labels)
        expected_range = np.arange(n_unique)

        if n_unique < len(self._attack_classes) or not np.array_equal(unique_labels, expected_range):
            self._label_map = {int(old): int(new) for new, old in enumerate(unique_labels)}
            self._inv_label_map = {v: k for k, v in self._label_map.items()}
            y = np.array([self._label_map[int(v)] for v in y], dtype=np.int32)
            self._model.set_params(num_class=n_unique)
            if eval_set:
                fit_kwargs["eval_set"] = [
                    (ex, np.array([self._label_map[int(v)] for v in ey], dtype=np.int32)) for ex, ey in eval_set
                ]
        else:
            self._label_map = None
            self._inv_label_map = None

        self._model.fit(X, y, **fit_kwargs)
        self._is_fitted = True
        self._feature_names = feature_names or []

        return {
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "n_classes": len(self._attack_classes),
            "n_training_classes": n_unique,
            "label_remapped": self._label_map is not None,
        }

    def predict_proba(self, X: NDArray[np.floating]) -> NDArray[np.floating]:
        """Return class probabilities (n_samples, n_classes).

        If labels were remapped during training (non-contiguous classes),
        the output is expanded back to the full class space with zeros
        for missing classes.
        """
        if not self._is_fitted:
            raise RuntimeError("Model not fitted")
        probs = self._model.predict_proba(X)

        if self._inv_label_map is not None:
            # Expand back to full class space
            full_probs = np.zeros(
                (X.shape[0], len(self._attack_classes)),
                dtype=probs.dtype,
            )
            for mapped_idx, original_idx in self._inv_label_map.items():
                if original_idx < full_probs.shape[1]:
                    full_probs[:, original_idx] = probs[:, mapped_idx]
            return full_probs

        return probs

    def predict_single(self, features: dict[str, float], ordered_names: list[str]) -> dict[str, Any]:
        """Score a single feature vector.

        Returns:
            Dict with 'score' (max non-benign probability), 'attack_class',
            and 'probabilities' dict.
        """
        X = np.array([[features.get(n, 0.0) for n in ordered_names]])
        probs = self.predict_proba(X)[0]

        probs_dict = {cls: float(probs[i]) for i, cls in enumerate(self._attack_classes)}

        # Risk score = max non-benign probability
        non_benign = {k: v for k, v in probs_dict.items() if k != "benign"}
        if non_benign:
            top_class = max(non_benign, key=non_benign.get)  # type: ignore[arg-type]
            score = non_benign[top_class]
        else:
            top_class = "benign"
            score = 0.0

        return {
            "score": score,
            "attack_class": top_class,
            "probabilities": probs_dict,
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "model": self._model,
            "is_fitted": self._is_fitted,
            "feature_names": self._feature_names,
            "attack_classes": self._attack_classes,
            "label_map": self._label_map,
            "inv_label_map": self._inv_label_map,
        }
        with open(path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> XGBoostModel:
        with open(path, "rb") as f:
            data = pickle.load(f)  # noqa: S301
        obj = cls.__new__(cls)
        obj._model = data["model"]
        obj._is_fitted = data["is_fitted"]
        obj._feature_names = data.get("feature_names", [])
        obj._attack_classes = data.get("attack_classes", ATTACK_CLASSES)
        obj._label_map = data.get("label_map")
        obj._inv_label_map = data.get("inv_label_map")
        return obj
