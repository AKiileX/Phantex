# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8b — Content Model Trainer.

Training pipeline for the content classifier:
1. Load labeled samples from TrainingDataStore.
2. Encode all texts via EmbeddingEncoder → feature matrix.
3. Train a lightweight sklearn classifier (LogisticRegression or XGBoost).
4. Validate precision ≥ 0.90, recall ≥ 0.80, FPR ≤ 0.05.
5. Return trained model + metrics for shadow-mode deployment.

Follows the same pattern as the behavioral ``trainer.py`` (J3):
- Deterministic with seed control for reproducibility.
- Produces a training manifest (provenance).
- Integrates with data sanitization (J5b).

Thread-safety: training is inherently single-threaded; the trainer
creates a new model that is atomically swapped into the classifier.
"""

from __future__ import annotations

import hashlib
import logging
import pickle
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ml.content.embeddings.encoder import EmbeddingEncoder
from ml.content.trained.data_store import TrainingDataStore, TrainingSample

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------
_MIN_SAMPLES = 50  # Minimum training samples required
_PRECISION_THRESHOLD = 0.90  # Gate: precision must be ≥ this
_RECALL_THRESHOLD = 0.80  # Gate: recall must be ≥ this
_FPR_THRESHOLD = 0.05  # Gate: false positive rate must be ≤ this
_DEFAULT_SEED = 42

@dataclass
class TrainingMetrics:
    """Validation metrics from a training run."""

    precision: float = 0.0
    recall: float = 0.0
    fpr: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0
    train_samples: int = 0
    test_samples: int = 0
    train_positives: int = 0
    test_positives: int = 0
    classes: list[str] = field(default_factory=list)
    passed_gate: bool = False
    gate_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "fpr": round(self.fpr, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "train_samples": self.train_samples,
            "test_samples": self.test_samples,
            "train_positives": self.train_positives,
            "test_positives": self.test_positives,
            "classes": self.classes,
            "passed_gate": self.passed_gate,
            "gate_details": self.gate_details,
        }

@dataclass
class TrainingResult:
    """Full result of a training run."""

    success: bool
    model: Any | None = None
    classes: list[str] = field(default_factory=list)
    metrics: TrainingMetrics | None = None
    model_hash: str = ""
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "model_hash": self.model_hash,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
            "metrics": self.metrics.to_dict() if self.metrics else None,
        }

class ContentTrainer:
    """Train a content classifier from labeled samples.

    Parameters
    ----------
    encoder:
        Embedding encoder for feature extraction.
    precision_threshold:
        Minimum precision to pass the quality gate.
    recall_threshold:
        Minimum recall to pass the quality gate.
    fpr_threshold:
        Maximum FPR to pass the quality gate.
    seed:
        Random seed for reproducibility.
    """

    def __init__(
        self,
        encoder: EmbeddingEncoder,
        *,
        precision_threshold: float = _PRECISION_THRESHOLD,
        recall_threshold: float = _RECALL_THRESHOLD,
        fpr_threshold: float = _FPR_THRESHOLD,
        seed: int = _DEFAULT_SEED,
    ) -> None:
        self._encoder = encoder
        self._precision_thresh = precision_threshold
        self._recall_thresh = recall_threshold
        self._fpr_thresh = fpr_threshold
        self._seed = seed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train(
        self,
        data_store: TrainingDataStore,
        *,
        mode: str = "binary",
        algorithm: str = "logistic_regression",
    ) -> TrainingResult:
        """Run the full training pipeline.

        Parameters
        ----------
        data_store:
            Training data source.
        mode:
            ``"binary"`` (benign vs malicious) or ``"multiclass"``
            (benign vs per-category labels).
        algorithm:
            ``"logistic_regression"`` (default) or ``"xgboost"``.

        Returns
        -------
        TrainingResult with model, metrics, and pass/fail gate status.
        """
        t0 = time.monotonic()

        # Validate parameters
        _VALID_MODES = ("binary", "multiclass")
        _VALID_ALGORITHMS = ("logistic_regression", "xgboost")
        if mode not in _VALID_MODES:
            return TrainingResult(
                success=False,
                error=f"Invalid mode '{mode}'; expected one of {_VALID_MODES}",
            )
        if algorithm not in _VALID_ALGORITHMS:
            return TrainingResult(
                success=False,
                error=f"Invalid algorithm '{algorithm}'; expected one of {_VALID_ALGORITHMS}",
            )

        try:
            return self._run_pipeline(data_store, mode=mode, algorithm=algorithm)
        except Exception as exc:
            logger.error("Content training failed: %s", exc, exc_info=True)
            return TrainingResult(
                success=False,
                error=str(exc),
                duration_seconds=time.monotonic() - t0,
            )

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def _run_pipeline(
        self,
        data_store: TrainingDataStore,
        *,
        mode: str,
        algorithm: str,
    ) -> TrainingResult:
        t0 = time.monotonic()

        # Step 1: Split data
        train_samples, test_samples = data_store.get_training_split(test_fraction=0.2, min_confidence=0.5)

        if len(train_samples) < _MIN_SAMPLES:
            return TrainingResult(
                success=False,
                error=f"Insufficient training data: {len(train_samples)} < {_MIN_SAMPLES}",
                duration_seconds=time.monotonic() - t0,
            )

        # Step 2: Encode features
        train_texts = [s.text for s in train_samples]
        test_texts = [s.text for s in test_samples]

        logger.info("Encoding %d train + %d test samples", len(train_texts), len(test_texts))
        X_train = self._encoder.encode_batch(train_texts)
        X_test = self._encoder.encode_batch(test_texts) if test_texts else np.zeros((0, self._encoder.dimension))

        # Step 3: Build labels
        if mode == "binary":
            y_train = np.array([0 if s.label == "benign" else 1 for s in train_samples])
            y_test = np.array([0 if s.label == "benign" else 1 for s in test_samples])
            classes = ["benign", "malicious"]
        else:
            # Multi-class: use category as label
            all_categories = sorted({s.category for s in train_samples + test_samples})
            cat_to_idx = {c: i for i, c in enumerate(all_categories)}
            y_train = np.array([cat_to_idx.get(s.category, 0) for s in train_samples])
            y_test = np.array([cat_to_idx.get(s.category, 0) for s in test_samples])
            classes = all_categories

        # Step 4: Sample weights (analyst > synthetic > seed)
        sample_weights = self._compute_sample_weights(train_samples)

        # Step 5: Train
        logger.info("Training %s classifier (%s mode)", algorithm, mode)
        model = self._train_model(X_train, y_train, sample_weights, algorithm, mode)

        # Step 6: Validate
        metrics = self._validate(model, X_test, y_test, classes, train_samples, test_samples)

        # Step 7: Model hash (128-bit for integrity)
        model_hash = hashlib.sha256(pickle.dumps(model)).hexdigest()[:32]

        duration = time.monotonic() - t0

        logger.info(
            "Training complete: precision=%.3f recall=%.3f fpr=%.3f passed=%s (%.1fs)",
            metrics.precision,
            metrics.recall,
            metrics.fpr,
            metrics.passed_gate,
            duration,
        )

        return TrainingResult(
            success=metrics.passed_gate,
            model=model,
            classes=classes,
            metrics=metrics,
            model_hash=model_hash,
            duration_seconds=duration,
        )

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def _train_model(
        self,
        X: NDArray,
        y: NDArray,
        weights: NDArray,
        algorithm: str,
        mode: str,
    ) -> Any:
        """Train the classifier."""
        if algorithm == "xgboost":
            return self._train_xgboost(X, y, weights, mode)
        return self._train_logistic(X, y, weights)

    def _train_logistic(
        self,
        X: NDArray,
        y: NDArray,
        weights: NDArray,
    ) -> Any:
        """Train Logistic Regression."""
        from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]

        model = LogisticRegression(
            C=1.0,
            max_iter=1000,
            solver="lbfgs",
            random_state=self._seed,
            class_weight="balanced",
        )
        model.fit(X, y, sample_weight=weights)
        return model

    def _train_xgboost(
        self,
        X: NDArray,
        y: NDArray,
        weights: NDArray,
        mode: str,
    ) -> Any:
        """Train XGBoost classifier."""
        import xgboost as xgb  # type: ignore[import-untyped]

        n_classes = len(np.unique(y))
        objective = "binary:logistic" if n_classes <= 2 else "multi:softprob"

        params: dict[str, Any] = {
            "objective": objective,
            "n_estimators": 100,
            "max_depth": 4,
            "learning_rate": 0.1,
            "random_state": self._seed,
            "eval_metric": "logloss",
        }
        if n_classes > 2:
            params["num_class"] = n_classes

        model = xgb.XGBClassifier(**params)
        model.fit(X, y, sample_weight=weights)
        return model

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(
        self,
        model: Any,
        X_test: NDArray,
        y_test: NDArray,
        classes: list[str],
        train_samples: list[TrainingSample],
        test_samples: list[TrainingSample],
    ) -> TrainingMetrics:
        """Compute validation metrics and check quality gate."""
        if len(X_test) == 0 or len(y_test) == 0:
            return TrainingMetrics(
                classes=classes,
                train_samples=len(train_samples),
                test_samples=0,
                passed_gate=False,
                gate_details={"reason": "no_test_data"},
            )

        y_pred = model.predict(X_test)

        # Binary metrics (treat non-zero as positive)
        tp = int(np.sum((y_pred > 0) & (y_test > 0)))
        fp = int(np.sum((y_pred > 0) & (y_test == 0)))
        fn = int(np.sum((y_pred == 0) & (y_test > 0)))
        tn = int(np.sum((y_pred == 0) & (y_test == 0)))

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-8)
        accuracy = (tp + tn) / max(tp + fp + fn + tn, 1)

        # Quality gate
        gate_details: dict[str, Any] = {}
        passed = True

        if precision < self._precision_thresh:
            gate_details["precision_fail"] = f"{precision:.3f} < {self._precision_thresh}"
            passed = False
        if recall < self._recall_thresh:
            gate_details["recall_fail"] = f"{recall:.3f} < {self._recall_thresh}"
            passed = False
        if fpr > self._fpr_thresh:
            gate_details["fpr_fail"] = f"{fpr:.3f} > {self._fpr_thresh}"
            passed = False

        train_positives = sum(1 for s in train_samples if s.label != "benign")
        test_positives = sum(1 for s in test_samples if s.label != "benign")

        return TrainingMetrics(
            precision=precision,
            recall=recall,
            fpr=fpr,
            f1=f1,
            accuracy=accuracy,
            train_samples=len(train_samples),
            test_samples=len(test_samples),
            train_positives=train_positives,
            test_positives=test_positives,
            classes=classes,
            passed_gate=passed,
            gate_details=gate_details,
        )

    # ------------------------------------------------------------------
    # Sample weighting
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_sample_weights(samples: list[TrainingSample]) -> NDArray:
        """Weight samples: analyst > seed > synthetic."""
        source_weights = {
            "analyst": 3.0,  # Highest — real production data
            "seed": 1.0,  # Built-in examples
            "synthetic": 0.5,  # Augmented — lower trust
        }
        weights = np.array([source_weights.get(s.source, 1.0) * s.confidence for s in samples], dtype=np.float32)

        # Normalize to mean=1
        mean_w = weights.mean()
        if mean_w > 0:
            weights /= mean_w

        return weights
