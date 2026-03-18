# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8b — Content Model Validator.

Standalone validation for trained content models.  Runs the same
quality gate checks as the trainer but on arbitrary test data.
Useful for periodic re-validation of deployed models.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ml.content.embeddings.encoder import EmbeddingEncoder
from ml.content.trained.data_store import TrainingSample

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of model validation."""

    passed: bool
    precision: float = 0.0
    recall: float = 0.0
    fpr: float = 0.0
    f1: float = 0.0
    n_samples: int = 0
    errors: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

class ContentValidator:
    """Validate a trained content model against test data.

    Parameters
    ----------
    encoder:
        Embedding encoder for feature extraction.
    precision_threshold:
        Minimum precision.
    recall_threshold:
        Minimum recall.
    fpr_threshold:
        Maximum false positive rate.
    """

    def __init__(
        self,
        encoder: EmbeddingEncoder,
        *,
        precision_threshold: float = 0.90,
        recall_threshold: float = 0.80,
        fpr_threshold: float = 0.05,
    ) -> None:
        self._encoder = encoder
        self._precision = precision_threshold
        self._recall = recall_threshold
        self._fpr = fpr_threshold

    def validate(
        self,
        model: Any,
        test_samples: list[TrainingSample],
    ) -> ValidationResult:
        """Run validation on the model with test samples.

        Returns a ValidationResult with pass/fail and metrics.
        """
        if not test_samples:
            return ValidationResult(
                passed=False,
                errors=["No test samples provided"],
            )

        if len(test_samples) < 10:
            return ValidationResult(
                passed=False,
                n_samples=len(test_samples),
                errors=[f"Too few test samples: {len(test_samples)} < 10"],
            )

        try:
            texts = [s.text for s in test_samples]
            X = self._encoder.encode_batch(texts)
            y = np.array([0 if s.label == "benign" else 1 for s in test_samples])

            y_pred = model.predict(X)

            tp = int(np.sum((y_pred > 0) & (y > 0)))
            fp = int(np.sum((y_pred > 0) & (y == 0)))
            fn = int(np.sum((y_pred == 0) & (y > 0)))
            tn = int(np.sum((y_pred == 0) & (y == 0)))

            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            fpr = fp / max(fp + tn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-8)

            errors: list[str] = []
            if precision < self._precision:
                errors.append(f"Precision {precision:.3f} < {self._precision}")
            if recall < self._recall:
                errors.append(f"Recall {recall:.3f} < {self._recall}")
            if fpr > self._fpr:
                errors.append(f"FPR {fpr:.3f} > {self._fpr}")

            return ValidationResult(
                passed=len(errors) == 0,
                precision=precision,
                recall=recall,
                fpr=fpr,
                f1=f1,
                n_samples=len(test_samples),
                errors=errors,
                details={"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            )
        except Exception as exc:
            logger.error("Validation failed: %s", exc, exc_info=True)
            return ValidationResult(
                passed=False,
                n_samples=len(test_samples),
                errors=[str(exc)],
            )
