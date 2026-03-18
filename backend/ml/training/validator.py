# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Model Validator (J2).

Validates trained models against precision, recall, and FPR thresholds.
If validation fails, the model is rejected and the previous version is kept.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import structlog
from numpy.typing import NDArray

from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.training.validator")

@dataclass
class ValidationResult:
    """Result of model validation against quality thresholds."""

    precision: float
    recall: float
    fpr: float  # False positive rate
    accuracy: float
    passed: bool
    rejection_reasons: list[str]

class ModelValidator:
    """Validate model quality before deployment."""

    def __init__(self) -> None:
        cfg = get_ml_config().training
        self._precision_threshold = cfg.precision_threshold
        self._recall_threshold = cfg.recall_threshold
        self._fpr_threshold = cfg.fpr_threshold

    def validate(
        self,
        y_true: NDArray[np.integer],
        y_pred: NDArray[np.integer],
        y_scores: NDArray[np.floating] | None = None,
    ) -> ValidationResult:
        """Validate predictions against thresholds.

        Args:
            y_true: Ground truth labels (0=benign, >0=attack).
            y_pred: Predicted labels (binary: 0=benign, 1=attack).
            y_scores: Optional raw scores for FPR computation.

        Returns:
            ValidationResult with pass/fail and metrics.
        """
        # Binary: attack (>0) vs benign (0)
        true_binary = (y_true > 0).astype(int)
        pred_binary = (y_pred > 0).astype(int)

        tp = int(((pred_binary == 1) & (true_binary == 1)).sum())
        fp = int(((pred_binary == 1) & (true_binary == 0)).sum())
        fn = int(((pred_binary == 0) & (true_binary == 1)).sum())
        tn = int(((pred_binary == 0) & (true_binary == 0)).sum())

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

        reasons: list[str] = []
        if precision < self._precision_threshold:
            reasons.append(f"Precision {precision:.3f} < threshold {self._precision_threshold}")
        if recall < self._recall_threshold:
            reasons.append(f"Recall {recall:.3f} < threshold {self._recall_threshold}")
        if fpr > self._fpr_threshold:
            reasons.append(f"FPR {fpr:.3f} > threshold {self._fpr_threshold}")

        passed = len(reasons) == 0

        result = ValidationResult(
            precision=precision,
            recall=recall,
            fpr=fpr,
            accuracy=accuracy,
            passed=passed,
            rejection_reasons=reasons,
        )

        logger.info(
            "model_validation",
            precision=precision,
            recall=recall,
            fpr=fpr,
            accuracy=accuracy,
            passed=passed,
            reasons=reasons,
        )

        return result
