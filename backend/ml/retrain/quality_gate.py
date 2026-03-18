# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q2: Quality Gate for Model Promotion.

Validates that a newly trained model meets minimum quality thresholds
before it can replace the current production model. This prevents
model degradation from bad training data, label noise, or
distribution shift.

Quality checks:
  1. Precision >= current_precision - tolerance
  2. Recall >= current_recall - tolerance
  3. FPR <= absolute ceiling
  4. No NaN/Inf in model outputs
  5. Model produces non-trivial predictions (not all-zero/all-one)

Security:
  - All decisions are logged with full context
  - No side effects — pure validation
  - Tolerances are configurable but bounded
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.retrain.quality_gate")

class QualityResult:
    """Result of a quality gate evaluation."""

    __slots__ = ("passed", "checks", "reason")

    def __init__(
        self,
        passed: bool,
        checks: dict[str, Any],
        reason: str,
    ) -> None:
        self.passed = passed
        self.checks = checks
        self.reason = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reason": self.reason,
            "checks": self.checks,
        }

class QualityGate:
    """Validate new model quality against configurable thresholds.

    Usage:
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.91,
            new_recall=0.83,
            new_fpr=0.04,
            current_precision=0.90,
            current_recall=0.85,
            predictions=model_predictions,
        )
        if result.passed:
            promote_model()
    """

    def __init__(self) -> None:
        cfg = get_ml_config().auto_retrain
        self._precision_tolerance = cfg.precision_regression_tolerance
        self._recall_tolerance = cfg.recall_regression_tolerance
        self._fpr_max = cfg.fpr_max

    def evaluate(
        self,
        new_precision: float,
        new_recall: float,
        new_fpr: float,
        current_precision: float = 0.0,
        current_recall: float = 0.0,
        predictions: NDArray[np.floating] | None = None,
    ) -> QualityResult:
        """Evaluate whether a new model passes quality gates.

        Args:
            new_precision: New model's validation precision.
            new_recall: New model's validation recall.
            new_fpr: New model's false positive rate.
            current_precision: Current production model's precision.
            current_recall: Current production model's recall.
            predictions: Optional array of model predictions for sanity checks.

        Returns:
            QualityResult with pass/fail and detailed check results.
        """
        checks: dict[str, Any] = {}
        failures: list[str] = []

        # Clamp inputs to valid metric ranges
        new_precision = max(0.0, min(1.0, new_precision))
        new_recall = max(0.0, min(1.0, new_recall))
        new_fpr = max(0.0, min(1.0, new_fpr))
        current_precision = max(0.0, min(1.0, current_precision))
        current_recall = max(0.0, min(1.0, current_recall))

        # Check 1: Precision regression
        precision_threshold = max(0.0, current_precision - self._precision_tolerance)
        precision_ok = new_precision >= precision_threshold
        checks["precision"] = {
            "new": round(new_precision, 4),
            "threshold": round(precision_threshold, 4),
            "current": round(current_precision, 4),
            "tolerance": self._precision_tolerance,
            "passed": precision_ok,
        }
        if not precision_ok:
            failures.append(f"precision_regression: {new_precision:.4f} < {precision_threshold:.4f}")

        # Check 2: Recall regression
        recall_threshold = max(0.0, current_recall - self._recall_tolerance)
        recall_ok = new_recall >= recall_threshold
        checks["recall"] = {
            "new": round(new_recall, 4),
            "threshold": round(recall_threshold, 4),
            "current": round(current_recall, 4),
            "tolerance": self._recall_tolerance,
            "passed": recall_ok,
        }
        if not recall_ok:
            failures.append(f"recall_regression: {new_recall:.4f} < {recall_threshold:.4f}")

        # Check 3: Absolute FPR ceiling
        fpr_ok = new_fpr <= self._fpr_max
        checks["fpr"] = {
            "new": round(new_fpr, 4),
            "max": self._fpr_max,
            "passed": fpr_ok,
        }
        if not fpr_ok:
            failures.append(f"fpr_ceiling: {new_fpr:.4f} > {self._fpr_max}")

        # Check 4: NaN/Inf check on predictions
        predictions_ok = True
        if predictions is not None:
            has_nan = bool(np.isnan(predictions).any())
            has_inf = bool(np.isinf(predictions).any())
            predictions_ok = not has_nan and not has_inf
            checks["predictions_valid"] = {
                "has_nan": has_nan,
                "has_inf": has_inf,
                "passed": predictions_ok,
            }
            if not predictions_ok:
                failures.append("predictions contain NaN or Inf")

            # Check 5: Non-trivial predictions
            if predictions_ok and len(predictions) > 0:
                all_same = bool(np.all(predictions == predictions[0]))
                checks["predictions_nontrivial"] = {
                    "all_same": all_same,
                    "passed": not all_same,
                }
                if all_same:
                    predictions_ok = False
                    failures.append("all predictions identical (trivial model)")

        passed = len(failures) == 0
        reason = "all_checks_passed" if passed else "; ".join(failures)

        if not passed:
            logger.warning(
                "quality_gate_failed",
                failures=failures,
                new_precision=round(new_precision, 4),
                new_recall=round(new_recall, 4),
                new_fpr=round(new_fpr, 4),
            )
        else:
            logger.info(
                "quality_gate_passed",
                new_precision=round(new_precision, 4),
                new_recall=round(new_recall, 4),
                new_fpr=round(new_fpr, 4),
            )

        return QualityResult(passed=passed, checks=checks, reason=reason)
