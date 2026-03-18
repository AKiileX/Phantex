# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Rolling Accuracy Tracker (J5d).

Tracks precision, recall, and FPR on confirmed alerts (30-day window).
Fires meta-alert when accuracy degrades beyond threshold.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.meta.accuracy_tracker")

@dataclass
class AccuracySnapshot:
    """Point-in-time accuracy metrics."""

    timestamp: float
    precision: float
    recall: float
    fpr: float
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "precision": self.precision,
            "recall": self.recall,
            "fpr": self.fpr,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
        }

class AccuracyTracker:
    """Rolling-window accuracy tracker for ML predictions."""

    def __init__(
        self,
        window_days: int = 30,
        precision_threshold: float = 0.80,
        recall_threshold: float = 0.70,
        fpr_threshold: float = 0.10,
    ) -> None:
        """
        Args:
            window_days: Rolling window size in days.
            precision_threshold: Alert when precision drops below this.
            recall_threshold: Alert when recall drops below this.
            fpr_threshold: Alert when FPR exceeds this.
        """
        self._window_sec = window_days * 86400
        # (timestamp, predicted_positive, actual_positive)
        self._predictions: deque[tuple[float, bool, bool]] = deque(maxlen=500_000)
        self._precision_thresh = precision_threshold
        self._recall_thresh = recall_threshold
        self._fpr_thresh = fpr_threshold

    def record(
        self,
        predicted_positive: bool,
        actual_positive: bool,
        timestamp: float | None = None,
    ) -> None:
        """Record a prediction outcome.

        Args:
            predicted_positive: Whether the model flagged this as positive.
            actual_positive: Whether it was confirmed positive.
            timestamp: Event time (default: now).
        """
        ts = timestamp or time.time()
        self._predictions.append((ts, predicted_positive, actual_positive))
        self._evict_old(ts)

    def _evict_old(self, now: float) -> None:
        cutoff = now - self._window_sec
        while self._predictions and self._predictions[0][0] < cutoff:
            self._predictions.popleft()

    def compute(self) -> AccuracySnapshot:
        """Compute current accuracy metrics over the window."""
        now = time.time()
        self._evict_old(now)

        tp = fp = fn = tn = 0
        for _, predicted, actual in self._predictions:
            if predicted and actual:
                tp += 1
            elif predicted and not actual:
                fp += 1
            elif not predicted and actual:
                fn += 1
            else:
                tn += 1

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)

        return AccuracySnapshot(
            timestamp=now,
            precision=precision,
            recall=recall,
            fpr=fpr,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
        )

    def check_degradation(self) -> dict[str, Any]:
        """Check if accuracy has degraded below thresholds.

        Returns:
            Dict with degraded flag and details.
        """
        snap = self.compute()
        issues = []

        if snap.precision < self._precision_thresh and (snap.true_positives + snap.false_positives) > 10:
            issues.append(
                {
                    "metric": "precision",
                    "current": snap.precision,
                    "threshold": self._precision_thresh,
                }
            )

        if snap.recall < self._recall_thresh and (snap.true_positives + snap.false_negatives) > 10:
            issues.append(
                {
                    "metric": "recall",
                    "current": snap.recall,
                    "threshold": self._recall_thresh,
                }
            )

        if snap.fpr > self._fpr_thresh and (snap.false_positives + snap.true_negatives) > 10:
            issues.append(
                {
                    "metric": "fpr",
                    "current": snap.fpr,
                    "threshold": self._fpr_thresh,
                }
            )

        return {
            "degraded": len(issues) > 0,
            "snapshot": snap.to_dict(),
            "issues": issues,
            "total_predictions": len(self._predictions),
        }
