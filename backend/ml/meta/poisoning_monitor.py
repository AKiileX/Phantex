# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Training Poisoning Monitor (J5d).

Monitors training label distribution for signs of label-flipping
poisoning attacks. If false-positive dismissal rate exceeds 2×
normal, fires a meta-alert to the ML team.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.meta.poisoning_monitor")

@dataclass
class PoisoningAlert:
    """Alert for suspected training data poisoning."""

    detected: bool
    dismissal_rate: float
    baseline_rate: float
    ratio: float
    window_events: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "dismissal_rate": self.dismissal_rate,
            "baseline_rate": self.baseline_rate,
            "ratio": self.ratio,
            "window_events": self.window_events,
        }

class PoisoningMonitor:
    """Monitor label distribution for poisoning signals."""

    def __init__(
        self,
        ratio_threshold: float = 2.0,
        window_days: int = 7,
        min_events: int = 20,
    ) -> None:
        """
        Args:
            ratio_threshold: Alert when dismissal rate ≥ this × baseline.
            window_days: Sliding window for recent labels.
            min_events: Minimum label events before alerting.
        """
        self._ratio_threshold = ratio_threshold
        self._window_sec = window_days * 86400
        self._min_events = min_events

        # (timestamp, is_dismissal)
        self._labels: deque[tuple[float, bool]] = deque()
        self._baseline_rate: float = 0.05  # 5% dismissal rate as default

    def set_baseline_rate(self, rate: float) -> None:
        """Set the baseline false-positive dismissal rate."""
        self._baseline_rate = max(rate, 0.001)

    def record_label(
        self,
        is_dismissal: bool,
        timestamp: float | None = None,
    ) -> None:
        """Record a label decision (confirm or dismiss)."""
        ts = timestamp or time.time()
        self._labels.append((ts, is_dismissal))
        self._evict_old(ts)

    def _evict_old(self, now: float) -> None:
        cutoff = now - self._window_sec
        while self._labels and self._labels[0][0] < cutoff:
            self._labels.popleft()

    def check(self) -> PoisoningAlert:
        """Check for abnormal dismissal rate.

        Returns:
            PoisoningAlert with detection result.
        """
        now = time.time()
        self._evict_old(now)

        total = len(self._labels)
        if total < self._min_events:
            return PoisoningAlert(
                detected=False,
                dismissal_rate=0.0,
                baseline_rate=self._baseline_rate,
                ratio=0.0,
                window_events=total,
            )

        dismissals = sum(1 for _, d in self._labels if d)
        rate = dismissals / total
        ratio = rate / max(self._baseline_rate, 0.001)

        detected = ratio >= self._ratio_threshold

        if detected:
            logger.warning(
                "poisoning_signal_detected",
                dismissal_rate=round(rate, 4),
                baseline_rate=self._baseline_rate,
                ratio=round(ratio, 2),
                total_labels=total,
            )

        return PoisoningAlert(
            detected=detected,
            dismissal_rate=rate,
            baseline_rate=self._baseline_rate,
            ratio=ratio,
            window_events=total,
        )
