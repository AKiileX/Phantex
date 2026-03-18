# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Evasion Pattern Detector (J5d).

Detects adversarial evasion attempts by monitoring ML score distributions
for suspicious clustering just below the alert threshold.

Normal distribution: roughly bell-shaped around mean.
Evasion attack: artificial spike in bin just below threshold (e.g., 0.65–0.70 if threshold = 0.70).
Detection: if count in [threshold-0.05, threshold] bin exceeds 3× expected → evasion suspected.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger("phantex.ml.meta.evasion_detector")

@dataclass
class EvasionAlert:
    """Alert for suspected evasion activity."""

    detected: bool
    near_threshold_count: int
    expected_count: float
    ratio: float
    recommended_action: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "near_threshold_count": self.near_threshold_count,
            "expected_count": self.expected_count,
            "ratio": self.ratio,
            "recommended_action": self.recommended_action,
            **self.details,
        }

class EvasionDetector:
    """Detect adversarial evasion via near-threshold score clustering."""

    def __init__(
        self,
        threshold: float = 0.70,
        bin_width: float = 0.05,
        ratio_trigger: float = 3.0,
        window_minutes: int = 10,
        max_threshold_adjustment: float = 0.05,
    ) -> None:
        """
        Args:
            threshold: Current ML alert threshold.
            bin_width: Width of the "just below threshold" bin.
            ratio_trigger: Trigger when near-threshold count ≥ ratio × expected.
            window_minutes: Sliding window for score collection.
            max_threshold_adjustment: Maximum automatic threshold lowering.
        """
        self._threshold = threshold
        self._bin_width = bin_width
        self._ratio_trigger = ratio_trigger
        self._window_sec = window_minutes * 60
        self._max_adjust = max_threshold_adjustment

        # (timestamp, score)
        self._scores: deque[tuple[float, float]] = deque(maxlen=100_000)

    @property
    def threshold(self) -> float:
        return self._threshold

    def record_score(self, score: float, timestamp: float | None = None) -> None:
        """Record an ML prediction score."""
        ts = timestamp or time.time()
        self._scores.append((ts, score))
        self._evict_old(ts)

    def record_scores(self, scores: list[float], timestamp: float | None = None) -> None:
        """Record a batch of scores."""
        ts = timestamp or time.time()
        for s in scores:
            self._scores.append((ts, s))
        self._evict_old(ts)

    def _evict_old(self, now: float) -> None:
        cutoff = now - self._window_sec
        while self._scores and self._scores[0][0] < cutoff:
            self._scores.popleft()

    def check(self) -> EvasionAlert:
        """Check for evasion pattern in current window.

        Returns:
            EvasionAlert with detection result and recommendation.
        """
        if len(self._scores) < 20:
            return EvasionAlert(
                detected=False,
                near_threshold_count=0,
                expected_count=0.0,
                ratio=0.0,
                recommended_action="none",
                details={"reason": "insufficient_data", "total_scores": len(self._scores)},
            )

        scores = np.array([s for _, s in self._scores])

        # Define the "just below threshold" bin
        low = self._threshold - self._bin_width
        high = self._threshold

        near_count = int(((scores >= low) & (scores < high)).sum())

        # Expected count: uniform distribution assumption across bins
        n_bins = int(1.0 / self._bin_width)
        expected = len(scores) / max(n_bins, 1)

        ratio = near_count / max(expected, 1.0)

        detected = ratio >= self._ratio_trigger

        if detected:
            action = f"lower_threshold_by_{self._max_adjust}"
            logger.warning(
                "evasion_pattern_detected",
                near_threshold=near_count,
                expected=expected,
                ratio=round(ratio, 2),
            )
        else:
            action = "none"

        return EvasionAlert(
            detected=detected,
            near_threshold_count=near_count,
            expected_count=expected,
            ratio=ratio,
            recommended_action=action,
            details={
                "threshold": self._threshold,
                "bin_range": [low, high],
                "total_scores": len(scores),
            },
        )

    def get_adjusted_threshold(self) -> float:
        """Return threshold adjusted for evasion (if detected)."""
        alert = self.check()
        if alert.detected:
            return self._threshold - self._max_adjust
        return self._threshold
