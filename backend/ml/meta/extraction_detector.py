# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Model Extraction Detector (J5d).

Monitors API query patterns for signs of model extraction attacks.

Normal: analyst queries ~10-50 entities/hour during investigation.
Extraction: >500 queries/hour with systematic patterns (sequential, random).
Detection: query rate > 10× rolling average → throttle + alert.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.meta.extraction_detector")

@dataclass
class ExtractionAlert:
    """Alert for suspected model extraction probing."""

    detected: bool
    user_id: str
    query_count: int
    rolling_average: float
    ratio: float
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "user_id": self.user_id,
            "query_count": self.query_count,
            "rolling_average": self.rolling_average,
            "ratio": self.ratio,
            "recommended_action": self.recommended_action,
        }

class ExtractionDetector:
    """Detect model extraction via API query rate anomaly."""

    def __init__(
        self,
        rate_multiplier: float = 10.0,
        window_hours: int = 1,
        throttle_limit_per_min: int = 100,
        min_queries_for_baseline: int = 20,
    ) -> None:
        """
        Args:
            rate_multiplier: Flag when rate ≥ this × rolling average.
            window_hours: Observation window.
            throttle_limit_per_min: Rate limit to apply when extraction detected.
            min_queries_for_baseline: Min queries before baseline is meaningful.
        """
        self._rate_mult = rate_multiplier
        self._window_sec = window_hours * 3600
        self._throttle_limit = throttle_limit_per_min
        self._min_baseline = min_queries_for_baseline

        # {user_id: deque[(timestamp,)]}
        self._queries: dict[str, deque[float]] = defaultdict(deque)
        # {user_id: set of entity_ids queried}
        self._entities: dict[str, set[str]] = defaultdict(set)
        # Rolling average per user (exponential moving average)
        self._avg_rate: dict[str, float] = {}

    def record_query(
        self,
        user_id: str,
        entity_id: str,
        timestamp: float | None = None,
    ) -> None:
        """Record a trust score / ML score API query."""
        ts = timestamp or time.time()
        self._queries[user_id].append(ts)
        self._entities[user_id].add(entity_id)
        self._evict_old(user_id, ts)

    def _evict_old(self, user_id: str, now: float) -> None:
        cutoff = now - self._window_sec
        q = self._queries[user_id]
        while q and q[0] < cutoff:
            q.popleft()

    def check_user(self, user_id: str) -> ExtractionAlert:
        """Check if a specific user shows extraction behavior.

        Returns:
            ExtractionAlert with detection result.
        """
        now = time.time()
        self._evict_old(user_id, now)

        query_count = len(self._queries[user_id])
        entity_count = len(self._entities.get(user_id, set()))

        # Update rolling average
        prev_avg = self._avg_rate.get(user_id, 0.0)
        alpha = 0.1  # EMA smoothing factor
        current_rate = query_count  # queries in window
        new_avg = alpha * current_rate + (1 - alpha) * prev_avg if prev_avg > 0 else current_rate
        self._avg_rate[user_id] = new_avg

        # Use baseline from EMA (after sufficient history)
        baseline = max(prev_avg, self._min_baseline)
        ratio = query_count / max(baseline, 1.0)

        detected = ratio >= self._rate_mult and query_count >= self._min_baseline

        if detected:
            action = f"throttle_to_{self._throttle_limit}_per_min"
            logger.warning(
                "extraction_probing_detected",
                user_id=user_id,
                queries=query_count,
                entities=entity_count,
                ratio=round(ratio, 2),
            )
        else:
            action = "none"

        return ExtractionAlert(
            detected=detected,
            user_id=user_id,
            query_count=query_count,
            rolling_average=baseline,
            ratio=ratio,
            recommended_action=action,
        )

    def check_all_users(self) -> list[ExtractionAlert]:
        """Check all tracked users for extraction behavior."""
        alerts = []
        for user_id in list(self._queries.keys()):
            alert = self.check_user(user_id)
            if alert.detected:
                alerts.append(alert)
        return alerts

    def should_throttle(self, user_id: str) -> bool:
        """Quick check: should we throttle this user?"""
        return self.check_user(user_id).detected
