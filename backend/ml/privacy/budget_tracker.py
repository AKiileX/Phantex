# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Per-User Privacy Budget Tracker (J5f).

Tracks cumulative privacy budget (ε) per user per hour.
When budget exhausted, API returns cached values.

In production: Redis-backed. This implementation: in-memory
with the same interface for unit tests and later Redis swap.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import structlog

from ml.privacy.config import DEFAULT_DP_CONFIG, DPConfig

logger = structlog.get_logger("phantex.ml.privacy.budget_tracker")

@dataclass
class BudgetStatus:
    """Current privacy budget status for a user."""

    user_id: str
    budget_remaining: float
    budget_total: float
    queries_this_window: int
    budget_exhausted: bool
    resets_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "budget_remaining": round(self.budget_remaining, 4),
            "budget_total": self.budget_total,
            "queries_this_window": self.queries_this_window,
            "budget_exhausted": self.budget_exhausted,
            "resets_at": self.resets_at,
        }

class PrivacyBudgetTracker:
    """Track privacy budget (epsilon) per user per time window.

    Each API query consuming DP noise deducts from the user's hourly budget.
    When the budget reaches 0, queries return cached (stale) values with
    an X-Privacy-Budget-Remaining: 0 header.
    """

    def __init__(self, config: DPConfig = DEFAULT_DP_CONFIG) -> None:
        self._config = config
        self._total_budget = config.per_user_hourly_budget
        self._reset_sec = config.budget_reset_seconds

        # {user_id: (window_start, spent, query_count)}
        self._budgets: dict[str, tuple[float, float, int]] = {}

    def _get_or_reset(self, user_id: str, now: float) -> tuple[float, float, int]:
        """Get current budget state, resetting if window expired."""
        if user_id in self._budgets:
            window_start, spent, count = self._budgets[user_id]
            if now - window_start < self._reset_sec:
                return window_start, spent, count

        # Reset window
        self._budgets[user_id] = (now, 0.0, 0)
        return now, 0.0, 0

    def consume(
        self,
        user_id: str,
        epsilon_cost: float,
        timestamp: float | None = None,
    ) -> BudgetStatus:
        """Consume privacy budget for a query.

        Args:
            user_id: The querying user.
            epsilon_cost: ε consumed by this query.
            timestamp: Query time (default: now).

        Returns:
            Updated BudgetStatus.
        """
        now = timestamp or time.time()
        window_start, spent, count = self._get_or_reset(user_id, now)

        new_spent = spent + epsilon_cost
        new_count = count + 1
        self._budgets[user_id] = (window_start, new_spent, new_count)

        remaining = max(0.0, self._total_budget - new_spent)
        exhausted = remaining <= 0

        if exhausted:
            logger.warning(
                "privacy_budget_exhausted",
                user_id=user_id,
                total_queries=new_count,
            )

        return BudgetStatus(
            user_id=user_id,
            budget_remaining=remaining,
            budget_total=self._total_budget,
            queries_this_window=new_count,
            budget_exhausted=exhausted,
            resets_at=window_start + self._reset_sec,
        )

    def check(
        self,
        user_id: str,
        timestamp: float | None = None,
    ) -> BudgetStatus:
        """Check budget status without consuming."""
        now = timestamp or time.time()
        window_start, spent, count = self._get_or_reset(user_id, now)
        remaining = max(0.0, self._total_budget - spent)

        return BudgetStatus(
            user_id=user_id,
            budget_remaining=remaining,
            budget_total=self._total_budget,
            queries_this_window=count,
            budget_exhausted=remaining <= 0,
            resets_at=window_start + self._reset_sec,
        )

    def has_budget(
        self,
        user_id: str,
        epsilon_cost: float = 1.0,
        timestamp: float | None = None,
    ) -> bool:
        """Quick check: does user have enough budget?"""
        status = self.check(user_id, timestamp)
        return status.budget_remaining >= epsilon_cost
