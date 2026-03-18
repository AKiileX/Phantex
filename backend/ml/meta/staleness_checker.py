# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Model Staleness Checker (J5d).

Monitors model age and fires a warning when a model has not been
retrained for >14 days. Ensures models stay current with evolving
behavioral patterns.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.meta.staleness_checker")

@dataclass
class StalenessResult:
    """Result of a staleness check."""

    stale: bool
    model_id: str
    age_days: float
    max_age_days: int
    last_trained: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "stale": self.stale,
            "model_id": self.model_id,
            "age_days": round(self.age_days, 1),
            "max_age_days": self.max_age_days,
            "last_trained": self.last_trained,
        }

class StalenessChecker:
    """Monitor model freshness."""

    def __init__(self, max_age_days: int = 14) -> None:
        """
        Args:
            max_age_days: Alert if model is older than this.
        """
        self._max_age = max_age_days
        # {model_id: last_trained_timestamp}
        self._models: dict[str, float] = {}

    def register_model(self, model_id: str, trained_at: float | None = None) -> None:
        """Register or update a model's training timestamp."""
        self._models[model_id] = trained_at or time.time()

    def check(self, model_id: str) -> StalenessResult:
        """Check if a specific model is stale."""
        last_trained = self._models.get(model_id, 0.0)
        now = time.time()
        age_days = (now - last_trained) / 86400 if last_trained > 0 else float("inf")

        stale = age_days > self._max_age

        if stale:
            logger.warning(
                "model_stale",
                model_id=model_id,
                age_days=round(age_days, 1),
                max_age=self._max_age,
            )

        return StalenessResult(
            stale=stale,
            model_id=model_id,
            age_days=age_days,
            max_age_days=self._max_age,
            last_trained=last_trained,
        )

    def check_all(self) -> list[StalenessResult]:
        """Check all registered models for staleness."""
        return [self.check(mid) for mid in self._models]

    def get_stale_models(self) -> list[StalenessResult]:
        """Return only stale models."""
        return [r for r in self.check_all() if r.stale]
