# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Baseline Profile Models (J4).

Data classes for per-agent behavioral baselines.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

@dataclass
class MetricBaseline:
    """Statistical baseline for a single metric."""

    mean: float = 0.0
    std: float = 0.0
    p95: float = 0.0
    count: int = 0  # Number of observations
    min_val: float = 0.0
    max_val: float = 0.0

@dataclass
class BaselineProfile:
    """Complete behavioral profile for a single agent.

    Mode transitions:
      LEARNING → ACTIVE (after learning_days)
      ACTIVE → STALE (after stale_days of inactivity)
      STALE → LEARNING (on next event — resets profile)
    """

    agent_id: str
    tenant_id: str
    mode: Literal["LEARNING", "ACTIVE", "STALE"] = "LEARNING"
    created_at: float = field(default_factory=time.time)
    last_event_at: float = field(default_factory=time.time)
    learning_start: float = field(default_factory=time.time)

    # Per-metric baselines (metric_name → stats)
    metrics: dict[str, MetricBaseline] = field(default_factory=dict)

    # Historical network destinations (for "new destination" detection)
    known_destinations: set[str] = field(default_factory=set)

    # Event type distribution (for Jensen-Shannon divergence)
    event_type_histogram: dict[str, int] = field(default_factory=dict)

    # Tool sequence n-gram frequency (for novel pattern detection)
    top_bigrams: dict[str, int] = field(default_factory=dict)

    # Active hours histogram (hour → count)
    hour_histogram: dict[int, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict for PostgreSQL storage."""
        return {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "mode": self.mode,
            "created_at": self.created_at,
            "last_event_at": self.last_event_at,
            "learning_start": self.learning_start,
            "metrics": {
                k: {
                    "mean": v.mean,
                    "std": v.std,
                    "p95": v.p95,
                    "count": v.count,
                    "min_val": v.min_val,
                    "max_val": v.max_val,
                }
                for k, v in self.metrics.items()
            },
            "known_destinations": list(self.known_destinations),
            "event_type_histogram": self.event_type_histogram,
            "top_bigrams": self.top_bigrams,
            "hour_histogram": {str(k): v for k, v in self.hour_histogram.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineProfile:
        """Deserialize from JSON dict."""
        profile = cls(
            agent_id=data["agent_id"],
            tenant_id=data["tenant_id"],
            mode=data.get("mode", "LEARNING"),
            created_at=data.get("created_at", time.time()),
            last_event_at=data.get("last_event_at", time.time()),
            learning_start=data.get("learning_start", time.time()),
        )
        for k, v in data.get("metrics", {}).items():
            profile.metrics[k] = MetricBaseline(
                mean=v.get("mean", 0),
                std=v.get("std", 0),
                p95=v.get("p95", 0),
                count=v.get("count", 0),
                min_val=v.get("min_val", 0),
                max_val=v.get("max_val", 0),
            )
        profile.known_destinations = set(data.get("known_destinations", []))
        profile.event_type_histogram = data.get("event_type_histogram", {})
        profile.top_bigrams = data.get("top_bigrams", {})
        profile.hour_histogram = {int(k): v for k, v in data.get("hour_histogram", {}).items()}
        return profile
