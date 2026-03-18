# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Velocity Features (J1).

Rate-of-change features: events_per_second, tool_calls_per_minute,
new_destinations_per_hour.

Computed from rolling windows over the event stream.
"""

from __future__ import annotations

from ml.config import ROLLING_WINDOWS
from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

register_feature(
    FeatureDefinition(
        name="events_per_second_1m",
        category="velocity",
        description="Events per second (1-minute rolling window)",
        window="1m",
    )
)

register_feature(
    FeatureDefinition(
        name="events_per_second_5m",
        category="velocity",
        description="Events per second (5-minute rolling window)",
        window="5m",
    )
)

register_feature(
    FeatureDefinition(
        name="tool_calls_per_minute_1m",
        category="velocity",
        description="Tool calls per minute (1-minute rolling window)",
        window="1m",
    )
)

register_feature(
    FeatureDefinition(
        name="tool_calls_per_minute_5m",
        category="velocity",
        description="Tool calls per minute (5-minute rolling window)",
        window="5m",
    )
)

register_feature(
    FeatureDefinition(
        name="new_destinations_per_hour",
        category="velocity",
        description="New unique network destinations per hour",
        window="1h",
    )
)

def compute_velocity_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute velocity features from recent events.

    Args:
        events: List of event dicts.
        now: Current epoch timestamp.

    Returns:
        Dict of feature_name → rate.
    """
    result: dict[str, float] = {}

    for w in ROLLING_WINDOWS:
        cutoff = now - w.seconds
        window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]
        total = len(window_events)
        tool_calls = sum(1 for e in window_events if e.get("event_type") == "TOOL_CALL")

        eps = total / max(w.seconds, 1)
        tcpm = (tool_calls / max(w.seconds, 1)) * 60.0

        result[f"events_per_second_{w.name}"] = min(eps, 100_000.0)
        result[f"tool_calls_per_minute_{w.name}"] = min(tcpm, 100_000.0)

    # New destinations per hour
    cutoff_1h = now - 3_600
    cutoff_prior = now - 7_200  # Prior hour for "new" comparison
    current_dests: set[str] = set()
    prior_dests: set[str] = set()
    for e in events:
        ts = e.get("timestamp_epoch", 0)
        dest = e.get("dest_ip", "")
        if not dest:
            continue
        if ts >= cutoff_1h:
            current_dests.add(dest)
        elif ts >= cutoff_prior:
            prior_dests.add(dest)

    new_dests = len(current_dests - prior_dests)
    result["new_destinations_per_hour"] = float(new_dests)

    return result
