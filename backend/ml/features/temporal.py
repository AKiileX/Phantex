# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Temporal Features (J1).

Time-of-day and inter-event timing features:
hour_of_day, day_of_week, time_since_last_event, burst_duration.

These are instant features (no window) computed from the current event.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

register_feature(
    FeatureDefinition(
        name="hour_of_day",
        category="temporal",
        description="Hour of day (0–23) in UTC",
        window=None,
    )
)

register_feature(
    FeatureDefinition(
        name="day_of_week",
        category="temporal",
        description="Day of week (0=Monday, 6=Sunday)",
        window=None,
    )
)

register_feature(
    FeatureDefinition(
        name="time_since_last_event",
        category="temporal",
        description="Seconds since the agent's previous event",
        window=None,
    )
)

register_feature(
    FeatureDefinition(
        name="burst_duration",
        category="temporal",
        description="Duration (seconds) of the current activity burst (events < 2s apart)",
        window=None,
    )
)

def compute_temporal_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute temporal features.

    Args:
        events: List of event dicts sorted by timestamp_epoch ascending.
                The LAST event is the current event.
        now: Current epoch timestamp.

    Returns:
        Dict of feature_name → value.
    """
    result: dict[str, float] = {}

    # Hour and day from current UTC time
    dt = datetime.fromtimestamp(now, tz=UTC)
    result["hour_of_day"] = float(dt.hour)
    result["day_of_week"] = float(dt.weekday())

    # Time since last event
    if len(events) >= 2:
        timestamps = sorted(e.get("timestamp_epoch", 0) for e in events)
        last_ts = timestamps[-1]
        prev_ts = timestamps[-2]
        result["time_since_last_event"] = max(last_ts - prev_ts, 0.0)
    else:
        result["time_since_last_event"] = 0.0

    # Burst duration: walk backwards from most recent event,
    # while inter-event gap < 2 seconds
    if len(events) >= 2:
        timestamps = sorted(e.get("timestamp_epoch", 0) for e in events)
        burst_start = timestamps[-1]
        for i in range(len(timestamps) - 1, 0, -1):
            gap = timestamps[i] - timestamps[i - 1]
            if gap > 2.0:
                break
            burst_start = timestamps[i - 1]
        result["burst_duration"] = timestamps[-1] - burst_start
    else:
        result["burst_duration"] = 0.0

    return result
