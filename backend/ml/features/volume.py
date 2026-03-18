# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Volume Features (J1).

Count-based features over sliding time windows:
  event_count, tool_call_count, file_read_count, network_connect_count

Events are tracked in Redis sorted sets (score = timestamp) per agent,
and the extractor queries the count within each window.
"""

from __future__ import annotations

from ml.config import WINDOWS
from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

_VOLUME_TYPES: list[tuple[str, str, str | None]] = [
    ("event_count", "Total events", None),
    ("tool_call_count", "Tool call events", "TOOL_CALL"),
    ("file_read_count", "File read events", "FILE_READ"),
    ("network_connect_count", "Network connect events", "NETWORK_CONNECT"),
]

# Register each type × window combination
for _base, _desc, _etype in _VOLUME_TYPES:
    for w in WINDOWS:
        register_feature(
            FeatureDefinition(
                name=f"{_base}_{w.name}",
                category="volume",
                description=f"{_desc} in last {w.name}",
                window=w.name,
            )
        )

def compute_volume_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute volume features from a list of recent events.

    Args:
        events: List of event dicts (must have 'timestamp_epoch' and 'event_type').
        now: Current epoch timestamp (seconds).

    Returns:
        Dict of feature_name → count.
    """
    result: dict[str, float] = {}

    for base, _desc, event_type in _VOLUME_TYPES:
        for w in WINDOWS:
            cutoff = now - w.seconds
            count = 0
            for e in events:
                ts = e.get("timestamp_epoch", 0)
                if ts < cutoff:
                    continue
                if event_type is None or e.get("event_type") == event_type:
                    count += 1
            result[f"{base}_{w.name}"] = float(min(count, 1_000_000))

    return result
