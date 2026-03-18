# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Behavioral Features (J1).

Statistical features about agent interaction patterns:
avg_response_time, avg_token_count, prompt_length_mean, prompt_length_std.
"""

from __future__ import annotations

import math

from ml.config import WINDOWS
from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

_BEHAVIORAL_WINDOWS = [w for w in WINDOWS if w.name in ("1h", "24h")]

for w in _BEHAVIORAL_WINDOWS:
    register_feature(
        FeatureDefinition(
            name=f"avg_response_time_{w.name}",
            category="behavioral",
            description=f"Average tool response time (ms) in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"avg_token_count_{w.name}",
            category="behavioral",
            description=f"Average token count per event in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"prompt_length_mean_{w.name}",
            category="behavioral",
            description=f"Mean prompt length (chars) in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"prompt_length_std_{w.name}",
            category="behavioral",
            description=f"Standard deviation of prompt length in last {w.name}",
            window=w.name,
        )
    )

def _safe_mean(values: list[float]) -> float:
    """Return mean of values, 0.0 if empty."""
    if not values:
        return 0.0
    return sum(values) / len(values)

def _safe_std(values: list[float]) -> float:
    """Return population standard deviation, 0.0 if < 2 values."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)

def compute_behavioral_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute behavioral features from recent events."""
    result: dict[str, float] = {}

    for w in _BEHAVIORAL_WINDOWS:
        cutoff = now - w.seconds
        window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]

        response_times = [float(e["tool_duration_ms"]) for e in window_events if e.get("tool_duration_ms") is not None]
        token_counts = [float(e["token_count"]) for e in window_events if e.get("token_count") is not None]
        prompt_lengths = [float(e["prompt_length"]) for e in window_events if e.get("prompt_length") is not None]

        result[f"avg_response_time_{w.name}"] = min(_safe_mean(response_times), 1_000_000.0)
        result[f"avg_token_count_{w.name}"] = min(_safe_mean(token_counts), 1_000_000.0)
        result[f"prompt_length_mean_{w.name}"] = min(_safe_mean(prompt_lengths), 1_000_000.0)
        result[f"prompt_length_std_{w.name}"] = min(_safe_std(prompt_lengths), 1_000_000.0)

    return result
