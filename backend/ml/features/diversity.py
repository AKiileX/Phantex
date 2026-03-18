# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Diversity Features (J1).

Uniqueness/cardinality features: unique_tools_used, unique_files_accessed,
unique_network_dests over 1h and 24h windows.
"""

from __future__ import annotations

from ml.config import WINDOWS
from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

_DIV_WINDOWS = [w for w in WINDOWS if w.name in ("1h", "24h")]

for w in _DIV_WINDOWS:
    register_feature(
        FeatureDefinition(
            name=f"unique_tools_used_{w.name}",
            category="diversity",
            description=f"Unique tool names used in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"unique_files_accessed_{w.name}",
            category="diversity",
            description=f"Unique file paths accessed in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"unique_network_dests_{w.name}",
            category="diversity",
            description=f"Unique network destinations in last {w.name}",
            window=w.name,
        )
    )

def compute_diversity_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute diversity (cardinality) features from recent events."""
    result: dict[str, float] = {}

    for w in _DIV_WINDOWS:
        cutoff = now - w.seconds
        window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]

        tools: set[str] = set()
        files: set[str] = set()
        dests: set[str] = set()

        for e in window_events:
            tool = e.get("tool_name")
            if tool:
                tools.add(tool)
            fp = e.get("file_path")
            if fp:
                files.add(fp)
            dest = e.get("dest_ip")
            if dest:
                dests.add(dest)

        result[f"unique_tools_used_{w.name}"] = float(len(tools))
        result[f"unique_files_accessed_{w.name}"] = float(len(files))
        result[f"unique_network_dests_{w.name}"] = float(len(dests))

    return result
