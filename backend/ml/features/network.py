# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Network Features (J1).

Aggregate network traffic features: bytes_sent_total, bytes_recv_total,
outbound_ratio, unique_ports.
"""

from __future__ import annotations

from ml.config import WINDOWS
from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

_NET_WINDOWS = [w for w in WINDOWS if w.name in ("5m", "1h")]

for w in _NET_WINDOWS:
    register_feature(
        FeatureDefinition(
            name=f"bytes_sent_total_{w.name}",
            category="network",
            description=f"Total bytes sent in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"bytes_recv_total_{w.name}",
            category="network",
            description=f"Total bytes received in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"outbound_ratio_{w.name}",
            category="network",
            description=f"Ratio of outbound to total bytes in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"unique_ports_{w.name}",
            category="network",
            description=f"Unique destination ports in last {w.name}",
            window=w.name,
        )
    )

def _safe_int(value: object, default: int = 0) -> int:
    """Convert *value* to ``int``, returning *default* on failure.

    Handles ``None``, empty strings, floats and non-numeric strings
    without raising.
    """
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def compute_network_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute network features from recent events."""
    result: dict[str, float] = {}

    for w in _NET_WINDOWS:
        cutoff = now - w.seconds
        window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]

        bytes_sent = 0
        bytes_recv = 0
        ports: set[int] = set()

        for e in window_events:
            bs = _safe_int(e.get("bytes_out", 0))
            br = _safe_int(e.get("bytes_in", 0))
            port = _safe_int(e.get("dest_port"), default=-1)
            bytes_sent += bs
            bytes_recv += br
            if port > 0:
                ports.add(port)

        total_bytes = bytes_sent + bytes_recv
        ratio = (bytes_sent / total_bytes) if total_bytes > 0 else 0.0

        result[f"bytes_sent_total_{w.name}"] = float(min(bytes_sent, 10_000_000_000))
        result[f"bytes_recv_total_{w.name}"] = float(min(bytes_recv, 10_000_000_000))
        result[f"outbound_ratio_{w.name}"] = ratio
        result[f"unique_ports_{w.name}"] = float(len(ports))

    return result
