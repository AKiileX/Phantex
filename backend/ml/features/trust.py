# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Trust Features (K3).

Trust-related features derived from event patterns that mirror signals
used by the Rust Trust Graph Engine.  These enable the ML model to learn
trust-degradation patterns independently of the rule engine.

Features:
  - severity distribution (low/medium/high/critical counts per window)
  - anomaly density (fraction of events with anomaly_score > threshold)
  - permission escalation rate (permission change events per window)
  - out_of_scope ratio (events flagged out-of-scope)
  - trust_volatility (stddev of per-event severity scores in window)
"""

from __future__ import annotations

import math

from ml.config import WINDOWS
from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ───────────────────────────────────────────────────

_TRUST_WINDOWS = [w for w in WINDOWS if w.name in ("5m", "1h", "24h")]

# Severity distribution (4 buckets × N windows)
for w in _TRUST_WINDOWS:
    for sev in ("low", "medium", "high", "critical"):
        register_feature(
            FeatureDefinition(
                name=f"trust_severity_{sev}_{w.name}",
                category="trust",
                description=f"Count of {sev}-severity events in last {w.name}",
                window=w.name,
            )
        )

    register_feature(
        FeatureDefinition(
            name=f"trust_anomaly_density_{w.name}",
            category="trust",
            description=f"Fraction of events with anomaly_score > 0.5 in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"trust_permission_escalation_rate_{w.name}",
            category="trust",
            description=f"Permission escalation events per minute in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"trust_out_of_scope_ratio_{w.name}",
            category="trust",
            description=f"Fraction of events flagged out-of-scope in last {w.name}",
            window=w.name,
        )
    )
    register_feature(
        FeatureDefinition(
            name=f"trust_volatility_{w.name}",
            category="trust",
            description=f"Std-dev of per-event severity scores in last {w.name}",
            window=w.name,
        )
    )

# Instant (non-windowed) aggregate features
register_feature(
    FeatureDefinition(
        name="trust_critical_event_streak",
        category="trust",
        description="Current consecutive critical-severity event streak",
        window=None,
    )
)
register_feature(
    FeatureDefinition(
        name="trust_max_severity_last_event",
        category="trust",
        description="Severity score of the most recent event (0-1 scale)",
        window=None,
    )
)

# ── Identity features (AS5 — Hardware-Backed Agent Identity) ──────────────

register_feature(
    FeatureDefinition(
        name="identity_level",
        category="trust",
        description="Agent identity assurance level (0=none … 4=attested)",
        window=None,
    )
)
register_feature(
    FeatureDefinition(
        name="identity_is_hardware",
        category="trust",
        description="1.0 if agent identity is backed by TPM/Enclave or higher",
        window=None,
    )
)
register_feature(
    FeatureDefinition(
        name="identity_is_attested",
        category="trust",
        description="1.0 if agent has passed remote attestation verification",
        window=None,
    )
)
register_feature(
    FeatureDefinition(
        name="identity_trust_boost",
        category="trust",
        description="Trust score additive boost based on identity level (0.0–0.30)",
        window=None,
    )
)

# ── Severity helpers ──────────────────────────────────────────────────────

_SEVERITY_NUMERIC: dict[str, float] = {
    "low": 0.1,
    "medium": 0.3,
    "high": 0.6,
    "critical": 1.0,
}

def _event_severity(event: dict) -> str:
    """Extract normalised severity string from an event."""
    raw = str(event.get("severity", "low")).lower().strip()
    if raw in _SEVERITY_NUMERIC:
        return raw
    # Map numeric-ish values
    try:
        v = float(raw)
        if v >= 0.8:
            return "critical"
        if v >= 0.5:
            return "high"
        if v >= 0.2:
            return "medium"
        return "low"
    except (ValueError, TypeError):
        return "low"

def _severity_score(event: dict) -> float:
    return _SEVERITY_NUMERIC.get(_event_severity(event), 0.1)

def _safe_float(value: object, default: float = 0.0) -> float:
    """Convert *value* to float, returning *default* on failure."""
    try:
        return float(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return default

def _is_permission_escalation(event: dict) -> bool:
    etype = str(event.get("event_type", "")).lower()
    action = str(event.get("action", "")).lower()
    return any(
        kw in etype or kw in action
        for kw in (
            "permission",
            "escalat",
            "privilege",
            "sudo",
            "role_change",
        )
    )

def _is_out_of_scope(event: dict) -> bool:
    if event.get("out_of_scope"):
        return True
    return str(event.get("scope_violation", "")).lower() in ("true", "1", "yes")

def _safe_std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)

# ── Compute ───────────────────────────────────────────────────────────────

def compute_trust_features(
    events: list[dict],
    now: float,
    *,
    tenant_id: str = "",
    agent_id: str = "",
) -> dict[str, float]:
    """Compute trust-related features from recent events."""
    result: dict[str, float] = {}

    for w in _TRUST_WINDOWS:
        cutoff = now - w.seconds
        window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]
        n = len(window_events)

        # Severity distribution
        sev_counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for e in window_events:
            sev_counts[_event_severity(e)] += 1
        for sev, cnt in sev_counts.items():
            result[f"trust_severity_{sev}_{w.name}"] = float(cnt)

        # Anomaly density
        anomaly_count = sum(1 for e in window_events if _safe_float(e.get("anomaly_score", 0)) > 0.5)
        result[f"trust_anomaly_density_{w.name}"] = anomaly_count / n if n > 0 else 0.0

        # Permission escalation rate (per minute)
        esc_count = sum(1 for e in window_events if _is_permission_escalation(e))
        minutes = max(w.seconds / 60.0, 1.0)
        result[f"trust_permission_escalation_rate_{w.name}"] = esc_count / minutes

        # Out-of-scope ratio
        oos_count = sum(1 for e in window_events if _is_out_of_scope(e))
        result[f"trust_out_of_scope_ratio_{w.name}"] = oos_count / n if n > 0 else 0.0

        # Trust volatility (stddev of severity scores)
        sev_scores = [_severity_score(e) for e in window_events]
        result[f"trust_volatility_{w.name}"] = _safe_std(sev_scores)

    # ── Instant features ──────────────────────────────────────────────
    # Critical event streak (scan from most recent backward)
    sorted_events = sorted(events, key=lambda e: e.get("timestamp_epoch", 0), reverse=True)
    streak = 0
    for e in sorted_events:
        if _event_severity(e) == "critical":
            streak += 1
        else:
            break
    result["trust_critical_event_streak"] = float(streak)

    # Severity of the most recent event
    if sorted_events:
        result["trust_max_severity_last_event"] = _severity_score(sorted_events[0])
    else:
        result["trust_max_severity_last_event"] = 0.0

    # ── Identity features (AS5) ───────────────────────────────────────
    if tenant_id and agent_id:
        from app.services.identity_hierarchy import compute_identity_features

        id_feats = compute_identity_features(tenant_id, agent_id)
        result.update(id_feats)
    else:
        result["identity_level"] = 0.0
        result["identity_is_hardware"] = 0.0
        result["identity_is_attested"] = 0.0
        result["identity_trust_boost"] = 0.0

    return result
