# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Cost Anomaly Detector.

Detects cost anomalies for individual agents by comparing recent
hourly spend against a rolling baseline.  Three anomaly types:
  - **spike**          — single-hour cost > 3× baseline
  - **sustained_high** — 6-hour rolling average > 2× baseline
  - **unusual_model**  — agent switches to an unusually expensive model

When a cost anomaly correlates with a behavioural security anomaly
(elevated trust-score delta or open alert on the same agent) the
event is auto-escalated to a security investigation.

All writes go to ClickHouse ``cost_anomalies`` table.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.finops.cost_anomaly")

# ── Thresholds ────────────────────────────────────────────────────────────────

_SPIKE_FACTOR = 3.0  # single-hour cost > factor × 7d avg
_SUSTAINED_FACTOR = 2.0  # 6-hour rolling avg > factor × 7d avg
_BASELINE_DAYS = 7

# ── Public API ────────────────────────────────────────────────────────────────

async def detect_anomalies(
    ch: Any,
    tenant_id: uuid.UUID,
    *,
    limit: int = 20,
    db: Any | None = None,
) -> list[dict[str, Any]]:
    """Scan for cost anomalies across all agents in a tenant.

    Returns list of anomaly dicts (max *limit*), each suitable for
    insertion into ``phantex.cost_anomalies``.
    """
    cutoff = datetime.now(UTC) - timedelta(days=_BASELINE_DAYS)
    now = datetime.now(UTC)

    # Get per-agent baselines (7-day hourly avg)
    baselines = await _agent_baselines(ch, tenant_id, cutoff)
    if not baselines:
        return []

    # Get last 6 hours of per-agent hourly costs
    recent_cutoff = now - timedelta(hours=6)
    recent = await _recent_hourly(ch, tenant_id, recent_cutoff)

    anomalies: list[dict[str, Any]] = []

    for agent_id, hours in recent.items():
        baseline = baselines.get(agent_id, 0.0)
        if baseline <= 0:
            continue

        # Spike detection — any single hour > threshold
        for _hour_ts, cost in hours:
            if cost > baseline * _SPIKE_FACTOR:
                anomalies.append(
                    _make_anomaly(
                        tenant_id,
                        agent_id,
                        "spike",
                        "high",
                        f"Hourly cost ${cost:.4f} is {cost / baseline:.1f}× the 7-day avg ${baseline:.4f}",
                        cost,
                        baseline,
                        cost / baseline,
                    )
                )

        # Sustained high — 6-hour mean
        if len(hours) >= 3:
            avg_6h = sum(c for _, c in hours) / len(hours)
            if avg_6h > baseline * _SUSTAINED_FACTOR:
                anomalies.append(
                    _make_anomaly(
                        tenant_id,
                        agent_id,
                        "sustained_high",
                        "medium",
                        f"6h avg cost ${avg_6h:.4f} is {avg_6h / baseline:.1f}× the 7-day avg ${baseline:.4f}",
                        avg_6h,
                        baseline,
                        avg_6h / baseline,
                    )
                )

    # Trim to limit
    anomalies = anomalies[:limit]

    # Enrich with related open alerts when a DB session is available.
    anomalies = await correlate_with_security(ch, tenant_id, anomalies, db=db)

    # Persist
    if anomalies:
        await _write_anomalies(ch, anomalies)

    return anomalies

async def recent_anomalies(
    ch: Any,
    tenant_id: uuid.UUID,
    range_hours: int = 24,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Fetch recently logged anomalies from ClickHouse."""
    cutoff = datetime.now(UTC) - timedelta(hours=range_hours)
    result = await ch.query(
        """
        SELECT
            agent_id, anomaly_type, severity, description,
            cost_usd, baseline_usd, deviation_factor,
            correlated_alert_id, timestamp
        FROM phantex.cost_anomalies
        WHERE tenant_id = {tid:UUID}
          AND timestamp >= {cutoff:DateTime64(3)}
        ORDER BY timestamp DESC
        LIMIT {lim:UInt32}
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff, "lim": limit},
    )
    return [
        {
            "agent_id": str(r[0]),
            "anomaly_type": r[1],
            "severity": r[2],
            "description": r[3],
            "cost_usd": round(float(r[4] or 0), 4),
            "baseline_usd": round(float(r[5] or 0), 4),
            "deviation_factor": round(float(r[6] or 0), 2),
            "correlated_alert_id": str(r[7]) if r[7] else None,
            "timestamp": r[8].isoformat() if hasattr(r[8], "isoformat") else str(r[8]),
        }
        for r in result.result_rows
    ]

# ── Correlation with security alerts ─────────────────────────────────────────

async def correlate_with_security(
    ch: Any,
    tenant_id: uuid.UUID,
    anomalies: list[dict[str, Any]],
    db: Any | None = None,
) -> list[dict[str, Any]]:
    """Check if anomalous agents also have open security alerts.

    If *db* (SQLAlchemy session) is provided, query the alerts table
    for each anomalous agent.  Returns anomalies with
    ``correlated_alert_id`` populated where a match is found.
    """
    if not db or not anomalies:
        return anomalies

    try:
        from sqlalchemy import text

        agent_ids = list({a["agent_id"] for a in anomalies})
        result = await db.execute(
            text(
                "SELECT id, agent_id FROM alerts "
                "WHERE tenant_id = :tid AND status = 'open' "
                "AND agent_id = ANY(:aids) "
                "ORDER BY created_at DESC"
            ),
            {"tid": str(tenant_id), "aids": agent_ids},
        )
        alert_map: dict[str, str] = {}
        for row in result.fetchall():
            aid = str(row[1])
            if aid not in alert_map:
                alert_map[aid] = str(row[0])

        for a in anomalies:
            corr = alert_map.get(a["agent_id"])
            if corr:
                a["correlated_alert_id"] = corr
                a["severity"] = "critical"
                a["description"] += f" — correlated with open alert {corr}"
                logger.warning(
                    "cost_security_correlation",
                    agent_id=a["agent_id"],
                    alert_id=corr,
                    anomaly=a["anomaly_type"],
                )
    except Exception:
        logger.exception("cost_security_correlation_failed")

    return anomalies

# ── Internal helpers ──────────────────────────────────────────────────────────

async def _agent_baselines(
    ch: Any,
    tenant_id: uuid.UUID,
    cutoff: datetime,
) -> dict[str, float]:
    """Compute average hourly cost per agent over the baseline window."""
    result = await ch.query(
        """
        SELECT
            agent_id,
            sum(total_cost_usd) / greatest(count(DISTINCT hour), 1) AS avg_hourly
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        GROUP BY agent_id
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff},
    )
    return {r[0]: float(r[1] or 0) for r in result.result_rows}

async def _recent_hourly(
    ch: Any,
    tenant_id: uuid.UUID,
    cutoff: datetime,
) -> dict[str, list[tuple[datetime, float]]]:
    """Return per-agent per-hour costs over the recent window."""
    result = await ch.query(
        """
        SELECT agent_id, hour, sum(total_cost_usd) AS cost
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        GROUP BY agent_id, hour
        ORDER BY agent_id, hour
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff},
    )
    out: dict[str, list[tuple[datetime, float]]] = {}
    for r in result.result_rows:
        out.setdefault(r[0], []).append((r[1], float(r[2] or 0)))
    return out

def _make_anomaly(
    tenant_id: uuid.UUID,
    agent_id: str,
    anomaly_type: str,
    severity: str,
    description: str,
    cost: float,
    baseline: float,
    deviation: float,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "anomaly_type": anomaly_type,
        "severity": severity,
        "description": description,
        "cost_usd": round(cost, 4),
        "baseline_usd": round(baseline, 4),
        "deviation_factor": round(deviation, 2),
        "correlated_alert_id": None,
        "timestamp": datetime.now(UTC),
    }

async def _write_anomalies(ch: Any, anomalies: list[dict[str, Any]]) -> None:
    """Persist anomaly records to ClickHouse."""
    cols = [
        "tenant_id",
        "agent_id",
        "anomaly_type",
        "severity",
        "description",
        "cost_usd",
        "baseline_usd",
        "deviation_factor",
        "correlated_alert_id",
        "timestamp",
    ]
    rows = [
        [
            a["tenant_id"],
            a["agent_id"],
            a["anomaly_type"],
            a["severity"],
            a["description"],
            a["cost_usd"],
            a["baseline_usd"],
            a["deviation_factor"],
            a.get("correlated_alert_id"),
            a["timestamp"],
        ]
        for a in anomalies
    ]
    try:
        await ch.insert("phantex.cost_anomalies", rows, column_names=cols)
        logger.info("cost_anomalies_written", count=len(rows))
    except Exception:
        logger.exception("cost_anomalies_write_failed")
