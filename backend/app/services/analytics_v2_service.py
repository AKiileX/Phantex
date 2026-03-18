# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Advanced Analytics Service

Drill-down query builder for the new AC materialized views.
All queries are tenant-scoped via parameterized SQL — no string interpolation.

Provides:
  - KPI summary (total events, alerts, agents, attack classes)
  - Severity trend (daily severity distribution)
  - Attack class trend (daily attack-class breakdown)
  - Top agents by risk (critical+high events)
  - Tool heatmap (hourly tool-call frequency)
  - Framework breakdown (daily framework distribution)
  - Data volume trend (hourly bytes in/out)
  - Drill-down (arbitrary 2-dimension grouping on raw events)
  - CSV export helper
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from clickhouse_connect.driver.asyncclient import AsyncClient

from app.utils.logging import get_logger

logger = get_logger("phantex.analytics_v2")

# ── Range / interval helpers (shared with v1) ────────────────────────────────

_RANGE_MAP: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "12h": timedelta(hours=12),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}

ValidRange = Literal["1h", "6h", "12h", "24h", "7d", "30d", "90d"]

def _since(range_str: str) -> datetime:
    delta = _RANGE_MAP.get(range_str)
    if delta is None:
        raise ValueError(f"Invalid range: {range_str}")
    return datetime.now(UTC) - delta

# ── KPI Summary ──────────────────────────────────────────────────────────────

async def kpi_summary(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "24h",
    pg_alert_count: int | None = None,
    pg_severity_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Single-row KPI summary: total events, alerts, agents, attack classes.

    If *pg_alert_count* is provided (from PostgreSQL), it is used as the
    authoritative alerts total.  Likewise *pg_severity_counts* overrides
    the CH-derived critical/high/medium/low counts.
    """
    s = _since(range_str)
    result = await ch.query(
        """
        SELECT
            count()                                                   AS total_events,
            countIf(event_type = 'ALERT')                             AS ch_alert_events,
            uniqExactIf(agent_id, agent_id != '')                     AS active_agents,
            uniqExactIf(attack_class, attack_class IS NOT NULL)       AS attack_classes,
            countIf(severity = 'critical')                            AS critical_count,
            countIf(severity = 'high')                                AS high_count,
            countIf(severity = 'medium')                              AS medium_count,
            countIf(severity = 'low')                                 AS low_count,
            sum(ifNull(bytes_sent, 0))                                AS bytes_sent,
            sum(ifNull(bytes_recv, 0))                                AS bytes_recv
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND timestamp >= {since:DateTime64(3)}
        """,
        parameters={"tid": str(tenant_id), "since": s},
    )
    row = result.first_row
    alerts = pg_alert_count if pg_alert_count is not None else row[1]
    sev = pg_severity_counts or {}
    return {
        "total_events": row[0],
        "total_alerts": alerts,
        "active_agents": row[2],
        "attack_classes": row[3],
        "critical": sev.get("critical", row[4]),
        "high": sev.get("high", row[5]),
        "medium": sev.get("medium", row[6]),
        "low": sev.get("low", row[7]),
        "bytes_sent": row[8],
        "bytes_recv": row[9],
        "range": range_str,
    }

# ── Severity Trend (daily) ──────────────────────────────────────────────────

async def severity_trend(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "30d",
) -> list[dict[str, Any]]:
    s = _since(range_str)
    result = await ch.query(
        """
        SELECT day, severity, sum(event_count) AS count
        FROM phantex.severity_daily
        WHERE tenant_id = {tid:UUID} AND day >= {since:Date}
        GROUP BY day, severity
        ORDER BY day
        """,
        parameters={"tid": str(tenant_id), "since": s.date()},
    )
    return [{"day": str(r[0]), "severity": r[1], "count": r[2]} for r in result.result_rows]

# ── Attack Class Trend (daily) ───────────────────────────────────────────────

async def attack_class_trend(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "30d",
) -> list[dict[str, Any]]:
    s = _since(range_str)
    result = await ch.query(
        """
        SELECT day, attack_class, sum(event_count) AS count, sum(unique_agents) AS agents
        FROM phantex.attack_class_daily
        WHERE tenant_id = {tid:UUID} AND day >= {since:Date}
        GROUP BY day, attack_class
        ORDER BY day
        """,
        parameters={"tid": str(tenant_id), "since": s.date()},
    )
    return [{"day": str(r[0]), "attack_class": r[1], "count": r[2], "agents": r[3]} for r in result.result_rows]

# ── Top Agents by Risk ───────────────────────────────────────────────────────

async def top_agents_risk(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "7d",
    limit: int = 20,
) -> list[dict[str, Any]]:
    s = _since(range_str)
    limit = max(1, min(limit, 100))
    result = await ch.query(
        """
        SELECT
            agent_id,
            sum(total_events)   AS total_events,
            sum(critical_count) AS critical,
            sum(high_count)     AS high,
            sum(medium_count)   AS medium,
            sum(low_count)      AS low,
            sum(attack_count)   AS attacks,
            sum(bytes_sent)     AS bytes_sent,
            sum(bytes_recv)     AS bytes_recv
        FROM phantex.agent_risk_daily
        WHERE tenant_id = {tid:UUID} AND day >= {since:Date}
          AND agent_id != ''
        GROUP BY agent_id
        ORDER BY critical DESC, high DESC, attacks DESC
        LIMIT {lim:UInt32}
        """,
        parameters={"tid": str(tenant_id), "since": s.date(), "lim": limit},
    )
    return [
        {
            "agent_id": str(r[0]),
            "total_events": r[1],
            "critical": r[2],
            "high": r[3],
            "medium": r[4],
            "low": r[5],
            "attacks": r[6],
            "bytes_sent": r[7],
            "bytes_recv": r[8],
        }
        for r in result.result_rows
    ]

# ── Tool Heatmap (hourly) ───────────────────────────────────────────────────

async def tool_heatmap(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "7d",
    limit: int = 20,
) -> list[dict[str, Any]]:
    s = _since(range_str)
    limit = max(1, min(limit, 50))
    # First get the top N tools by call count, then fetch their hourly data
    result = await ch.query(
        """
        SELECT tool_name, hour, sum(call_count) AS calls, sum(total_duration) AS duration
        FROM phantex.tool_usage_hourly
        WHERE tenant_id = {tid:UUID} AND hour >= {since:DateTime64(3)}
          AND tool_name IN (
              SELECT tool_name FROM phantex.tool_usage_hourly
              WHERE tenant_id = {tid:UUID} AND hour >= {since:DateTime64(3)}
              GROUP BY tool_name ORDER BY sum(call_count) DESC LIMIT {lim:UInt32}
          )
        GROUP BY tool_name, hour
        ORDER BY hour
        """,
        parameters={"tid": str(tenant_id), "since": s, "lim": limit},
    )
    return [{"tool": r[0], "hour": str(r[1]), "calls": r[2], "duration_ms": r[3]} for r in result.result_rows]

# ── Framework Breakdown (daily) ──────────────────────────────────────────────

async def framework_breakdown(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "30d",
) -> list[dict[str, Any]]:
    s = _since(range_str)
    result = await ch.query(
        """
        SELECT framework, sum(event_count) AS count, sum(unique_agents) AS agents
        FROM phantex.framework_daily
        WHERE tenant_id = {tid:UUID} AND day >= {since:Date}
        GROUP BY framework
        ORDER BY count DESC
        """,
        parameters={"tid": str(tenant_id), "since": s.date()},
    )
    return [{"framework": r[0], "count": r[1], "agents": r[2]} for r in result.result_rows]

# ── Data Volume Trend (hourly) ───────────────────────────────────────────────

async def data_volume_trend(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "7d",
) -> list[dict[str, Any]]:
    s = _since(range_str)
    result = await ch.query(
        """
        SELECT hour, sum(event_count) AS events, sum(bytes_sent) AS sent, sum(bytes_recv) AS recv, sum(unique_agents) AS agents
        FROM phantex.data_volume_hourly
        WHERE tenant_id = {tid:UUID} AND hour >= {since:DateTime64(3)}
        GROUP BY hour
        ORDER BY hour
        """,
        parameters={"tid": str(tenant_id), "since": s},
    )
    return [
        {"hour": str(r[0]), "events": r[1], "bytes_sent": r[2], "bytes_recv": r[3], "agents": r[4]}
        for r in result.result_rows
    ]

# ── Flexible Drill-Down ─────────────────────────────────────────────────────

_ALLOWED_DIMENSIONS = frozenset(
    {
        "event_type",
        "attack_class",
        "severity",
        "agent_id",
        "framework",
        "tool_name",
        "dest_ip",
        "dest_port",
    }
)

_ALLOWED_METRICS = frozenset(
    {
        "count",
        "bytes_sent",
        "bytes_recv",
        "avg_duration",
    }
)

ValidDimension = Literal[
    "event_type",
    "attack_class",
    "severity",
    "agent_id",
    "framework",
    "tool_name",
    "dest_ip",
    "dest_port",
]

ValidMetric = Literal["count", "bytes_sent", "bytes_recv", "avg_duration"]

async def drill_down(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    dimension1: ValidDimension,
    dimension2: ValidDimension | None = None,
    metric: ValidMetric = "count",
    range_str: ValidRange = "7d",
    limit: int = 50,
    filter_severity: str | None = None,
    filter_attack_class: str | None = None,
    filter_event_type: str | None = None,
) -> list[dict[str, Any]]:
    """Arbitrary 2-dimension grouping on raw events with optional filters."""
    # Defense-in-depth: re-validate dimensions/metric against allowlists
    # even though FastAPI Literal types gate the input at the router layer.
    if dimension1 not in _ALLOWED_DIMENSIONS:
        raise ValueError("Invalid dimension1")
    if dimension2 and dimension2 not in _ALLOWED_DIMENSIONS:
        raise ValueError("Invalid dimension2")
    if metric not in _ALLOWED_METRICS:
        raise ValueError("Invalid metric")

    s = _since(range_str)
    limit = max(1, min(limit, 200))

    metric_expr = {
        "count": "count() AS value",
        "bytes_sent": "sum(ifNull(bytes_sent, 0)) AS value",
        "bytes_recv": "sum(ifNull(bytes_recv, 0)) AS value",
        "avg_duration": "avgOrDefault(duration_ms) AS value",
    }[metric]

    dims = [dimension1]
    if dimension2 and dimension2 != dimension1:
        dims.append(dimension2)
    dim_sql = ", ".join(dims)

    query = f"""
        SELECT {dim_sql}, {metric_expr}
        FROM phantex.events
        WHERE tenant_id = {{tid:UUID}}
          AND timestamp >= {{since:DateTime64(3)}}
    """
    params: dict[str, Any] = {"tid": str(tenant_id), "since": s}

    if filter_severity:
        query += " AND severity = {f_sev:String}"
        params["f_sev"] = filter_severity
    if filter_attack_class:
        query += " AND attack_class = {f_ac:String}"
        params["f_ac"] = filter_attack_class
    if filter_event_type:
        query += " AND event_type = {f_et:String}"
        params["f_et"] = filter_event_type

    query += f" GROUP BY {dim_sql} ORDER BY value DESC LIMIT {{lim:UInt32}}"
    params["lim"] = limit

    result = await ch.query(query, parameters=params)

    rows = []
    for r in result.result_rows:
        row: dict[str, Any] = {dims[0]: str(r[0]) if r[0] is not None else None}
        if len(dims) > 1:
            row[dims[1]] = str(r[1]) if r[1] is not None else None
        val = round(r[len(dims)], 2) if isinstance(r[len(dims)], float) else r[len(dims)]
        row[metric] = val  # frontend reads row[metric]
        row["value"] = val  # alias for sorting reference
        rows.append(row)
    return rows

# ── CSV Export Helper ────────────────────────────────────────────────────────

_CSV_INJECTION_PREFIXES = frozenset({"=", "+", "-", "@", "\t", "\r"})

def _sanitize_csv_value(value: Any) -> Any:
    """Prevent CSV formula injection (CWE-1236).

    If a cell value starts with a character that spreadsheet applications
    interpret as a formula, prefix it with a single-quote to neutralize it.
    """
    if isinstance(value, str) and value and value[0] in _CSV_INJECTION_PREFIXES:
        return f"'{value}"
    return value

def rows_to_csv(rows: list[dict[str, Any]]) -> str:
    """Convert a list of dicts to a CSV string with formula-injection defense."""
    if not rows:
        return ""
    output = io.StringIO()
    sanitized = [{k: _sanitize_csv_value(v) for k, v in row.items()} for row in rows]
    writer = csv.DictWriter(output, fieldnames=sanitized[0].keys())
    writer.writeheader()
    writer.writerows(sanitized)
    return output.getvalue()
