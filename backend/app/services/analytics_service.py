# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Analytics Service.

Query builder for ClickHouse analytics endpoints.
All queries are tenant-scoped — tenant_id is injected from the
authenticated user, never from user input.

Uses parameterized queries only — no string interpolation in SQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from clickhouse_connect.driver.asyncclient import AsyncClient

from app.utils.logging import get_logger

logger = get_logger("phantex.analytics")

# ── Interval parsing ─────────────────────────────────────────────────────────

_INTERVAL_MAP: dict[str, str] = {
    "1m": "toStartOfMinute",
    "5m": "toStartOfFiveMinutes",
    "15m": "toStartOfFifteenMinutes",
    "1h": "toStartOfHour",
    "1d": "toStartOfDay",
}

_RANGE_MAP: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "12h": timedelta(hours=12),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}

ValidInterval = Literal["1m", "5m", "15m", "1h", "1d"]
ValidRange = Literal["1h", "6h", "12h", "24h", "7d", "30d", "90d"]

def _parse_range(range_str: str) -> datetime:
    """Convert a range string like '7d' to a UTC datetime threshold."""
    delta = _RANGE_MAP.get(range_str)
    if delta is None:
        raise ValueError(f"Invalid range: {range_str}. Valid: {list(_RANGE_MAP.keys())}")
    return datetime.now(UTC) - delta

# ── Event Volume ─────────────────────────────────────────────────────────────

async def event_volume(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    interval: ValidInterval = "1h",
    range_str: ValidRange = "7d",
    agent_id: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    """Time-series event counts grouped by interval and event_type.

    Hits the pre-aggregated hourly table when interval >= 1h, otherwise raw events.
    """
    since = _parse_range(range_str)
    trunc_fn = _INTERVAL_MAP.get(interval, "toStartOfHour")

    # Use aggregated table for hourly+ intervals
    if interval in ("1h", "1d"):
        query = f"""
            SELECT
                {trunc_fn}(hour) AS bucket,
                event_type,
                sum(event_count) AS count
            FROM phantex.events_hourly
            WHERE tenant_id = {{tid:UUID}}
              AND hour >= {{since:DateTime64(3)}}
        """
        params: dict[str, Any] = {"tid": str(tenant_id), "since": since}

        if agent_id is not None:
            query += " AND agent_id = {agent_id:String}"
            params["agent_id"] = str(agent_id)

        query += " GROUP BY bucket, event_type ORDER BY bucket"
    else:
        query = f"""
            SELECT
                {trunc_fn}(timestamp) AS bucket,
                event_type,
                count() AS count
            FROM phantex.events
            WHERE tenant_id = {{tid:UUID}}
              AND timestamp >= {{since:DateTime64(3)}}
        """
        params = {"tid": str(tenant_id), "since": since}

        if agent_id is not None:
            query += " AND agent_id = {agent_id:String}"
            params["agent_id"] = str(agent_id)
        if event_type is not None:
            query += " AND event_type = {etype:String}"
            params["etype"] = event_type

        query += " GROUP BY bucket, event_type ORDER BY bucket"

    result = await ch.query(query, parameters=params)

    return [{"bucket": str(row[0]), "event_type": row[1], "count": row[2]} for row in result.result_rows]

# ── Top Agents ───────────────────────────────────────────────────────────────

async def top_agents(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "24h",
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Agents ranked by event volume in the given range."""
    since = _parse_range(range_str)
    limit = max(1, min(limit, 100))

    result = await ch.query(
        """
        SELECT
            agent_id,
            count() AS event_count,
            uniqExact(event_type) AS unique_types,
            max(timestamp) AS last_event
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND timestamp >= {since:DateTime64(3)}
        GROUP BY agent_id
        ORDER BY event_count DESC
        LIMIT {lim:UInt32}
        """,
        parameters={
            "tid": str(tenant_id),
            "since": since,
            "lim": limit,
        },
    )

    return [
        {
            "agent_id": str(row[0]),
            "event_count": row[1],
            "unique_types": row[2],
            "last_event": str(row[3]),
        }
        for row in result.result_rows
    ]

# ── Attack Breakdown ─────────────────────────────────────────────────────────

async def attack_breakdown(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    range_str: ValidRange = "30d",
) -> list[dict[str, Any]]:
    """Alert counts grouped by attack class and severity."""
    since = _parse_range(range_str)

    result = await ch.query(
        """
        SELECT
            attack_class,
            severity,
            count() AS count
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND timestamp >= {since:DateTime64(3)}
          AND attack_class IS NOT NULL
        GROUP BY attack_class, severity
        ORDER BY count DESC
        """,
        parameters={"tid": str(tenant_id), "since": since},
    )

    return [{"attack_class": row[0], "severity": row[1], "count": row[2]} for row in result.result_rows]

# ── Network Destinations ─────────────────────────────────────────────────────

async def network_destinations(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    agent_id: str,
    range_str: ValidRange = "7d",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Unique network destinations for an agent with byte totals."""
    since = _parse_range(range_str)
    limit = max(1, min(limit, 200))

    result = await ch.query(
        """
        SELECT
            dest_ip,
            dest_port,
            count() AS connection_count,
            sumOrDefault(bytes_sent) AS total_bytes_sent,
            sumOrDefault(bytes_recv) AS total_bytes_recv,
            min(timestamp) AS first_seen,
            max(timestamp) AS last_seen
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND agent_id = {aid:String}
          AND dest_ip IS NOT NULL
        GROUP BY dest_ip, dest_port
        ORDER BY connection_count DESC
        LIMIT {lim:UInt32}
        """,
        parameters={
            "tid": str(tenant_id),
            "aid": str(agent_id),
            "since": since,
            "lim": limit,
        },
    )

    return [
        {
            "dest_ip": str(row[0]) if row[0] else None,
            "dest_port": row[1],
            "connection_count": row[2],
            "total_bytes_sent": row[3],
            "total_bytes_recv": row[4],
            "first_seen": str(row[5]),
            "last_seen": str(row[6]),
        }
        for row in result.result_rows
    ]

# ── Tool Usage ───────────────────────────────────────────────────────────────

async def tool_usage(
    ch: AsyncClient,
    tenant_id: uuid.UUID,
    *,
    agent_id: str,
    range_str: ValidRange = "7d",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Tool call frequency and duration stats for an agent."""
    since = _parse_range(range_str)
    limit = max(1, min(limit, 200))

    result = await ch.query(
        """
        SELECT
            tool_name,
            count() AS call_count,
            avgOrDefault(duration_ms) AS avg_duration_ms,
            maxOrDefault(duration_ms) AS max_duration_ms,
            min(timestamp) AS first_used,
            max(timestamp) AS last_used
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND agent_id = {aid:String}
          AND timestamp >= {since:DateTime64(3)}
          AND event_type = 'TOOL_CALL'
          AND tool_name IS NOT NULL
          AND tool_name != ''
        GROUP BY tool_name
        ORDER BY call_count DESC
        LIMIT {lim:UInt32}
        """,
        parameters={
            "tid": str(tenant_id),
            "aid": str(agent_id),
            "since": since,
            "lim": limit,
        },
    )

    return [
        {
            "tool_name": row[0],
            "call_count": row[1],
            "avg_duration_ms": round(row[2], 1),
            "max_duration_ms": row[3],
            "first_used": str(row[4]),
            "last_used": str(row[5]),
        }
        for row in result.result_rows
    ]
