# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — PostgreSQL Storage Writer.

Kafka consumer that batch-inserts events into PostgreSQL.
Uses ON CONFLICT DO NOTHING on event_id for idempotent writes.

Batch: 500 events or 2s flush interval.
Consumer group: storage-writer-pg
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.consumers.base_consumer import BaseStorageConsumer

def _parse_ts(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp string into a timezone-aware datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value)
    # Handle common ISO formats: 2026-03-01T00:11:42.405301+00:00
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        pass
    # Fallback
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return datetime.now(UTC)

logger = structlog.get_logger("phantex.consumer.pg")

# Severity overrides for lifecycle events.
# The sensor sends most events as INFO but certain event types are
# inherently more important and should be stored at higher severity.
_EVENT_SEVERITY_OVERRIDES: dict[str, str] = {
    "AGENT_DISCOVERED": "medium",
    "AGENT_TERMINATED": "high",
}

def _safe_int(value, default: int = 0) -> int:
    """Safely convert a value to int, returning *default* on failure."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

class PostgresWriter(BaseStorageConsumer):
    """Batch INSERT events into PostgreSQL with ON CONFLICT DO NOTHING."""

    def __init__(
        self,
        pool,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name="pg-writer",
            consumer_group="storage-writer-pg",
            batch_size=500,
            flush_interval_seconds=2.0,
            **kwargs,
        )
        self._pool = pool

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Batch INSERT with executemany + ON CONFLICT DO NOTHING."""
        if not events:
            return

        import json

        # Build batch of tuples matching the PG events schema:
        # (id, tenant_id, agent_id, sensor_id, event_type, severity, timestamp, raw_data)
        rows = []
        agent_discovered_events: list[dict[str, Any]] = []
        for e in events:
            event_id = e.get("event_id")
            if not event_id:
                continue

            event_type = e.get("event_type")
            severity = _EVENT_SEVERITY_OVERRIDES.get(
                event_type, (e.get("severity") or "info"),
            ).lower()

            rows.append(
                (
                    event_id,
                    e.get("tenant_id") or None,
                    e.get("agent_id") or None,
                    e.get("sensor_id") or None,
                    event_type,
                    severity,
                    _parse_ts(e.get("timestamp")),
                    json.dumps(e),  # full event payload as raw_data JSONB
                )
            )

            if e.get("event_type") == "AGENT_DISCOVERED":
                agent_discovered_events.append(e)

        if not rows:
            return

        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO events (
                    id, tenant_id, agent_id, sensor_id,
                    event_type, severity, timestamp,
                    raw_data
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7,
                    $8
                )
                ON CONFLICT (id, timestamp) DO NOTHING
                """,
                rows,
            )

            # Upsert agents from AGENT_DISCOVERED events
            for ad in agent_discovered_events:
                await self._upsert_agent(conn, ad)

            # Update last_seen for ALL events with an agent_id (keeps status fresh)
            agent_ts: dict[str, Any] = {}
            for e in events:
                aid = e.get("agent_id")
                ts = _parse_ts(e.get("timestamp"))
                if aid and ts:
                    if aid not in agent_ts or ts > agent_ts[aid]:
                        agent_ts[aid] = ts
            for paid, ts in agent_ts.items():
                await conn.execute(
                    """
                    UPDATE agents
                    SET last_seen = GREATEST(last_seen, $1),
                        status = CASE WHEN status IN ('stale', 'offline') THEN 'active' ELSE status END,
                        updated_at = $1
                    WHERE paid = $2
                    """,
                    ts, paid,
                )

        logger.debug(
            "pg_batch_written",
            count=len(rows),
        )

    async def _upsert_agent(self, conn: Any, event: dict[str, Any]) -> None:
        """Create or update an agent record from an AGENT_DISCOVERED event."""
        raw_data = event.get("raw_data", {})
        if isinstance(raw_data, str):
            import json as _json
            try:
                raw_data = _json.loads(raw_data)
            except (ValueError, TypeError):
                raw_data = {}

        lifecycle = raw_data.get("lifecycle", {})
        paid = lifecycle.get("paid") or event.get("agent_id")
        if not paid:
            return

        tenant_id = event.get("tenant_id")
        if not tenant_id:
            return

        framework = lifecycle.get("framework") or None
        exe_path = lifecycle.get("exe_path") or None
        pid = lifecycle.get("pid")
        sensor_id = event.get("sensor_id") or None
        ts = _parse_ts(event.get("timestamp"))

        try:
            await conn.execute(
                """
                INSERT INTO agents (
                    id, tenant_id, paid, framework, exe_path,
                    process_pid, sensor_id, status, first_seen, last_seen, updated_at
                ) VALUES (
                    gen_random_uuid(), $1, $2, $3, $4,
                    $5, $6, 'active', $7, $7, $7
                )
                ON CONFLICT (paid) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    updated_at = EXCLUDED.updated_at,
                    process_pid = COALESCE(EXCLUDED.process_pid, agents.process_pid),
                    exe_path = COALESCE(EXCLUDED.exe_path, agents.exe_path),
                    framework = COALESCE(EXCLUDED.framework, agents.framework),
                    sensor_id = COALESCE(EXCLUDED.sensor_id, agents.sensor_id),
                    status = 'active'
                """,
                tenant_id, paid, framework, exe_path,
                pid, sensor_id, ts,
            )
            logger.info("agent_upserted", paid=paid, framework=framework)
        except Exception as exc:
            logger.warning("agent_upsert_failed", paid=paid, error=str(exc))

def _truncate_payload(payload: Any, max_bytes: int = 65536) -> str | None:
    """Truncate raw payload to prevent oversized writes."""
    if payload is None:
        return None
    s = str(payload)
    if len(s) > max_bytes:
        return s[:max_bytes] + "...(truncated)"
    return s
