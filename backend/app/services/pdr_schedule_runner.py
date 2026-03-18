# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Scheduled PDR Export Runner.

Adds scheduled and on-demand export execution on top of existing PDR export
channels. A schedule selects recent events from Postgres and pushes them
through an existing channel adapter (S3 / Webhook / Kafka mirror).

Leader election uses a PostgreSQL advisory lock so only one API worker runs
the scheduler loop even when multiple workers are started.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text

from app.database import admin_engine, admin_session_factory
from app.services.agent_policy_service import compute_next_cron
from app.services.pdr_service import create_channel
from app.utils.logging import get_logger

logger = get_logger("phantex.services.pdr_schedule_runner")

_SCHEDULER_LOCK_ID = 33033

def _parse_json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default
    return value

async def execute_channel_export(
    *,
    tenant_id: str,
    channel_row: dict[str, Any],
    lookback_minutes: int,
    event_types: list[str] | None = None,
    max_events: int = 1000,
) -> dict[str, Any]:
    """Export recent tenant events through an existing PDR channel."""
    cutoff = datetime.now(UTC) - timedelta(minutes=lookback_minutes)

    async with admin_session_factory() as session:
        sql = """
            SELECT id, agent_id, sensor_id, event_type, severity, timestamp, raw_data
            FROM events
            WHERE tenant_id = :tenant_id
              AND timestamp >= :cutoff
        """
        params: dict[str, Any] = {
            "tenant_id": tenant_id,
            "cutoff": cutoff,
            "limit": max_events * 5,
        }
        sql += " ORDER BY timestamp ASC LIMIT :limit"

        result = await session.execute(text(sql), params)
        rows = result.mappings().all()

    if event_types:
        allowed = set(event_types)
        rows = [row for row in rows if row["event_type"] in allowed]
    rows = rows[:max_events]

    config = _parse_json(channel_row.get("config"), {})
    pii_fields = _parse_json(channel_row.get("pii_fields"), None)
    channel = create_channel(channel_row["channel_type"], config)
    try:
        payload = [
            {
                "id": str(row["id"]),
                "agent_id": row.get("agent_id"),
                "sensor_id": row.get("sensor_id"),
                "event_type": row["event_type"],
                "severity": row["severity"],
                "timestamp": row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
                "raw_data": row.get("raw_data") or {},
            }
            for row in rows
        ]
        result = await channel.export_batch(payload, tenant_id, pii_fields=pii_fields)
        return {
            "events_selected": len(payload),
            **(result or {}),
        }
    finally:
        with contextlib.suppress(Exception):
            await channel.close()

class PDRScheduleRunner:
    """Background runner for scheduled export jobs."""

    def __init__(self, *, poll_interval_seconds: float = 30.0) -> None:
        self._poll_interval = poll_interval_seconds
        self._running = False
        self._task: asyncio.Task | None = None
        self._lock_conn = None

    async def start(self) -> None:
        if self._running:
            return

        self._lock_conn = await admin_engine.connect()
        acquired = await self._lock_conn.scalar(
            text("SELECT pg_try_advisory_lock(:lock_id)"),
            {"lock_id": _SCHEDULER_LOCK_ID},
        )
        if not acquired:
            logger.info("pdr_schedule_runner_not_leader")
            await self._lock_conn.close()
            self._lock_conn = None
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="pdr-schedule-runner")
        logger.info("pdr_schedule_runner_started")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        if self._lock_conn is not None:
            with contextlib.suppress(Exception):
                await self._lock_conn.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": _SCHEDULER_LOCK_ID},
                )
            with contextlib.suppress(Exception):
                await self._lock_conn.close()
            self._lock_conn = None
        logger.info("pdr_schedule_runner_stopped")

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await self.run_pending_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("pdr_schedule_runner_error", error=str(exc)[:300])
            await asyncio.sleep(self._poll_interval)

    async def run_pending_once(self) -> int:
        now = datetime.now(UTC)
        processed = 0
        async with admin_session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT
                        s.id, s.tenant_id, s.channel_id, s.name, s.cron_schedule,
                        s.lookback_minutes, s.event_types, s.max_events,
                        c.channel_type, c.config, c.pii_fields
                    FROM pdr_export_schedules s
                    JOIN pdr_channels c
                      ON c.id = s.channel_id
                     AND c.tenant_id = s.tenant_id
                    WHERE s.enabled = true
                      AND c.enabled = true
                      AND s.deleted_at IS NULL
                      AND s.next_run_at <= :now
                    ORDER BY s.next_run_at ASC
                    LIMIT 20
                    """
                ),
                {"now": now},
            )
            rows = result.mappings().all()

            for row in rows:
                next_run_at = compute_next_cron(row["cron_schedule"], after=now)
                status = "success"
                message = ""
                try:
                    export_result = await execute_channel_export(
                        tenant_id=str(row["tenant_id"]),
                        channel_row=dict(row),
                        lookback_minutes=int(row["lookback_minutes"] or 60),
                        event_types=_parse_json(row.get("event_types"), None),
                        max_events=int(row.get("max_events") or 1000),
                    )
                    message = f"exported {export_result.get('events_selected', 0)} event(s)"
                    processed += 1
                except Exception as exc:
                    status = "error"
                    message = str(exc)[:500]
                    logger.warning(
                        "pdr_schedule_run_failed",
                        schedule_id=row["id"],
                        tenant_id=str(row["tenant_id"]),
                        error=message,
                    )

                await session.execute(
                    text(
                        """
                        UPDATE pdr_export_schedules
                        SET last_run_at = :now,
                            next_run_at = :next_run_at,
                            last_run_status = :status,
                            last_run_message = :message,
                            updated_at = now()
                        WHERE id = :schedule_id
                        """
                    ),
                    {
                        "now": now,
                        "next_run_at": next_run_at,
                        "status": status,
                        "message": message,
                        "schedule_id": row["id"],
                    },
                )

            await session.commit()
        return processed