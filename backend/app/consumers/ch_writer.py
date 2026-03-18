# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ClickHouse Storage Writer.

Kafka consumer that batch-inserts events into ClickHouse.
ClickHouse's ReplacingMergeTree provides eventual deduplication on event_id.

Batch: 5000 events or 5s flush interval.
Consumer group: storage-writer-ch
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import structlog

from app.consumers.base_consumer import BaseStorageConsumer

logger = structlog.get_logger("phantex.consumer.ch")

def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int, returning *default* on failure."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def _safe_ipv4(value: Any) -> str | None:
    """Return a valid IPv4 string or None."""
    if not value:
        return None
    try:
        ipaddress.IPv4Address(str(value))
        return str(value)
    except (ValueError, ipaddress.AddressValueError):
        return None

class ClickHouseWriter(BaseStorageConsumer):
    """Batch INSERT events into ClickHouse."""

    def __init__(
        self,
        ch_client,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name="ch-writer",
            consumer_group="storage-writer-ch",
            batch_size=5000,
            flush_interval_seconds=5.0,
            **kwargs,
        )
        self._ch = ch_client

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Batch INSERT into ClickHouse events table using native insert."""
        if not events:
            return

        # Build column data
        rows = []
        for e in events:
            event_id = e.get("event_id")
            if not event_id:
                continue

            _NIL_UUID = "00000000-0000-0000-0000-000000000000"

            # Extract tool_name: check top-level, then nested payload/raw_data
            tool_name = e.get("tool_name") or None
            if not tool_name:
                payload = e.get("payload") or e.get("raw_data") or {}
                if isinstance(payload, dict):
                    tool_name = payload.get("tool_name") or payload.get("name") or None

            rows.append(
                [
                    event_id,
                    e.get("tenant_id") or _NIL_UUID,
                    e.get("agent_id") or "",
                    e.get("framework", ""),
                    e.get("event_type", ""),
                    e.get("severity", "info").lower(),
                    e.get("attack_class") or None,
                    e.get("timestamp", "1970-01-01 00:00:00"),
                    _safe_ipv4(e.get("dest_ip")),
                    _safe_int(e.get("dest_port")) or None,
                    _safe_int(e.get("bytes_out", 0)),
                    _safe_int(e.get("bytes_in", 0)),
                    e.get("file_path") or None,
                    tool_name,
                    _safe_int(e.get("tool_duration_ms")) or None,
                ]
            )

        if not rows:
            return

        # clickhouse-connect insert uses column-oriented format
        column_names = [
            "event_id",
            "tenant_id",
            "agent_id",
            "framework",
            "event_type",
            "severity",
            "attack_class",
            "timestamp",
            "dest_ip",
            "dest_port",
            "bytes_sent",
            "bytes_recv",
            "file_path",
            "tool_name",
            "duration_ms",
        ]

        # clickhouse-connect sync client — run in executor to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self._ch.insert("events", rows, column_names=column_names),
        )

        logger.debug(
            "ch_batch_written",
            count=len(rows),
        )
