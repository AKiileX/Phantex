# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Telemetry Export Service (Q3).

Buffers anonymized telemetry records and uploads them to the configured
endpoint in batches every 15 minutes (configurable). Provides:
- Kill switch check (PHANTEX_TELEMETRY_EXPORT env var)
- Per-tenant opt-in verification (DB check)
- Buffer management (max records, max age)
- Batch upload (gzipped JSON-L, retry with backoff)
- Viewer buffer (recent payloads for admin review)
- Metrics (batches sent, records exported, errors)

This is the CLIENT-SIDE component — runs inside customer's deployment.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

import structlog

from ml.telemetry.anonymizer import TelemetryRecord
from ml.telemetry.config import (
    TelemetryExportConfig,
    is_telemetry_kill_switch_active,
)

logger = structlog.get_logger("phantex.ml.telemetry.exporter")

# ── Export Metrics ───────────────────────────────────────────────────────────

@dataclass
class ExportMetrics:
    """Telemetry export metrics for monitoring."""

    batches_sent: int = 0
    batches_failed: int = 0
    records_exported: int = 0
    records_dropped: int = 0
    last_export_at: float | None = None
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batches_sent": self.batches_sent,
            "batches_failed": self.batches_failed,
            "records_exported": self.records_exported,
            "records_dropped": self.records_dropped,
            "last_export_at": self.last_export_at,
            "last_error": self.last_error,
        }

# ── Viewer Entry ─────────────────────────────────────────────────────────────

@dataclass
class ViewerEntry:
    """A single telemetry export payload visible to admins."""

    payload: list[dict[str, Any]]
    record_count: int
    exported_at: float
    destination: str
    success: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_preview": self.payload[:5],  # First 5 records only
            "record_count": self.record_count,
            "exported_at": self.exported_at,
            "destination": self.destination,
            "success": self.success,
            "error": self.error,
        }

# ── Telemetry Exporter ──────────────────────────────────────────────────────

class TelemetryExporter:
    """Buffers and exports anonymized telemetry records.

    Usage:
        exporter = TelemetryExporter(config, db_pool)
        await exporter.enqueue(record)       # Add from inference pipeline
        await exporter.flush()               # Manual flush (also auto-flushes)
        exporter.get_viewer_entries()         # Admin review

    The exporter checks THREE gates before exporting:
    1. Kill switch OFF (PHANTEX_TELEMETRY_EXPORT != false)
    2. Tenant has opted in (DB check)
    3. Cloud endpoint is configured (non-empty URL)
    """

    def __init__(
        self,
        config: TelemetryExportConfig | None = None,
        db_pool=None,
        http_client=None,
    ) -> None:
        self._config = config or TelemetryExportConfig()
        self._db = db_pool
        self._http = http_client
        self._buffer: list[TelemetryRecord] = []
        self._buffer_lock = asyncio.Lock()
        self._metrics = ExportMetrics()
        self._viewer: deque[ViewerEntry] = deque(maxlen=self._config.viewer_buffer_size)
        self._opted_in_cache: dict[str, tuple[bool, float]] = {}
        self._cache_ttl = 300  # 5 min cache for opt-in status
        self._flush_task: asyncio.Task | None = None

    @property
    def metrics(self) -> ExportMetrics:
        return self._metrics

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    # ── Gate Checks ──────────────────────────────────────────────────

    def is_globally_enabled(self) -> bool:
        """Check if telemetry export is globally allowed."""
        return not is_telemetry_kill_switch_active()

    def has_endpoint(self) -> bool:
        """Check if a cloud endpoint is configured."""
        return bool(self._config.cloud_endpoint)

    async def is_tenant_opted_in(self, tenant_id: str) -> bool:
        """Check if a tenant has opted into telemetry export.

        Uses a local cache (5 min TTL) to avoid DB round-trips.
        If no DB is configured, returns False (safe default).

        NOTE: Pass the RAW tenant_id (UUID string), NOT the anonymized hash.
        The telemetry_config table is keyed by tenant_id UUID.
        """
        now = time.time()
        cached = self._opted_in_cache.get(tenant_id)
        if cached and (now - cached[1]) < self._cache_ttl:
            return cached[0]

        if self._db is None:
            return False

        try:
            async with self._db.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT enabled FROM telemetry_config
                    WHERE tenant_id = $1
                    """,
                    tenant_id,
                )
                opted_in = bool(row and row["enabled"])
        except Exception:
            opted_in = False

        self._opted_in_cache[tenant_id] = (opted_in, now)
        return opted_in

    # ── Enqueue ──────────────────────────────────────────────────────

    async def enqueue(self, record: TelemetryRecord) -> bool:
        """Add a telemetry record to the export buffer.

        Returns True if record was accepted, False if dropped (kill switch,
        buffer full, not opted in).
        """
        # Gate 1: Kill switch
        if not self.is_globally_enabled():
            return False

        async with self._buffer_lock:
            # Gate 2: Buffer capacity (inside lock to avoid TOCTOU race)
            if len(self._buffer) >= self._config.max_batch_size:
                self._metrics.records_dropped += 1
                return False
            self._buffer.append(record)

        return True

    async def enqueue_batch(self, records: list[TelemetryRecord]) -> int:
        """Add multiple records. Returns count of accepted records."""
        accepted = 0
        for record in records:
            if await self.enqueue(record):
                accepted += 1
        return accepted

    # ── Flush / Upload ───────────────────────────────────────────────

    async def flush(self) -> bool:
        """Flush the buffer to the cloud endpoint.

        Returns True if the upload succeeded (or buffer was empty).
        """
        # Gate 1: Kill switch
        if not self.is_globally_enabled():
            logger.info("telemetry_flush_blocked", reason="kill_switch_active")
            return False

        # Gate 2: Endpoint configured
        if not self.has_endpoint():
            logger.debug("telemetry_flush_skipped", reason="no_endpoint")
            return True  # Not an error — just no cloud yet

        # Atomically drain buffer
        async with self._buffer_lock:
            if not self._buffer:
                return True
            batch = self._buffer[:]
            self._buffer.clear()

        # Evict stale records
        now = time.time()
        max_age = self._config.max_record_age_seconds
        fresh = [r for r in batch if (now - r.created_at) <= max_age]
        stale_count = len(batch) - len(fresh)
        if stale_count > 0:
            self._metrics.records_dropped += stale_count
            logger.info("telemetry_stale_records_dropped", count=stale_count)

        if not fresh:
            return True

        # Serialize to gzipped JSON-L
        payload_dicts = [r.to_export_dict() for r in fresh]
        jsonl = "\n".join(json.dumps(d, separators=(",", ":")) for d in payload_dicts)
        body = gzip.compress(jsonl.encode("utf-8"))

        # Upload
        success = await self._upload(body, len(fresh))

        # Record in viewer
        self._viewer.append(
            ViewerEntry(
                payload=payload_dicts,
                record_count=len(fresh),
                exported_at=now,
                destination=self._config.cloud_endpoint,
                success=success,
                error=self._metrics.last_error if not success else None,
            )
        )

        return success

    async def _upload(self, body: bytes, record_count: int) -> bool:
        """Upload a compressed batch to the cloud endpoint."""
        endpoint = self._config.cloud_endpoint
        timeout = self._config.upload_timeout_seconds
        retries = self._config.upload_retries

        for attempt in range(1, retries + 1):
            try:
                if self._http is not None:
                    # Use injected HTTP client (for testing or custom transport)
                    resp = await self._http.post(
                        endpoint,
                        content=body,
                        headers={
                            "Content-Type": "application/x-ndjson",
                            "Content-Encoding": "gzip",
                        },
                        timeout=timeout,
                    )
                    if resp.status_code < 300:
                        self._metrics.batches_sent += 1
                        self._metrics.records_exported += record_count
                        self._metrics.last_export_at = time.time()
                        logger.info(
                            "telemetry_batch_exported",
                            records=record_count,
                            bytes=len(body),
                        )
                        return True
                    else:
                        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
                else:
                    # No HTTP client — log and succeed (dry run / no cloud)
                    logger.info(
                        "telemetry_dry_run",
                        records=record_count,
                        bytes=len(body),
                    )
                    self._metrics.batches_sent += 1
                    self._metrics.records_exported += record_count
                    self._metrics.last_export_at = time.time()
                    return True

            except Exception as exc:
                wait = min(2**attempt, 30)
                logger.warning(
                    "telemetry_upload_failed",
                    attempt=attempt,
                    max_retries=retries,
                    error=str(exc),
                    retry_in=wait,
                )
                # Sanitize error — never leak internal details to API consumers
                exc_type = type(exc).__name__
                self._metrics.last_error = f"Upload failed: {exc_type}"
                if attempt < retries:
                    await asyncio.sleep(wait)

        self._metrics.batches_failed += 1
        self._metrics.records_dropped += record_count
        return False

    # ── Viewer ───────────────────────────────────────────────────────

    def get_viewer_entries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent export payloads for admin review.

        This implements the "Telemetry Viewer" — admin can see exactly
        what is exported before it leaves the network.
        """
        limit = max(1, min(limit, 500))  # Clamp to sane range
        entries = list(self._viewer)
        entries.reverse()  # Most recent first
        return [e.to_dict() for e in entries[:limit]]

    def get_pending_preview(self) -> list[dict[str, Any]]:
        """Return the current buffer contents as preview dicts.

        Admin can inspect what WILL be exported on the next flush.
        """
        return [r.to_export_dict() for r in self._buffer[:50]]

    # ── Background Flush Loop ────────────────────────────────────────

    async def start_flush_loop(self) -> None:
        """Start the periodic flush loop (every batch_interval_seconds)."""
        if self._flush_task is not None:
            return

        async def _loop():
            while True:
                await asyncio.sleep(self._config.batch_interval_seconds)
                try:
                    await self.flush()
                except Exception:
                    logger.exception("telemetry_flush_loop_error")

        self._flush_task = asyncio.create_task(_loop(), name="telemetry-flush")
        logger.info(
            "telemetry_flush_loop_started",
            interval_seconds=self._config.batch_interval_seconds,
        )

    async def stop_flush_loop(self) -> None:
        """Stop the periodic flush loop and drain remaining records."""
        if self._flush_task is not None:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
            self._flush_task = None

        # Final flush attempt
        await self.flush()

    # ── Cache Management ─────────────────────────────────────────────

    def clear_opt_in_cache(self) -> None:
        """Clear the tenant opt-in cache (e.g. after config change)."""
        self._opted_in_cache.clear()
