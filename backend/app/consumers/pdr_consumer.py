# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — PDR (Phantex Data Relay) Kafka Consumer (L3).

Consumes from phantex.events.* and phantex.alerts.*, transforms events
to OCSF v1.1 via ocsf_mapper, then fans out to all enabled PDR export
channels per tenant (S3 / Webhook / Kafka mirror).

Architecture follows the same pattern as siem_consumer.py:
  1. Subscribe to topic patterns
  2. Buffer by tenant
  3. Lookup enabled PDR channels per tenant (cached)
  4. Export via channel adapters (pdr_service.py)
  5. Retry on failure, DLQ on exhaustion
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from typing import Any

from app.services.pdr_service import (
    ExportError,
    create_channel,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.consumer.pdr")

_TOPIC_TENANT_RE = re.compile(r"^phantex\.(?:events|alerts)\.(.+)$")

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

class PDRExportConsumer:
    """Kafka consumer that routes events/alerts → OCSF → PDR export channels."""

    def __init__(
        self,
        db_pool,
        *,
        bootstrap_servers: str = "localhost:9092",
        consumer_group: str = "pdr-export",
        max_retries: int = 3,
        batch_size: int = 200,
        flush_interval: float = 5.0,
        dlq_topic: str = "phantex.pdr.dlq",
        ssl_context: Any | None = None,
    ) -> None:
        self._pool = db_pool
        self._bootstrap = bootstrap_servers
        self._consumer_group = consumer_group
        self._max_retries = max_retries
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._dlq_topic = dlq_topic
        self._ssl_context = ssl_context

        self._consumer = None
        self._producer = None  # For DLQ writes
        self._running = False
        self._task: asyncio.Task | None = None

        # Cache: tenant_id → list[channel_config_dicts]
        self._channel_cache: dict[str, list[dict]] = {}
        self._cache_ts: dict[str, float] = {}
        self._cache_ttl: float = 60.0

        # Live channel instances: (tenant_id, channel_id) → channel
        self._channels: dict[tuple[str, str], Any] = {}

        # Metrics
        self.events_consumed: int = 0
        self.events_exported: int = 0
        self.export_errors: int = 0
        self.dlq_count: int = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume_loop(), name="pdr-export")
        logger.info("pdr_consumer_starting", group=self._consumer_group)

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            with contextlib.suppress(Exception):
                await self._consumer.stop()
        if self._producer:
            with contextlib.suppress(Exception):
                await self._producer.stop()

        # Close all live channel instances
        for channel in self._channels.values():
            with contextlib.suppress(Exception):
                await channel.close()
        self._channels.clear()

        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        logger.info(
            "pdr_consumer_stopped",
            consumed=self.events_consumed,
            exported=self.events_exported,
            errors=self.export_errors,
            dlq=self.dlq_count,
        )

    # ── Main Loop ─────────────────────────────────────────────────────────

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                await self._run_consumer()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("pdr_consumer_error", error=str(exc)[:200])
                await asyncio.sleep(5)

    async def _run_consumer(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        except ImportError:
            logger.error("aiokafka_not_installed")
            self._running = False
            return

        kafka_kwargs: dict[str, Any] = {
            "bootstrap_servers": self._bootstrap,
            "group_id": self._consumer_group,
            "auto_offset_reset": "latest",
            "enable_auto_commit": False,
            "value_deserializer": lambda x: x,
        }
        if self._ssl_context:
            kafka_kwargs["security_protocol"] = "SSL"
            kafka_kwargs["ssl_context"] = self._ssl_context

        self._consumer = AIOKafkaConsumer(**kafka_kwargs)
        await self._consumer.start()
        self._consumer.subscribe(pattern=r"^phantex\.(?:events|alerts)\..+$")

        # Optionally create DLQ producer
        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            )
            await self._producer.start()
        except Exception as exc:
            logger.warning("pdr_dlq_producer_init_failed", error=str(exc)[:200])
            self._producer = None

        # Buffer events by tenant
        buffer: dict[str, list[dict]] = {}
        last_flush = time.monotonic()

        try:
            async for msg in self._consumer:
                if not self._running:
                    break

                self.events_consumed += 1

                try:
                    event = json.loads(msg.value)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                # Extract tenant from topic
                m = _TOPIC_TENANT_RE.match(msg.topic)
                tenant_id = m.group(1) if m else event.get("tenant_id", "")
                if not tenant_id:
                    continue
                # Validate tenant_id is a UUID to prevent cache poisoning / log injection
                if not _UUID_RE.match(tenant_id):
                    logger.warning(
                        "pdr_invalid_tenant_id",
                        tenant_id=tenant_id[:64],
                        topic=msg.topic,
                    )
                    continue

                buffer.setdefault(tenant_id, []).append(event)

                # Flush when buffer large enough or interval elapsed
                now = time.monotonic()
                total = sum(len(v) for v in buffer.values())
                if total >= self._batch_size or (now - last_flush) >= self._flush_interval:
                    await self._flush_buffer(buffer)
                    buffer.clear()
                    last_flush = now
                    await self._consumer.commit()

        finally:
            if buffer:
                await self._flush_buffer(buffer)
            await self._consumer.stop()
            self._consumer = None
            if self._producer:
                await self._producer.stop()
                self._producer = None

    # ── Flush / Export ────────────────────────────────────────────────────

    async def _flush_buffer(self, buffer: dict[str, list[dict]]) -> None:
        """Fan out buffered events to each tenant's PDR channels."""
        for tenant_id, events in buffer.items():
            channels = await self._get_channels(tenant_id)
            if not channels:
                continue

            for ch_cfg in channels:
                await self._export_to_channel(tenant_id, ch_cfg, events)

    async def _export_to_channel(
        self,
        tenant_id: str,
        ch_cfg: dict,
        events: list[dict],
    ) -> None:
        """Export events to a single PDR channel with retry and DLQ."""
        channel_id = ch_cfg.get("id", "unknown")
        channel_type = ch_cfg.get("channel_type", "")
        config = ch_cfg.get("config", {})
        pii_fields = ch_cfg.get("pii_fields")

        if isinstance(config, str):
            try:
                config = json.loads(config)
            except (json.JSONDecodeError, TypeError):
                config = {}

        if isinstance(pii_fields, str):
            try:
                pii_fields = json.loads(pii_fields)
            except (json.JSONDecodeError, TypeError):
                pii_fields = None

        cache_key = (tenant_id, str(channel_id))

        try:
            # Reuse or create channel instance
            if cache_key not in self._channels:
                self._channels[cache_key] = create_channel(channel_type, config)

            channel = self._channels[cache_key]

            result = await channel.export_batch(events, tenant_id, pii_fields=pii_fields)

            exported = result.get("delivered", result.get("events", 0))
            self.events_exported += exported

            logger.info(
                "pdr_export_success",
                channel_type=channel_type,
                channel_id=channel_id,
                tenant_id=tenant_id,
                exported=exported,
            )

        except ExportError as exc:
            self.export_errors += len(events)
            logger.error(
                "pdr_export_failed",
                channel_type=channel_type,
                channel_id=channel_id,
                tenant_id=tenant_id,
                events=len(events),
                error=str(exc)[:200],
            )
            await self._send_to_dlq(tenant_id, events, channel_type, str(exc))

            # Invalidate channel instance (may be stale)
            if cache_key in self._channels:
                with contextlib.suppress(Exception):
                    await self._channels[cache_key].close()
                del self._channels[cache_key]

        except Exception as exc:
            self.export_errors += len(events)
            logger.error(
                "pdr_export_unexpected",
                channel_type=channel_type,
                tenant_id=tenant_id,
                error=str(exc)[:200],
            )
            await self._send_to_dlq(tenant_id, events, channel_type, str(exc))

    async def _send_to_dlq(
        self,
        tenant_id: str,
        events: list[dict],
        channel_type: str,
        error: str,
    ) -> None:
        """Route failed events to dead-letter topic."""
        if not self._producer:
            return
        try:
            dlq_msg = {
                "source": "pdr-export",
                "channel_type": channel_type,
                "tenant_id": tenant_id,
                "error": error[:500],
                "events": events[:50],  # Cap DLQ payload
                "timestamp": time.time(),
            }
            await self._producer.send_and_wait(
                self._dlq_topic,
                value=dlq_msg,
                key=tenant_id.encode("utf-8"),
            )
            self.dlq_count += len(events)
        except Exception as exc:
            logger.error("pdr_dlq_send_failed", error=str(exc)[:200])

    # ── Channel Cache ─────────────────────────────────────────────────────

    async def _get_channels(self, tenant_id: str) -> list[dict]:
        """Get enabled PDR export channels for a tenant (cached)."""
        now = time.monotonic()
        ts = self._cache_ts.get(tenant_id, 0)
        if now - ts < self._cache_ttl and tenant_id in self._channel_cache:
            return self._channel_cache[tenant_id]

        try:
            rows = await self._pool.fetch(
                """
                SELECT id, channel_type, config, pii_fields
                FROM pdr_channels
                WHERE tenant_id = $1 AND enabled = true
                """,
                tenant_id,
            )
            result = [dict(r) for r in rows]
            self._channel_cache[tenant_id] = result
            self._cache_ts[tenant_id] = now
            return result
        except Exception as exc:
            logger.warning(
                "pdr_channel_cache_error",
                tenant_id=tenant_id,
                error=str(exc)[:200],
            )
            return self._channel_cache.get(tenant_id, [])
