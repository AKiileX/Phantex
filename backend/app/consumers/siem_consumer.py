# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SIEM Kafka Consumer (N1).

Consumes from phantex.alerts.* and fans out to all enabled SIEM
integrations per tenant.

For each alert:
  1. Extract tenant_id from topic name
  2. Look up enabled integrations for that tenant
  3. Format + send to each platform adapter
  4. Retry on failure, DLQ after exhaustion
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from typing import Any

import structlog

logger = structlog.get_logger("phantex.consumer.siem")

_TOPIC_TENANT_RE = re.compile(r"^phantex\.alerts\.(.+)$")

class SIEMFanoutConsumer:
    """Kafka consumer that routes alerts to tenant-specific SIEM integrations."""

    def __init__(
        self,
        db_pool,
        *,
        bootstrap_servers: str = "localhost:9092",
        consumer_group: str = "siem-fanout",
        max_retries: int = 3,
        batch_size: int = 100,
        flush_interval: float = 5.0,
        ssl_context: Any | None = None,
    ) -> None:
        self._pool = db_pool
        self._bootstrap = bootstrap_servers
        self._consumer_group = consumer_group
        self._max_retries = max_retries
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._ssl_context = ssl_context

        self._consumer = None
        self._running = False
        self._task: asyncio.Task | None = None

        # Cache: tenant_id → list of (platform, config) — per-tenant timestamps
        self._integration_cache: dict[str, list[dict]] = {}
        self._cache_ts: dict[str, float] = {}  # per-tenant
        self._cache_ttl: float = 60.0

        # Metrics
        self.alerts_consumed: int = 0
        self.alerts_delivered: int = 0
        self.delivery_errors: int = 0

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume_loop(), name="siem-fanout")
        logger.info("siem_consumer_starting", group=self._consumer_group)

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            with contextlib.suppress(Exception):
                await self._consumer.stop()
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        logger.info(
            "siem_consumer_stopped",
            consumed=self.alerts_consumed,
            delivered=self.alerts_delivered,
            errors=self.delivery_errors,
        )

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                await self._run_consumer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("siem_consumer_error", error=str(e))
                await asyncio.sleep(5)

    async def _run_consumer(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError:
            logger.error("aiokafka_not_installed")
            self._running = False
            return

        kwargs = dict(
            bootstrap_servers=self._bootstrap,
            group_id=self._consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=False,
            value_deserializer=lambda x: x,
        )
        if self._ssl_context:
            kwargs["security_protocol"] = "SSL"
            kwargs["ssl_context"] = self._ssl_context

        self._consumer = AIOKafkaConsumer(**kwargs)
        await self._consumer.start()
        self._consumer.subscribe(pattern=r"^phantex\.alerts\..+$")

        # Buffer alerts by tenant
        buffer: dict[str, list[dict]] = {}
        last_flush = time.monotonic()

        try:
            async for msg in self._consumer:
                if not self._running:
                    break

                self.alerts_consumed += 1

                try:
                    alert = json.loads(msg.value)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                # Extract tenant from topic
                m = _TOPIC_TENANT_RE.match(msg.topic)
                tenant_id = m.group(1) if m else alert.get("tenant_id", "")
                if not tenant_id:
                    continue

                buffer.setdefault(tenant_id, []).append(alert)

                # Flush when buffer is large enough or interval elapsed
                now = time.monotonic()
                total_buffered = sum(len(v) for v in buffer.values())
                if total_buffered >= self._batch_size or (now - last_flush) >= self._flush_interval:
                    await self._flush_buffer(buffer)
                    buffer.clear()
                    last_flush = now
                    await self._consumer.commit()

        finally:
            # Final flush
            if buffer:
                await self._flush_buffer(buffer)
            await self._consumer.stop()
            self._consumer = None

    async def _flush_buffer(self, buffer: dict[str, list[dict]]) -> None:
        """Send buffered alerts to each tenant's enabled integrations."""
        for tenant_id, alerts in buffer.items():
            integrations = await self._get_integrations(tenant_id)
            if not integrations:
                continue

            for integ_config in integrations:
                await self._send_to_integration(tenant_id, integ_config, alerts)

    async def _send_to_integration(
        self,
        tenant_id: str,
        integ_config: dict,
        alerts: list[dict],
    ) -> None:
        """Send alerts to a single integration with retry."""
        from app.integrations.base import IntegrationError
        from app.integrations.registry import get_integration

        try:
            config = integ_config.get("config", {})
            if isinstance(config, str):
                config = json.loads(config)

            integration = get_integration(
                integ_config["platform"],
                tenant_id=tenant_id,
                config=config,
                rate_limit_per_min=integ_config.get("rate_limit_per_min"),
            )

            for attempt in range(1, self._max_retries + 1):
                try:
                    sent = await integration.send_batch(alerts)
                    self.alerts_delivered += sent
                    break
                except IntegrationError as e:
                    if not e.retryable or attempt == self._max_retries:
                        self.delivery_errors += len(alerts)
                        logger.error(
                            "siem_delivery_failed",
                            platform=integ_config["platform"],
                            tenant_id=tenant_id,
                            alerts=len(alerts),
                            error=str(e),
                        )
                        break
                    await asyncio.sleep(min(2**attempt, 30))

            await integration.close()

        except Exception as e:
            self.delivery_errors += len(alerts)
            logger.error(
                "siem_integration_error",
                platform=integ_config.get("platform"),
                tenant_id=tenant_id,
                error=str(e),
            )

    async def _get_integrations(self, tenant_id: str) -> list[dict]:
        """Get enabled integrations for a tenant (cached)."""
        now = time.monotonic()
        ts = self._cache_ts.get(tenant_id, 0)
        if now - ts < self._cache_ttl and tenant_id in self._integration_cache:
            return self._integration_cache[tenant_id]

        # Refresh cache
        try:
            rows = await self._pool.fetch(
                """
                SELECT platform, config, rate_limit_per_min
                FROM integrations
                WHERE tenant_id = $1 AND enabled = true
                """,
                tenant_id,
            )
            result = [dict(r) for r in rows]
            self._integration_cache[tenant_id] = result
            self._cache_ts[tenant_id] = now
            return result
        except Exception as e:
            logger.warning("siem_cache_refresh_error", error=str(e))
            return self._integration_cache.get(tenant_id, [])
