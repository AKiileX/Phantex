# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Notification Kafka Consumer (N2).

Consumes from phantex.alerts.* and routes to notification channels
based on per-tenant routing rules.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from typing import Any

import structlog

from app.notifications.base import NotificationError
from app.notifications.router import get_channel, match_routing_rules

logger = structlog.get_logger("phantex.consumer.notification")

_TOPIC_TENANT_RE = re.compile(r"^phantex\.alerts\.(.+)$")

class NotificationConsumer:
    """Kafka alert consumer → notification channel fan-out."""

    def __init__(
        self,
        db_pool,
        *,
        bootstrap_servers: str = "localhost:9092",
        consumer_group: str = "notification-fanout",
        max_retries: int = 3,
        ssl_context: Any | None = None,
    ) -> None:
        self._pool = db_pool
        self._bootstrap = bootstrap_servers
        self._consumer_group = consumer_group
        self._max_retries = max_retries
        self._ssl_context = ssl_context

        self._consumer = None
        self._running = False
        self._task: asyncio.Task | None = None

        # Cache — per-tenant timestamps
        self._rules_cache: dict[str, list[dict]] = {}
        self._channels_cache: dict[str, dict] = {}
        self._rules_cache_ts: dict[str, float] = {}  # per-tenant
        self._channels_cache_ts: dict[str, float] = {}  # per-tenant
        self._cache_ttl: float = 60.0

        # Metrics
        self.alerts_consumed: int = 0
        self.notifications_sent: int = 0
        self.notification_errors: int = 0

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume_loop(), name="notification-fanout")
        logger.info("notification_consumer_starting")

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
            "notification_consumer_stopped",
            consumed=self.alerts_consumed,
            sent=self.notifications_sent,
            errors=self.notification_errors,
        )

    async def _consume_loop(self) -> None:
        while self._running:
            try:
                await self._run_consumer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("notification_consumer_error", error=str(e))
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

        try:
            async for msg in self._consumer:
                if not self._running:
                    break

                self.alerts_consumed += 1

                try:
                    alert = json.loads(msg.value)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                m = _TOPIC_TENANT_RE.match(msg.topic)
                tenant_id = m.group(1) if m else alert.get("tenant_id", "")
                if not tenant_id:
                    continue

                alert["tenant_id"] = tenant_id
                await self._route_alert(tenant_id, alert)
                await self._consumer.commit()

        finally:
            await self._consumer.stop()
            self._consumer = None

    async def _route_alert(self, tenant_id: str, alert: dict[str, Any]) -> None:
        """Route an alert through the tenant's notification rules."""
        rules = await self._get_rules(tenant_id)
        if not rules:
            return

        channel_ids = match_routing_rules(alert, rules)
        if not channel_ids:
            return

        channels = await self._get_channels(tenant_id)

        for ch_id in channel_ids:
            ch_config = channels.get(ch_id)
            if not ch_config or not ch_config.get("enabled", True):
                continue

            await self._send_notification(tenant_id, ch_config, alert)

    async def _send_notification(
        self,
        tenant_id: str,
        ch_config: dict,
        alert: dict[str, Any],
    ) -> None:
        """Send a notification with retry."""
        config = ch_config.get("config", {})
        if isinstance(config, str):
            config = json.loads(config)

        try:
            channel = get_channel(
                ch_config["channel_type"],
                tenant_id=tenant_id,
                config=config,
                rate_limit_per_min=ch_config.get("rate_limit_per_min"),
            )

            for attempt in range(1, self._max_retries + 1):
                try:
                    await channel.send(alert)
                    self.notifications_sent += 1
                    break
                except NotificationError as e:
                    if not e.retryable or attempt == self._max_retries:
                        self.notification_errors += 1
                        logger.error(
                            "notification_failed",
                            channel_type=ch_config["channel_type"],
                            channel_id=ch_config.get("id"),
                            error=str(e),
                        )
                        break
                    await asyncio.sleep(min(2**attempt, 15))

            await channel.close()

        except Exception as e:
            self.notification_errors += 1
            logger.error("notification_error", error=str(e))

    async def _get_rules(self, tenant_id: str) -> list[dict]:
        """Get routing rules for tenant (cached)."""
        now = time.monotonic()
        ts = self._rules_cache_ts.get(tenant_id, 0)
        if now - ts < self._cache_ttl and tenant_id in self._rules_cache:
            return self._rules_cache[tenant_id]

        try:
            row = await self._pool.fetchrow(
                "SELECT rules FROM notification_routing_rules WHERE tenant_id = $1",
                tenant_id,
            )
            if row:
                rules = json.loads(row["rules"]) if isinstance(row["rules"], str) else row["rules"]
                self._rules_cache[tenant_id] = rules
                self._rules_cache_ts[tenant_id] = now
                return rules
            return []
        except Exception as e:
            logger.warning("rules_cache_error", error=str(e))
            return self._rules_cache.get(tenant_id, [])

    async def _get_channels(self, tenant_id: str) -> dict[str, dict]:
        """Get all enabled channels for tenant, keyed by ID (cached)."""
        now = time.monotonic()
        ts = self._channels_cache_ts.get(tenant_id, 0)
        if now - ts < self._cache_ttl and tenant_id in self._channels_cache:
            return self._channels_cache.get(tenant_id, {})

        try:
            rows = await self._pool.fetch(
                """
                SELECT id, channel_type, config, enabled, rate_limit_per_min
                FROM notification_channels
                WHERE tenant_id = $1 AND enabled = true
                """,
                tenant_id,
            )
            result = {r["id"]: dict(r) for r in rows}
            self._channels_cache[tenant_id] = result
            self._channels_cache_ts[tenant_id] = now
            return result
        except Exception as e:
            logger.warning("channels_cache_error", error=str(e))
            return self._channels_cache.get(tenant_id, {})
