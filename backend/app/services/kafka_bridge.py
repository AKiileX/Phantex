# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Kafka-to-WebSocket Alert Bridge.

Bridges the gap between the rule engine (separate process) and the FastAPI
WebSocket layer. The rule engine publishes alerts to Kafka topics
``phantex.alerts.{tenant_id}``. This consumer reads those topics and pushes
each alert through the in-memory AlertBroadcaster, which fans out to all
connected WebSocket clients for that tenant.

Architecture:
    Rule Engine  →  Kafka (phantex.alerts.*)  →  [THIS BRIDGE]  →  AlertBroadcaster  →  WebSocket clients

Design decisions:
    - ``auto_offset_reset="latest"`` — dashboards care about live alerts, not
      historical replay. Replaying old alerts on restart would flood the UI.
    - Consumer group ``api-realtime`` — each FastAPI process gets all messages
      (single-worker Phase 1; for multi-worker, use a broadcast group or
      Redis pub/sub in Phase 2).
    - Graceful degradation: if Kafka is unavailable at startup the bridge
      retries silently; in-memory broadcast still works for same-process alerts.
    - Bad messages (deserialization failure) are logged and skipped, never crash.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from typing import Any

import structlog

from engine.alerting.publisher import AlertBroadcaster

logger = structlog.get_logger("phantex.services.kafka_bridge")

# Regex to extract tenant_id from topic name: phantex.alerts.<tenant_id>
_TOPIC_TENANT_RE = re.compile(r"^phantex\.alerts\.(.+)$")

class KafkaAlertBridge:
    """
    Async Kafka consumer that reads ``phantex.alerts.*`` and pushes
    each alert into the in-memory AlertBroadcaster for WebSocket delivery.
    """

    def __init__(
        self,
        broadcaster: AlertBroadcaster,
        *,
        bootstrap_servers: str = "localhost:9092",
        topic_pattern: str = r"^phantex\.alerts\..+$",
        consumer_group: str = "api-realtime",
        ssl_context: Any | None = None,
    ) -> None:
        self._broadcaster = broadcaster
        self._bootstrap_servers = bootstrap_servers
        self._topic_pattern = topic_pattern
        self._consumer_group = consumer_group
        self._ssl_context = ssl_context
        self._consumer = None
        self._running = False
        self._task: asyncio.Task | None = None

        # Metrics
        self.messages_consumed: int = 0
        self.messages_broadcast: int = 0
        self.deserialization_errors: int = 0
        self.broadcast_errors: int = 0

    async def start(self) -> None:
        """Start the Kafka consumer in a background asyncio task."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._consume_loop(), name="kafka-alert-bridge")
        logger.info(
            "kafka_bridge_starting",
            bootstrap=self._bootstrap_servers,
            topic_pattern=self._topic_pattern,
            consumer_group=self._consumer_group,
        )

    async def stop(self) -> None:
        """Stop the consumer and wait for the task to finish."""
        self._running = False

        if self._consumer:
            try:
                await self._consumer.stop()
            except Exception as e:
                logger.warning("kafka_bridge_consumer_stop_error", error=str(e))

        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        logger.info(
            "kafka_bridge_stopped",
            messages_consumed=self.messages_consumed,
            messages_broadcast=self.messages_broadcast,
            deserialization_errors=self.deserialization_errors,
        )

    async def _consume_loop(self) -> None:
        """
        Main consumer loop with automatic retry on Kafka connection failure.

        Retries every 5 seconds if Kafka is unreachable. Uses ``auto_offset_reset="latest"``
        so dashboards only see live alerts, not historical replay.
        """
        while self._running:
            try:
                await self._run_consumer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("kafka_bridge_consumer_error", error=str(e))
                if self._running:
                    logger.info("kafka_bridge_reconnecting", delay_seconds=5)
                    await asyncio.sleep(5)

    async def _run_consumer(self) -> None:
        """Create consumer, subscribe to pattern, and process messages."""
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError:
            logger.warning(
                "aiokafka_not_installed",
                msg="Kafka bridge disabled — aiokafka not installed. "
                "Alerts will only be delivered via same-process broadcast.",
            )
            self._running = False
            return

        consumer_kwargs: dict[str, Any] = {
            "bootstrap_servers": self._bootstrap_servers,
            "group_id": self._consumer_group,
            "auto_offset_reset": "latest",
            "enable_auto_commit": True,
            "auto_commit_interval_ms": 5000,
            "value_deserializer": lambda v: v,  # raw bytes, we deserialize manually
            "request_timeout_ms": 10000,
            "session_timeout_ms": 30000,
            "heartbeat_interval_ms": 10000,
            "max_poll_records": 100,
        }
        if self._ssl_context is not None:
            consumer_kwargs["security_protocol"] = "SSL"
            consumer_kwargs["ssl_context"] = self._ssl_context

        self._consumer = AIOKafkaConsumer(**consumer_kwargs)

        # Subscribe to topic pattern
        self._consumer.subscribe(pattern=self._topic_pattern)

        try:
            await self._consumer.start()
            logger.info(
                "kafka_bridge_consumer_started",
                bootstrap=self._bootstrap_servers,
                group=self._consumer_group,
            )

            async for msg in self._consumer:
                if not self._running:
                    break
                await self._process_message(msg)

        finally:
            with contextlib.suppress(Exception):
                await self._consumer.stop()

    async def _process_message(self, msg: Any) -> None:
        """Deserialize a Kafka message and broadcast to WebSocket subscribers."""
        self.messages_consumed += 1

        # Extract tenant_id from topic name
        topic = msg.topic
        match = _TOPIC_TENANT_RE.match(topic)
        if not match:
            # Fallback: try extracting from message headers
            tenant_id = self._extract_tenant_from_headers(msg)
            if not tenant_id:
                logger.warning(
                    "kafka_bridge_unknown_topic",
                    topic=topic,
                    offset=msg.offset,
                )
                return
        else:
            tenant_id = match.group(1)

        # Deserialize alert payload
        try:
            if isinstance(msg.value, bytes):
                alert_payload = json.loads(msg.value.decode("utf-8"))
            elif isinstance(msg.value, str):
                alert_payload = json.loads(msg.value)
            else:
                alert_payload = msg.value
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.deserialization_errors += 1
            logger.warning(
                "kafka_bridge_deserialize_error",
                topic=topic,
                offset=msg.offset,
                error=str(e),
            )
            return

        # Broadcast to WebSocket subscribers for this tenant
        try:
            notified = await self._broadcaster.broadcast(tenant_id, alert_payload)
            self.messages_broadcast += 1

            if notified > 0:
                logger.debug(
                    "kafka_bridge_broadcast",
                    tenant_id=tenant_id,
                    notified=notified,
                    alert_id=alert_payload.get("alert_id"),
                    severity=alert_payload.get("severity"),
                )
        except Exception as e:
            self.broadcast_errors += 1
            logger.error(
                "kafka_bridge_broadcast_error",
                tenant_id=tenant_id,
                error=str(e),
            )

    @staticmethod
    def _extract_tenant_from_headers(msg: Any) -> str | None:
        """Extract tenant_id from Kafka message headers as fallback."""
        if not hasattr(msg, "headers") or not msg.headers:
            return None
        for key, value in msg.headers:
            if key == "tenant_id":
                return value.decode("utf-8") if isinstance(value, bytes) else str(value)
        return None

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "messages_consumed": self.messages_consumed,
            "messages_broadcast": self.messages_broadcast,
            "deserialization_errors": self.deserialization_errors,
            "broadcast_errors": self.broadcast_errors,
            "bootstrap_servers": self._bootstrap_servers,
            "consumer_group": self._consumer_group,
        }
