# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Alert Publisher — publishes alerts to Kafka and in-memory broadcast.

When a PRL rule fires and an alert is created in PostgreSQL, this module:
1. Serializes the alert to JSON
2. Publishes to Kafka topic `phantex.alerts.{tenant_id}`
3. Broadcasts to in-memory subscribers (WebSocket connections)

The Kafka publish is fire-and-forget at if Kafka is down,
the alert is still in PostgreSQL (source of truth). Kafka is for
real-time fan-out only.

Usage:
    publisher = AlertPublisher(kafka_bootstrap="localhost:9092")
    await publisher.start()
    await publisher.publish_alert(alert_data, tenant_id)
    await publisher.stop()
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import structlog

from engine.utils.truncate import truncate_dict

logger = structlog.get_logger("phantex.alerting.publisher")

# ── Alert Data Builder ────────────────────────────────────────────────────────

def build_alert_payload(
    *,
    alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    rule_id: uuid.UUID,
    rule_name: str,
    severity: str,
    attack_class: str | None,
    agent_id: str | None,
    event_id: uuid.UUID | None,
    event_type: str,
    event_data: dict[str, Any],
    title: str,
    description: str,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """
    Build a standardized alert payload for Kafka and WebSocket broadcast.

    This payload includes everything the dashboard needs to render an alert
    without additional API calls.
    """
    return {
        "alert_id": str(alert_id),
        "tenant_id": str(tenant_id),
        "rule_id": str(rule_id),
        "rule_name": rule_name,
        "severity": severity,
        "attack_class": attack_class,
        "agent_id": str(agent_id) if agent_id else None,
        "event_id": str(event_id) if event_id else None,
        "event_type": event_type,
        "title": title,
        "description": description,
        "status": "open",
        "created_at": timestamp or datetime.now(UTC).isoformat(),
        "event_snapshot": truncate_dict(event_data, max_size=2048, max_str_len=128, nested_str_len=64, max_keys=15),
    }

# ── In-Memory Broadcast (for WebSocket) ──────────────────────────────────────

# Type for subscriber callbacks
AlertCallback = Callable[[dict[str, Any]], Awaitable[None]]

class AlertBroadcaster:
    """
    In-memory pub/sub for alert notifications.

    WebSocket connections subscribe per-tenant. When an alert is published,
    all subscribers for that tenant receive it immediately.

    This is process-local — in a multi-process deployment, use Kafka consumer
    in each process or Redis pub/sub.
    """

    def __init__(self) -> None:
        # tenant_id → set of subscriber IDs
        self._subscribers: dict[str, dict[str, AlertCallback]] = {}

    def subscribe(
        self,
        tenant_id: str,
        subscriber_id: str,
        callback: AlertCallback,
    ) -> None:
        """Register a callback for alerts on a specific tenant."""
        if tenant_id not in self._subscribers:
            self._subscribers[tenant_id] = {}
        self._subscribers[tenant_id][subscriber_id] = callback
        logger.debug(
            "subscriber_added",
            tenant_id=tenant_id,
            subscriber_id=subscriber_id,
            total=len(self._subscribers[tenant_id]),
        )

    def unsubscribe(self, tenant_id: str, subscriber_id: str) -> None:
        """Remove a subscriber."""
        if tenant_id in self._subscribers:
            self._subscribers[tenant_id].pop(subscriber_id, None)
            if not self._subscribers[tenant_id]:
                del self._subscribers[tenant_id]
            logger.debug(
                "subscriber_removed",
                tenant_id=tenant_id,
                subscriber_id=subscriber_id,
            )

    async def broadcast(self, tenant_id: str, alert_payload: dict[str, Any]) -> int:
        """
        Send an alert to all subscribers for a tenant.
        Returns the number of subscribers notified.
        """
        subscribers = self._subscribers.get(tenant_id, {})
        if not subscribers:
            return 0

        notified = 0
        failed_ids: list[str] = []

        for sub_id, callback in list(subscribers.items()):
            try:
                await callback(alert_payload)
                notified += 1
            except Exception as e:
                logger.warning(
                    "broadcast_failed",
                    subscriber_id=sub_id,
                    error=str(e),
                )
                failed_ids.append(sub_id)

        # Clean up failed subscribers (likely disconnected WebSockets)
        for sub_id in failed_ids:
            self.unsubscribe(tenant_id, sub_id)

        return notified

    @property
    def subscriber_count(self) -> int:
        """Total subscribers across all tenants."""
        return sum(len(subs) for subs in self._subscribers.values())

    @property
    def tenant_count(self) -> int:
        """Number of tenants with active subscribers."""
        return len(self._subscribers)

# ── Kafka Alert Publisher ─────────────────────────────────────────────────────

class AlertPublisher:
    """
    Publishes alert payloads to Kafka topic `phantex.alerts.{tenant_id}`.

    Also broadcasts to in-memory subscribers for WebSocket push.
    """

    def __init__(
        self,
        kafka_bootstrap: str = "localhost:9092",
        topic_prefix: str = "phantex.alerts",
        broadcaster: AlertBroadcaster | None = None,
    ) -> None:
        self._kafka_bootstrap = kafka_bootstrap
        self._topic_prefix = topic_prefix
        self._producer = None  # Lazy init
        self._started = False
        self.broadcaster = broadcaster or AlertBroadcaster()

        # Metrics
        self._alerts_published: int = 0
        self._kafka_errors: int = 0
        self._ws_notifications: int = 0

    async def start(self) -> None:
        """Start the Kafka producer."""
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError:
            logger.warning(
                "aiokafka_not_installed",
                msg="Kafka alert publishing disabled — aiokafka not installed",
            )
            self._started = True  # Still allow in-memory broadcast
            return

        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._kafka_bootstrap,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                compression_type="gzip",
                acks=1,
                request_timeout_ms=5000,
                max_batch_size=1048576,  # 1MB
            )
            await self._producer.start()
            self._started = True
            logger.info("alert_publisher_started", bootstrap=self._kafka_bootstrap)
        except Exception as e:
            logger.error("alert_publisher_start_failed", error=str(e))
            self._started = True  # Still allow in-memory broadcast

    async def stop(self) -> None:
        """Stop the Kafka producer."""
        if self._producer:
            try:
                await self._producer.stop()
            except Exception as e:
                logger.warning("alert_producer_stop_error", error=str(e))
        self._started = False
        logger.info(
            "alert_publisher_stopped",
            alerts_published=self._alerts_published,
            kafka_errors=self._kafka_errors,
            ws_notifications=self._ws_notifications,
        )

    async def publish_alert(
        self,
        alert_payload: dict[str, Any],
        tenant_id: str,
    ) -> None:
        """
        Publish an alert to Kafka and broadcast to WebSocket subscribers.

        Fire-and-forget for Kafka — the alert is already in PostgreSQL.
        If Kafka fails, we log the error but don't retry (alert is safe in DB).

        Also publishes a derived ALERT event to the events topic so ClickHouse
        analytics (attack_class trend, KPI alerts count) reflect rule hits.
        """
        topic = f"{self._topic_prefix}.{tenant_id}"

        # 1) Kafka publish (alert topic)
        if self._producer:
            try:
                await self._producer.send_and_wait(
                    topic=topic,
                    value=alert_payload,
                    key=alert_payload.get("rule_name", "unknown"),
                    headers=[
                        ("tenant_id", tenant_id.encode("utf-8")),
                        ("severity", alert_payload.get("severity", "medium").encode("utf-8")),
                        ("alert_id", alert_payload.get("alert_id", "").encode("utf-8")),
                    ],
                )
                self._alerts_published += 1
                logger.info(
                    "alert_published_kafka",
                    topic=topic,
                    alert_id=alert_payload.get("alert_id"),
                    rule_name=alert_payload.get("rule_name"),
                    severity=alert_payload.get("severity"),
                )
            except Exception as e:
                self._kafka_errors += 1
                logger.error(
                    "alert_kafka_publish_failed",
                    topic=topic,
                    alert_id=alert_payload.get("alert_id"),
                    error=str(e),
                )

            # 1b) Also publish a derived ALERT event to the main events topic
            #     so ch_writer inserts it with attack_class for analytics.
            try:
                alert_event = {
                    "event_id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "agent_id": alert_payload.get("agent_id", ""),
                    "framework": "",
                    "event_type": "ALERT",
                    "severity": (alert_payload.get("severity") or "medium").lower(),
                    "attack_class": alert_payload.get("attack_class"),
                    "timestamp": alert_payload.get("created_at", datetime.now(UTC).isoformat()),
                }
                events_topic = f"phantex.events.{tenant_id}"
                await self._producer.send_and_wait(
                    topic=events_topic,
                    value=alert_event,
                    key=alert_payload.get("rule_name", "unknown"),
                )
                logger.debug(
                    "alert_event_published_to_events",
                    events_topic=events_topic,
                    attack_class=alert_event["attack_class"],
                )
            except Exception as e:
                logger.warning("alert_event_publish_failed", error=str(e))
        else:
            logger.debug(
                "alert_kafka_skipped",
                msg="No Kafka producer — alert only in DB + WebSocket",
                alert_id=alert_payload.get("alert_id"),
            )

        # 2) In-memory broadcast (WebSocket push)
        try:
            notified = await self.broadcaster.broadcast(tenant_id, alert_payload)
            self._ws_notifications += notified
            if notified > 0:
                logger.debug(
                    "alert_broadcast_ws",
                    tenant_id=tenant_id,
                    notified=notified,
                    alert_id=alert_payload.get("alert_id"),
                )
        except Exception as e:
            logger.warning("alert_broadcast_failed", error=str(e))

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "alerts_published": self._alerts_published,
            "kafka_errors": self._kafka_errors,
            "ws_notifications": self._ws_notifications,
            "ws_subscribers": self.broadcaster.subscriber_count,
            "ws_tenants": self.broadcaster.tenant_count,
            "kafka_connected": self._producer is not None,
            "started": self._started,
        }
