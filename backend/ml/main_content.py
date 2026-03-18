# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Content Analysis Consumer (JB6).

Kafka consumer that reads events from all tenant topics and runs
content analysis (prompt injection, jailbreak, data classification)
via ``GatewayContentHook.analyze_event()``.

When content is blocked or generates an alert the result is published
to ``phantex.alerts.{tenant_id}`` so the rule engine, dashboard, and
SIEM integrations can act on it.

Run: python -m ml.main_content
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
from typing import Any

import structlog

from app.config import get_settings
from app.consumers.base_consumer import BaseStorageConsumer

logger = structlog.get_logger("phantex.ml.content.consumer")

class ContentAnalysisConsumer(BaseStorageConsumer):
    """Kafka consumer that runs content analysis for every event."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="content-analysis",
            consumer_group="ml-content",
            batch_size=32,
            flush_interval_seconds=0.5,
            **kwargs,
        )
        self._hook = None  # Lazy init

    def _get_hook(self):
        if self._hook is None:
            from ml.content.integration.gateway_hook import GatewayContentHook

            self._hook = GatewayContentHook()
        return self._hook

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Run content analysis on a batch of events."""
        hook = self._get_hook()
        settings = get_settings()
        blocked = 0
        alerts = 0

        for event in events:
            # Extract text content — events carry payload.content or
            # payload.prompt / payload.response depending on direction.
            payload = event.get("payload", {})
            content = payload.get("content") or payload.get("prompt") or payload.get("response") or ""
            if not content:
                continue

            agent_id = event.get("agent_id", "")
            tenant_id = event.get("tenant_id", "")
            event_id = event.get("event_id", "")
            direction = payload.get("direction", "inbound")

            result = hook.analyze_event(
                content,
                agent_id=agent_id,
                tenant_id=tenant_id,
                event_id=event_id,
                direction=direction,
            )

            if not result.allowed:
                blocked += 1

            # Publish alert to Kafka if warranted
            if result.alert is not None:
                alerts += 1
                alert_topic = f"{settings.kafka_alert_topic_prefix}.{tenant_id}"
                try:
                    await self._produce_alert(alert_topic, result)
                except Exception:
                    logger.warning(
                        "content_alert_publish_failed",
                        event_id=event_id,
                        exc_info=True,
                    )

        if blocked or alerts:
            logger.info(
                "content_batch_done",
                batch_size=len(events),
                blocked=blocked,
                alerts=alerts,
            )

    async def _produce_alert(self, topic: str, result) -> None:  # noqa: ANN001
        """Publish a content analysis alert to Kafka."""
        from dataclasses import asdict

        alert_data = {
            "type": "content_analysis",
            "decision": result.decision,
            "severity": result.severity,
            "score": result.score,
            "allowed": result.allowed,
            "degraded": result.degraded,
            "processing_ms": result.processing_ms,
            "metadata": result.metadata,
        }
        if result.alert is not None:
            try:
                alert_data["alert"] = asdict(result.alert)
            except Exception:
                alert_data["alert"] = str(result.alert)

        if self._producer is not None:
            await self._producer.send_and_wait(
                topic,
                json.dumps(alert_data, default=str).encode(),
            )

async def main() -> None:
    """Start the content analysis consumer."""
    from app.utils.logging import setup_logging

    setup_logging()
    settings = get_settings()

    ssl_ctx = None
    if settings.kafka_tls_enabled:
        import ssl

        ssl_ctx = ssl.create_default_context()
        if settings.kafka_tls_ca_file:
            ssl_ctx.load_verify_locations(settings.kafka_tls_ca_file)
        if settings.kafka_tls_cert_file and settings.kafka_tls_key_file:
            ssl_ctx.load_cert_chain(settings.kafka_tls_cert_file, settings.kafka_tls_key_file)

    consumer = ContentAnalysisConsumer(
        bootstrap_servers=settings.kafka_bootstrap,
        ssl_context=ssl_ctx,
    )

    await consumer.start()

    # Wait for shutdown signal
    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("content_consumer_shutdown_signal")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)

    logger.info("content_analysis_consumer_running")
    await shutdown_event.wait()

    await consumer.stop()
    logger.info("content_analysis_consumer_stopped")

if __name__ == "__main__":
    asyncio.run(main())
