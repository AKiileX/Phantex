# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Baseline Consumer (J4).

Kafka consumer that runs the behavioral baseline engine on every event.
Computes features, updates baselines, and generates deviation alerts.

Run: python -m ml.main_baseline
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from typing import Any

import structlog

from app.config import get_settings
from app.consumers.base_consumer import BaseStorageConsumer

logger = structlog.get_logger("phantex.ml.baseline.consumer")

class BaselineConsumer(BaseStorageConsumer):
    """Kafka consumer that processes events through the baseline engine.

    Baseline alerts are published to ``phantex.alerts.{tenant_id}``
    Kafka topic for downstream consumption (SIEM, notifications, dashboard).
    """

    def __init__(self, redis_client, pg_pool=None, **kwargs: Any) -> None:
        super().__init__(
            name="baseline-engine",
            consumer_group="ml-baseline",
            batch_size=500,
            flush_interval_seconds=1.0,
            **kwargs,
        )
        self._redis = redis_client
        self._pg_pool = pg_pool
        self._alert_topic_prefix = get_settings().kafka_alert_topic_prefix
        self._extractor = None
        self._updater = None

    def _get_extractor(self):
        if self._extractor is None:
            from ml.features.extractor import FeatureExtractor

            self._extractor = FeatureExtractor(self._redis)
        return self._extractor

    def _get_updater(self):
        if self._updater is None:
            from ml.baseline.updater import BaselineUpdater

            self._updater = BaselineUpdater(self._pg_pool)
        return self._updater

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Process events: extract features, update baselines, generate alerts."""
        extractor = self._get_extractor()
        updater = self._get_updater()

        total_alerts = 0
        for event in events:
            tenant_id = event.get("tenant_id")
            agent_id = event.get("agent_id")
            if not tenant_id or not agent_id:
                continue

            # Get current features from Redis
            features = await extractor.get_features(tenant_id, agent_id)

            # Run baseline comparison and update
            alerts = await updater.process_event(event, features)
            total_alerts += len(alerts)

            # Publish baseline alerts to Kafka alert topic
            for alert in alerts:
                alert.setdefault("tenant_id", tenant_id)
                alert.setdefault("agent_id", agent_id)
                alert.setdefault("alert_type", "baseline_deviation")
                await self._publish_baseline_alert(alert)

                logger.info(
                    "baseline_alert",
                    alert_type=alert.get("type"),
                    severity=alert.get("severity"),
                    metric=alert.get("metric", ""),
                    agent_id=agent_id,
                    tenant_id=tenant_id,
                )

        if total_alerts > 0:
            logger.info(
                "baseline_alerts_generated",
                batch_size=len(events),
                alerts=total_alerts,
            )

    async def _publish_baseline_alert(self, alert: dict[str, Any]) -> None:
        """Publish a baseline deviation alert to Kafka.

        Uses the same ``phantex.alerts.{tenant_id}`` topic as PRL rule
        and ML ensemble alerts.
        """
        tenant_id = alert.get("tenant_id", "unknown")
        topic = f"{self._alert_topic_prefix}.{tenant_id}"
        if self._producer:
            try:
                await self._producer.send_and_wait(
                    topic=topic,
                    value=alert,
                )
                logger.debug(
                    "baseline_alert_published_kafka",
                    topic=topic,
                    alert_type=alert.get("type"),
                    agent_id=alert.get("agent_id"),
                )
            except Exception as e:
                logger.error(
                    "baseline_alert_kafka_publish_failed",
                    topic=topic,
                    error=str(e),
                )
        else:
            logger.debug(
                "baseline_alert_kafka_skipped",
                msg="No Kafka producer — alert logged only",
            )

async def main() -> None:
    """Start the baseline consumer."""
    from app.utils.logging import setup_logging

    setup_logging()
    settings = get_settings()

    import redis.asyncio as aioredis

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)

    # PostgreSQL pool for baseline persistence
    pg_pool = None
    try:
        import asyncpg

        pg_ssl_ctx = _build_pg_ssl_context(settings)
        pg_pool = await asyncpg.create_pool(
            dsn=settings.database_url_sync,
            min_size=2,
            max_size=5,
            ssl=pg_ssl_ctx,
        )
    except Exception as e:
        logger.warning("pg_pool_init_error", error=str(e))

    ssl_ctx = None
    if settings.kafka_tls_enabled:
        import ssl

        ssl_ctx = ssl.create_default_context()
        if settings.kafka_tls_ca_file:
            ssl_ctx.load_verify_locations(settings.kafka_tls_ca_file)
        if settings.kafka_tls_cert_file and settings.kafka_tls_key_file:
            ssl_ctx.load_cert_chain(settings.kafka_tls_cert_file, settings.kafka_tls_key_file)

    consumer = BaselineConsumer(
        redis_client,
        pg_pool=pg_pool,
        bootstrap_servers=settings.kafka_bootstrap,
        ssl_context=ssl_ctx,
    )

    await consumer.start()

    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("baseline_consumer_shutdown_signal")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)

    logger.info("baseline_consumer_running")
    await shutdown_event.wait()

    await consumer.stop()
    await redis_client.close()
    if pg_pool:
        await pg_pool.close()
    logger.info("baseline_consumer_stopped")

def _build_pg_ssl_context(settings):
    """Build SSL context for asyncpg pool in the baseline consumer.

    Mirrors the logic in ``app.main_consumer._build_pg_ssl_context`` so
    that baseline consumer PG connections use the same TLS settings as
    the main engine.
    """
    import ssl as _ssl

    mode = settings.db_ssl_mode
    if mode == "disable":
        return None
    # asyncpg natively supports "prefer" as a string — it negotiates
    # SSL and falls back silently if the server doesn't support it.
    if mode in ("prefer", "allow"):
        return "prefer"

    ctx = _ssl.create_default_context()

    if settings.db_ssl_ca_file:
        ctx.load_verify_locations(settings.db_ssl_ca_file)
    if settings.db_ssl_cert_file and settings.db_ssl_key_file:
        ctx.load_cert_chain(settings.db_ssl_cert_file, settings.db_ssl_key_file)

    if mode in ("require", "allow", "prefer"):
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    elif mode == "verify-ca":
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_REQUIRED
    elif mode == "verify-full":
        ctx.check_hostname = True
        ctx.verify_mode = _ssl.CERT_REQUIRED

    return ctx

if __name__ == "__main__":
    asyncio.run(main())
