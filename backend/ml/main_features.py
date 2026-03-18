# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Feature Extraction Consumer (J1).

Kafka consumer that reads events from all tenant topics and runs the
feature extraction pipeline. Produces Redis feature vectors per agent.

Run: python -m ml.main_features
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from typing import Any

import structlog

from app.config import get_settings
from app.consumers.base_consumer import BaseStorageConsumer
from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.features.consumer")

class FeatureExtractionConsumer(BaseStorageConsumer):
    """Kafka consumer that extracts features for every event."""

    def __init__(self, redis_client, **kwargs: Any) -> None:
        cfg = get_ml_config().features
        super().__init__(
            name="feature-extractor",
            consumer_group=cfg.consumer_group,
            batch_size=cfg.batch_size,
            flush_interval_seconds=cfg.flush_interval_seconds,
            **kwargs,
        )
        self._redis = redis_client
        self._extractor = None  # Lazy init

    def _get_extractor(self):
        if self._extractor is None:
            from ml.features.extractor import FeatureExtractor

            self._extractor = FeatureExtractor(self._redis)
        return self._extractor

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Extract features for a batch of events."""
        extractor = self._get_extractor()
        count = await extractor.process_batch(events)
        logger.debug(
            "features_extracted",
            batch_size=len(events),
            processed=count,
        )

async def main() -> None:
    """Start the feature extraction consumer."""
    from app.utils.logging import setup_logging

    setup_logging()
    settings = get_settings()

    # Connect to Redis
    import redis.asyncio as aioredis

    redis_client = aioredis.from_url(
        settings.redis_url,
        decode_responses=False,
    )

    ssl_ctx = None
    if settings.kafka_tls_enabled:
        import ssl

        ssl_ctx = ssl.create_default_context()
        if settings.kafka_tls_ca_file:
            ssl_ctx.load_verify_locations(settings.kafka_tls_ca_file)
        if settings.kafka_tls_cert_file and settings.kafka_tls_key_file:
            ssl_ctx.load_cert_chain(settings.kafka_tls_cert_file, settings.kafka_tls_key_file)

    consumer = FeatureExtractionConsumer(
        redis_client,
        bootstrap_servers=settings.kafka_bootstrap,
        ssl_context=ssl_ctx,
    )

    await consumer.start()

    # Wait for shutdown signal
    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("feature_consumer_shutdown_signal")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)

    logger.info("feature_extraction_consumer_running")
    await shutdown_event.wait()

    await consumer.stop()
    await redis_client.close()
    logger.info("feature_extraction_consumer_stopped")

if __name__ == "__main__":
    asyncio.run(main())
