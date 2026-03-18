# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ML Inference Consumer (J3 + J5 Integration).

Kafka consumer that runs ML inference on every event, generates
explainable alerts, and runs periodic meta-detection checks
(drift, evasion, staleness, accuracy).

Run: python -m ml.main_inference
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

logger = structlog.get_logger("phantex.ml.inference.consumer")

# Run meta checks every N batches (not per-event to keep hot-path fast)
_META_CHECK_INTERVAL_BATCHES = 20

class InferenceConsumer(BaseStorageConsumer):
    """Kafka consumer that scores events through the ML ensemble.

    J5 enhancements:
      - Pipeline now includes EnsembleExplainer + EvasionDetector.
      - Periodic meta-detection: drift, staleness, accuracy, evasion alerting.
      - ML alerts are published to ``phantex.alerts.{tenant_id}`` Kafka topic.
    """

    def __init__(self, redis_client, model_registry, **kwargs: Any) -> None:
        cfg = get_ml_config().inference
        super().__init__(
            name="ml-inference",
            consumer_group=cfg.consumer_group,
            batch_size=cfg.batch_size,
            flush_interval_seconds=cfg.flush_interval_seconds,
            **kwargs,
        )
        self._redis = redis_client
        self._registry = model_registry
        self._alert_topic_prefix = get_settings().kafka_alert_topic_prefix
        self._pipeline = None  # Lazy init
        self._meta_alerter = None
        self._staleness_checker = None
        self._accuracy_tracker = None
        self._drift_detector = None
        self._batch_counter: int = 0
        self._recent_scores: list[float] = []  # Collect scores for drift checks

    def _get_pipeline(self):
        if self._pipeline is None:
            from ml.explainability.ensemble_explainer import EnsembleExplainer
            from ml.features.extractor import FeatureExtractor
            from ml.meta.accuracy_tracker import AccuracyTracker
            from ml.meta.alerter import MetaAlerter
            from ml.meta.drift_detector import DriftDetector
            from ml.meta.evasion_detector import EvasionDetector
            from ml.meta.staleness_checker import StalenessChecker
            from ml.serving.inference import InferencePipeline
            from ml.serving.model_loader import ModelLoader

            extractor = FeatureExtractor(self._redis)
            loader = ModelLoader(self._registry)
            explainer = EnsembleExplainer()
            evasion = EvasionDetector(
                threshold=get_ml_config().ensemble.alert_threshold,
            )

            self._pipeline = InferencePipeline(
                extractor,
                loader,
                explainer=explainer,
                evasion_detector=evasion,
            )
            self._meta_alerter = MetaAlerter()
            self._staleness_checker = StalenessChecker()
            self._accuracy_tracker = AccuracyTracker()
            self._drift_detector = DriftDetector()
        return self._pipeline

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Score events and produce ML alerts."""
        pipeline = self._get_pipeline()
        alerts = await pipeline.score_batch(events)

        # F4-fix: Collect ALL event scores for drift detection, not just
        # alerts.  The evasion detector inside InferencePipeline records
        # every score already — mirror the counter here so drift detection
        # sees the full distribution (both alerting and non-alerting scores).
        evasion_det = pipeline.evasion_detector
        self._recent_scores = [s for _, s in evasion_det._scores]
        # Cap recent scores buffer
        if len(self._recent_scores) > 10_000:
            self._recent_scores = self._recent_scores[-10_000:]

        if alerts:
            logger.info(
                "ml_alerts_produced",
                batch_size=len(events),
                alerts=len(alerts),
            )
            # Publish alerts to Kafka alert topic (same pipeline as PRL rule alerts)
            for alert in alerts:
                await self._publish_ml_alert(alert)

        # ── J5d: Periodic meta-detection checks ─────────────────────
        self._batch_counter += 1
        if self._batch_counter % _META_CHECK_INTERVAL_BATCHES == 0:
            self._run_meta_checks()

    async def _publish_ml_alert(self, alert: dict[str, Any]) -> None:
        """Publish an ML alert to the Kafka alert topic.

        Uses the same ``phantex.alerts.{tenant_id}`` topic as PRL rule
        alerts so that downstream consumers (SIEM, notifications,
        dashboard WebSocket bridge) receive ML alerts identically.
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
                    "ml_alert_published_kafka",
                    topic=topic,
                    agent_id=alert.get("agent_id"),
                    score=alert.get("score"),
                )
            except Exception as e:
                logger.error(
                    "ml_alert_kafka_publish_failed",
                    topic=topic,
                    error=str(e),
                )
        else:
            logger.debug(
                "ml_alert_kafka_skipped",
                msg="No Kafka producer — alert logged only",
            )

    def _run_meta_checks(self) -> None:
        """Run meta-detection sweep (evasion, staleness, accuracy, drift)."""
        import numpy as np

        from ml.meta.alerter import MetaAlertType

        # Evasion check (already tracked per-score in InferencePipeline)
        evasion_result = self._pipeline.evasion_detector.check()
        if evasion_result.detected:
            self._meta_alerter.fire(
                MetaAlertType.EVASION_PATTERN,
                f"Evasion pattern detected: {evasion_result.near_threshold_count} scores "
                f"clustered near threshold (ratio {evasion_result.ratio:.1f}×)",
                details=evasion_result.to_dict(),
            )

        # Staleness check
        stale = self._staleness_checker.get_stale_models()
        for s in stale:
            self._meta_alerter.fire(
                MetaAlertType.MODEL_STALE,
                f"Model {s.model_id} is {s.age_days:.0f} days old (max {s.max_age_days})",
                details=s.to_dict(),
            )

        # Accuracy check
        snapshot = self._accuracy_tracker.compute()
        if snapshot.precision < self._accuracy_tracker._precision_thresh:
            self._meta_alerter.fire(
                MetaAlertType.ACCURACY_DRIFT,
                f"Precision degraded to {snapshot.precision:.2f} "
                f"(threshold {self._accuracy_tracker._precision_thresh})",
                details=snapshot.to_dict(),
            )

        # INT-02: Prediction drift check (KL divergence on score distribution)
        if len(self._recent_scores) >= 100 and self._drift_detector is not None:
            scores_arr = np.array(self._recent_scores)
            mid = len(scores_arr) // 2
            drift_result = self._drift_detector.check_prediction_drift(
                baseline_scores=scores_arr[:mid],
                current_scores=scores_arr[mid:],
            )
            if drift_result.drifted:
                self._meta_alerter.fire(
                    MetaAlertType.PREDICTION_DRIFT,
                    f"Prediction distribution drift detected "
                    f"(KL={drift_result.metric_value:.4f}, "
                    f"threshold={drift_result.threshold})",
                    details=drift_result.to_dict(),
                )

async def main() -> None:
    """Start the ML inference consumer."""
    from app.utils.logging import setup_logging

    setup_logging()
    settings = get_settings()

    import redis.asyncio as aioredis

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)

    from ml.registry.model_registry import ModelRegistry

    registry = ModelRegistry()

    ssl_ctx = None
    if settings.kafka_tls_enabled:
        import ssl

        ssl_ctx = ssl.create_default_context()
        if settings.kafka_tls_ca_file:
            ssl_ctx.load_verify_locations(settings.kafka_tls_ca_file)
        if settings.kafka_tls_cert_file and settings.kafka_tls_key_file:
            ssl_ctx.load_cert_chain(settings.kafka_tls_cert_file, settings.kafka_tls_key_file)

    consumer = InferenceConsumer(
        redis_client,
        registry,
        bootstrap_servers=settings.kafka_bootstrap,
        ssl_context=ssl_ctx,
    )

    await consumer.start()

    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("inference_consumer_shutdown_signal")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)

    logger.info("inference_consumer_running")
    await shutdown_event.wait()

    await consumer.stop()
    await redis_client.close()
    logger.info("inference_consumer_stopped")

if __name__ == "__main__":
    asyncio.run(main())
