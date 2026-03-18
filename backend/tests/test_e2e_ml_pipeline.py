# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
End-to-end ML pipeline smoke tests.

Exercises the full path: event → feature extraction → inference →
ML alert → Kafka publish.  Also tests baseline-alert Kafka
publishing and ClickHouse data-loader sync path.

These tests use mocks for external services (Kafka, Redis, ClickHouse)
but validate that the entire pipeline is correctly wired.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Helpers ──────────────────────────────────────────────────────────────────

FEATURE_NAMES = [f"f{i}" for i in range(10)]

_SAMPLE_EVENT = {
    "tenant_id": str(uuid.uuid4()),
    "agent_id": str(uuid.uuid4()),
    "event_id": str(uuid.uuid4()),
    "event_type": "tool_call",
    "timestamp": "2025-01-01T00:00:00Z",
}

def _alerting_ensemble():
    """Mock ensemble that always triggers an alert."""
    mock = MagicMock()
    mock.score = MagicMock(
        return_value={
            "score": 0.85,
            "should_alert": True,
            "stage_scores": {"isolation_forest": 0.9, "xgboost": 0.8},
            "attack_class": "credential_theft",
            "probabilities": {"credential_theft": 0.8},
            "threshold": 0.7,
            "stages_active": ["isolation_forest", "xgboost"],
        }
    )
    return mock

def _quiet_ensemble():
    """Mock ensemble that never triggers."""
    mock = MagicMock()
    mock.score = MagicMock(
        return_value={
            "score": 0.3,
            "should_alert": False,
            "stage_scores": {"isolation_forest": 0.3},
            "attack_class": "benign",
            "probabilities": {},
            "threshold": 0.7,
            "stages_active": [],
        }
    )
    return mock

def _mock_feature_extractor():
    extractor = AsyncMock()
    extractor.get_features = AsyncMock(return_value={f"f{i}": 0.1 * i for i in range(10)})
    return extractor

def _mock_model_loader(ensemble=None, names=None):
    from ml.serving.model_loader import ModelLoader

    loader = MagicMock(spec=ModelLoader)
    loader.get_ensemble = MagicMock(return_value=ensemble)
    loader.get_shadow_ensemble = MagicMock(return_value=None)
    loader.get_feature_names = MagicMock(return_value=names or FEATURE_NAMES)

    if ensemble is not None:

        def _fused(tenant_id, features, feature_names, **kw):
            return ensemble.score(features, feature_names)

        loader.get_fused_ensemble_result = MagicMock(side_effect=_fused)
    else:
        loader.get_fused_ensemble_result = MagicMock(return_value=None)
    return loader

# ═══════════════════════════════════════════════════════════════════════════
# Inference consumer → Kafka alert publish
# ═══════════════════════════════════════════════════════════════════════════

class TestInferenceConsumerKafkaPublish:
    """InferenceConsumer publishes ML alerts to the Kafka alert topic."""

    @pytest.mark.asyncio
    async def test_alerts_published_to_kafka(self):
        """process_batch sends each ML alert to phantex.alerts.{tenant_id}."""
        from ml.main_inference import InferenceConsumer

        redis_client = AsyncMock()
        registry = MagicMock()

        consumer = InferenceConsumer(
            redis_client,
            registry,
            bootstrap_servers="localhost:9092",
        )

        # Wire a mock Kafka producer (normally created by _run_consumer)
        producer = AsyncMock()
        producer.send_and_wait = AsyncMock()
        consumer._producer = producer

        # Build an InferencePipeline that returns one alert
        ensemble = _alerting_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        pipeline = InferencePipeline(
            extractor,
            loader,
            explainer=EnsembleExplainer(),
        )
        consumer._pipeline = pipeline

        events = [_SAMPLE_EVENT.copy()]
        await consumer.process_batch(events)

        # Verify producer.send_and_wait was called with the alert topic
        assert producer.send_and_wait.call_count >= 1
        call_kwargs = producer.send_and_wait.call_args
        topic = call_kwargs.kwargs.get("topic") or call_kwargs[1].get(
            "topic", call_kwargs[0][0] if call_kwargs[0] else ""
        )
        expected_topic = f"phantex.alerts.{_SAMPLE_EVENT['tenant_id']}"
        assert expected_topic in str(topic) or expected_topic == topic

    @pytest.mark.asyncio
    async def test_no_kafka_no_crash(self):
        """If no Kafka producer, alerts are logged but pipeline doesn't crash."""
        from ml.main_inference import InferenceConsumer

        consumer = InferenceConsumer(
            AsyncMock(),
            MagicMock(),
            bootstrap_servers="localhost:9092",
        )
        consumer._producer = None  # No producer

        ensemble = _alerting_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        consumer._pipeline = InferencePipeline(
            extractor,
            loader,
            explainer=EnsembleExplainer(),
        )

        # Should not raise
        await consumer.process_batch([_SAMPLE_EVENT.copy()])

    @pytest.mark.asyncio
    async def test_quiet_events_produce_no_kafka(self):
        """Events below threshold produce no Kafka publishes."""
        from ml.main_inference import InferenceConsumer

        consumer = InferenceConsumer(
            AsyncMock(),
            MagicMock(),
            bootstrap_servers="localhost:9092",
        )
        producer = AsyncMock()
        consumer._producer = producer

        ensemble = _quiet_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        consumer._pipeline = InferencePipeline(
            extractor,
            loader,
            explainer=EnsembleExplainer(),
        )

        await consumer.process_batch([_SAMPLE_EVENT.copy()])
        producer.send_and_wait.assert_not_called()

# ═══════════════════════════════════════════════════════════════════════════
# Baseline consumer → Kafka alert publish
# ═══════════════════════════════════════════════════════════════════════════

class TestBaselineConsumerKafkaPublish:
    """BaselineConsumer publishes deviation alerts to Kafka."""

    @pytest.mark.asyncio
    async def test_baseline_alerts_published(self):
        """Baseline deviation alerts are sent to Kafka alert topic."""
        from ml.main_baseline import BaselineConsumer

        redis_client = AsyncMock()
        consumer = BaselineConsumer(
            redis_client,
            bootstrap_servers="localhost:9092",
        )
        producer = AsyncMock()
        consumer._producer = producer

        # Mock the updater to return one alert
        mock_updater = AsyncMock()
        mock_updater.process_event = AsyncMock(
            return_value=[
                {"type": "deviation", "severity": "high", "metric": "tool_call_count_1h"},
            ]
        )
        consumer._updater = mock_updater
        consumer._extractor = _mock_feature_extractor()

        events = [_SAMPLE_EVENT.copy()]
        await consumer.process_batch(events)

        assert producer.send_and_wait.call_count == 1

    @pytest.mark.asyncio
    async def test_baseline_no_alerts_no_publish(self):
        """No deviation → no Kafka publish."""
        from ml.main_baseline import BaselineConsumer

        consumer = BaselineConsumer(
            AsyncMock(),
            bootstrap_servers="localhost:9092",
        )
        producer = AsyncMock()
        consumer._producer = producer

        mock_updater = AsyncMock()
        mock_updater.process_event = AsyncMock(return_value=[])
        consumer._updater = mock_updater
        consumer._extractor = _mock_feature_extractor()

        await consumer.process_batch([_SAMPLE_EVENT.copy()])
        producer.send_and_wait.assert_not_called()

# ═══════════════════════════════════════════════════════════════════════════
# ClickHouse sync data loading
# ═══════════════════════════════════════════════════════════════════════════

class TestClickHouseSyncLoading:
    """TrainingDataLoader.load_features_sync wires into training pipeline."""

    def test_load_features_sync_with_client(self):
        """Sync loader returns real data when ClickHouse client is present."""
        from ml.training.data_loader import TrainingDataLoader

        mock_ch = MagicMock()
        mock_result = MagicMock()
        mock_result.result_rows = [
            ("agent-1", 100, 20, 5, 3, 500, 200, 4, 3, 8, 6, 3, 50.0, 120.0),
            ("agent-1", 110, 22, 6, 4, 550, 210, 5, 4, 9, 7, 4, 55.0, 130.0),
        ]
        mock_ch.query = MagicMock(return_value=mock_result)

        loader = TrainingDataLoader(clickhouse_client=mock_ch)
        X, names, agents = loader.load_features_sync("tenant-1", lookback_days=30)

        assert X.shape == (2, 13)  # 13 feature columns
        assert len(names) == 13
        assert agents == ["agent-1", "agent-1"]
        mock_ch.query.assert_called_once()

    def test_load_features_sync_no_client(self):
        """Sync loader returns empty when ClickHouse client is None."""
        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader(clickhouse_client=None)
        X, names, agents = loader.load_features_sync("tenant-1")

        assert X.shape == (0, 0)
        assert names == []
        assert agents == []

    def test_load_features_sync_empty_result(self):
        """Empty ClickHouse result returns empty arrays gracefully."""
        from ml.training.data_loader import TrainingDataLoader

        mock_ch = MagicMock()
        mock_result = MagicMock()
        mock_result.result_rows = []
        mock_ch.query = MagicMock(return_value=mock_result)

        loader = TrainingDataLoader(clickhouse_client=mock_ch)
        X, names, agents = loader.load_features_sync("tenant-1")

        assert X.shape == (0, 0)
        assert len(names) == 13  # Feature names still returned
        assert agents == []

    def test_load_features_sync_query_failure(self):
        """ClickHouse query exception returns empty arrays gracefully."""
        from ml.training.data_loader import TrainingDataLoader

        mock_ch = MagicMock()
        mock_ch.query = MagicMock(side_effect=Exception("connection refused"))

        loader = TrainingDataLoader(clickhouse_client=mock_ch)
        X, names, agents = loader.load_features_sync("tenant-1")

        assert X.shape == (0, 0)
        assert len(names) == 13
        assert agents == []

class TestTrainingPipelineCHIntegration:
    """TrainingPipeline.train_all tries ClickHouse before synthetic."""

    def test_train_all_uses_ch_data_when_available(self):
        """When CH returns rows, training uses real data instead of synthetic."""
        from ml.training.trainer import TrainingPipeline

        mock_ch = MagicMock()
        mock_result = MagicMock()
        # Generate 200 rows of fake CH data (enough to pass min_samples)
        rows = []
        for i in range(200):
            rows.append((f"agent-{i % 10}", 100 + i, 20, 5, 3, 500, 200, 4, 3, 8, 6, 3, 50.0, 120.0))
        mock_result.result_rows = rows
        mock_ch.query = MagicMock(return_value=mock_result)

        pipeline = TrainingPipeline(clickhouse_client=mock_ch)
        results = pipeline.train_all(tenant_id="test-tenant")

        # Should have trained on the 200 CH rows (minus sanitization removals)
        assert results["n_samples"] <= 200
        assert results["stage1"]["model"] is not None
        mock_ch.query.assert_called_once()

    def test_train_all_falls_back_to_synthetic(self):
        """When CH is None, training uses synthetic data."""
        from ml.training.trainer import TrainingPipeline

        pipeline = TrainingPipeline(clickhouse_client=None)
        results = pipeline.train_all(tenant_id="test-tenant")

        # Should have trained on 10_000 synthetic samples
        assert results["n_samples"] <= 10_000
        assert results["stage1"]["model"] is not None

    def test_train_all_falls_back_on_empty_ch(self):
        """Empty CH result triggers synthetic fallback."""
        from ml.training.trainer import TrainingPipeline

        mock_ch = MagicMock()
        mock_result = MagicMock()
        mock_result.result_rows = []
        mock_ch.query = MagicMock(return_value=mock_result)

        pipeline = TrainingPipeline(clickhouse_client=mock_ch)
        results = pipeline.train_all(tenant_id="test-tenant")

        assert results["n_samples"] <= 10_000
        assert results["stage1"]["model"] is not None

# ═══════════════════════════════════════════════════════════════════════════
# Full end-to-end: event → scoring → alert → Kafka
# ═══════════════════════════════════════════════════════════════════════════

class TestEndToEndMLPipeline:
    """Full pipeline smoke test: event in → ML alert → Kafka publish."""

    @pytest.mark.asyncio
    async def test_full_event_to_kafka_alert(self):
        """Single event scores above threshold → alert published to Kafka."""
        from ml.main_inference import InferenceConsumer

        # 1. Set up consumer with mocked dependencies
        consumer = InferenceConsumer(
            AsyncMock(),
            MagicMock(),
            bootstrap_servers="localhost:9092",
        )
        producer = AsyncMock()
        consumer._producer = producer

        # 2. Wire pipeline with alerting ensemble
        ensemble = _alerting_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        consumer._pipeline = InferencePipeline(
            extractor,
            loader,
            explainer=EnsembleExplainer(),
        )

        # 3. Process a batch of events
        tenant_id = str(uuid.uuid4())
        events = [
            {
                "tenant_id": tenant_id,
                "agent_id": str(uuid.uuid4()),
                "event_id": str(uuid.uuid4()),
                "event_type": "tool_call",
                "timestamp": "2025-01-01T00:00:00Z",
            }
            for _ in range(5)
        ]

        await consumer.process_batch(events)

        # 4. Verify all 5 alerts were published to Kafka
        assert producer.send_and_wait.call_count == 5

        # 5. Verify topic format
        for call in producer.send_and_wait.call_args_list:
            kwargs = call.kwargs if call.kwargs else {}
            topic = kwargs.get("topic", "")
            assert topic == f"phantex.alerts.{tenant_id}"

            # 6. Verify alert payload contains required fields
            value = kwargs.get("value", {})
            assert "score" in value
            assert "tenant_id" in value
            assert "attack_class" in value
            assert "explanation" in value
            assert value["score"] == 0.85

    @pytest.mark.asyncio
    async def test_mixed_events_only_alerts_published(self):
        """Batch with mixed scores: only above-threshold events get Kafka alerts."""
        from ml.main_inference import InferenceConsumer

        consumer = InferenceConsumer(
            AsyncMock(),
            MagicMock(),
            bootstrap_servers="localhost:9092",
        )
        producer = AsyncMock()
        consumer._producer = producer

        # Pipeline that alternates between alerting and quiet
        extractor = _mock_feature_extractor()
        loader = MagicMock()
        loader.get_shadow_ensemble = MagicMock(return_value=None)
        loader.get_feature_names = MagicMock(return_value=FEATURE_NAMES)

        call_count = {"n": 0}

        def _fused(tenant_id, features, feature_names, **kw):
            call_count["n"] += 1
            if call_count["n"] % 2 == 0:
                return {
                    "score": 0.85,
                    "should_alert": True,
                    "stage_scores": {"if": 0.9},
                    "attack_class": "exfiltration",
                    "probabilities": {},
                    "threshold": 0.7,
                    "stages_active": ["if"],
                }
            return {
                "score": 0.3,
                "should_alert": False,
                "stage_scores": {"if": 0.3},
                "attack_class": "benign",
                "probabilities": {},
                "threshold": 0.7,
                "stages_active": [],
            }

        loader.get_fused_ensemble_result = MagicMock(side_effect=_fused)

        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        consumer._pipeline = InferencePipeline(
            extractor,
            loader,
            explainer=EnsembleExplainer(),
        )

        tenant_id = str(uuid.uuid4())
        events = [
            {
                "tenant_id": tenant_id,
                "agent_id": str(uuid.uuid4()),
                "event_id": str(uuid.uuid4()),
                "event_type": "tool_call",
                "timestamp": "2025-01-01T00:00:00Z",
            }
            for _ in range(6)
        ]

        await consumer.process_batch(events)

        # 3 out of 6 events triggered alerts (even-numbered calls)
        assert producer.send_and_wait.call_count == 3
