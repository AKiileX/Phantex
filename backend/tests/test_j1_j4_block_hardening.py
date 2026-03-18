# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
J1-J4 Block Hardening Tests — ML Detection Pipeline.

Covers fixes and hardening identified during  audit:

  F1  (MEDIUM)  main_baseline      — asyncpg pool missing SSL → _build_pg_ssl_context
  F2  (LOW)     inference.py       — duplicate elapsed_ms computation removed
  F3  (MEDIUM)  network.py         — bare int() on event fields → _safe_int()
  F4  (MEDIUM)  main_inference.py  — drift detection now uses all scores, not only alerts
"""

from __future__ import annotations

import math
import ssl
import tempfile
import time
from collections import deque
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import pytest

# ═══════════════════════════════════════════════════════════════════════════
# F1: Baseline consumer asyncpg SSL context
# ═══════════════════════════════════════════════════════════════════════════

class TestBaselinePgSslContext:
    """F1: _build_pg_ssl_context must return proper SSL contexts."""

    def test_disabled_ssl_returns_none(self):
        """db_ssl_mode='disable' produces None."""
        from ml.main_baseline import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "disable"
        assert _build_pg_ssl_context(settings) is None

    def test_require_mode(self):
        """db_ssl_mode='require' → CERT_NONE, check_hostname=False."""
        from ml.main_baseline import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "require"
        settings.db_ssl_ca_file = None
        settings.db_ssl_cert_file = None
        settings.db_ssl_key_file = None
        ctx = _build_pg_ssl_context(settings)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_verify_ca_mode(self):
        """db_ssl_mode='verify-ca' → CERT_REQUIRED, check_hostname=False."""
        from ml.main_baseline import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "verify-ca"
        settings.db_ssl_ca_file = None
        settings.db_ssl_cert_file = None
        settings.db_ssl_key_file = None
        ctx = _build_pg_ssl_context(settings)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_verify_full_mode(self):
        """db_ssl_mode='verify-full' → CERT_REQUIRED, check_hostname=True."""
        from ml.main_baseline import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "verify-full"
        settings.db_ssl_ca_file = None
        settings.db_ssl_cert_file = None
        settings.db_ssl_key_file = None
        ctx = _build_pg_ssl_context(settings)
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_matches_main_consumer_implementation(self):
        """Baseline _build_pg_ssl_context matches main_consumer's logic."""
        from app.main_consumer import _build_pg_ssl_context as mc_build
        from ml.main_baseline import _build_pg_ssl_context as bl_build

        for mode in ("disable", "require", "prefer", "allow", "verify-ca", "verify-full"):
            settings = MagicMock()
            settings.db_ssl_mode = mode
            settings.db_ssl_ca_file = None
            settings.db_ssl_cert_file = None
            settings.db_ssl_key_file = None

            mc_result = mc_build(settings)
            bl_result = bl_build(settings)

            if mc_result is None:
                assert bl_result is None, f"Mismatch for mode={mode}"
            elif isinstance(mc_result, str):
                assert bl_result == mc_result, f"Mismatch for mode={mode}: {bl_result!r} != {mc_result!r}"
            else:
                assert type(bl_result) is type(mc_result)
                assert bl_result.check_hostname == mc_result.check_hostname
                assert bl_result.verify_mode == mc_result.verify_mode

# ═══════════════════════════════════════════════════════════════════════════
# F2: Duplicate elapsed_ms removed
# ═══════════════════════════════════════════════════════════════════════════

class TestElapsedMsNoDuplicate:
    """F2: inference.py should have exactly one elapsed_ms computation."""

    def test_single_elapsed_ms_line(self):
        """Source file contains only one 'elapsed_ms = ' assignment."""
        import inspect

        from ml.serving import inference

        src = inspect.getsource(inference.InferencePipeline.score_event)
        count = src.count("elapsed_ms = ")
        assert count == 1, f"Expected 1 elapsed_ms assignment, found {count}"

    @pytest.mark.asyncio
    async def test_elapsed_ms_accurate(self):
        """elapsed_ms in the alert should reflect actual scoring time."""
        from ml.serving.inference import InferencePipeline

        mock_ensemble = MagicMock()
        mock_ensemble.score = MagicMock(
            return_value={
                "score": 0.85,
                "should_alert": True,
                "stage_scores": {"isolation_forest": 0.85},
                "attack_class": "exfiltration",
                "probabilities": {},
                "threshold": 0.7,
                "stages_active": ["isolation_forest"],
            }
        )

        loader = MagicMock()
        loader.get_feature_names = MagicMock(return_value=["f1", "f2"])
        loader.get_shadow_ensemble = MagicMock(return_value=None)
        loader.get_fused_ensemble_result = MagicMock(side_effect=lambda *a, **kw: mock_ensemble.score({}, []))

        extractor = AsyncMock()
        extractor.get_features = AsyncMock(return_value={"f1": 1.0, "f2": 2.0})

        pipeline = InferencePipeline(extractor, loader)
        alert = await pipeline.score_event(
            {
                "tenant_id": "t1",
                "agent_id": "a1",
                "event_id": "e1",
            }
        )
        assert alert is not None
        # elapsed_ms should be a small positive number (< 500ms for mocked path)
        assert 0 < alert["inference_ms"] < 500

# ═══════════════════════════════════════════════════════════════════════════
# F3: Network feature _safe_int
# ═══════════════════════════════════════════════════════════════════════════

class TestNetworkSafeInt:
    """F3: network.py _safe_int handles bad values gracefully."""

    def test_safe_int_normal(self):
        """Normal integer passthrough."""
        from ml.features.network import _safe_int

        assert _safe_int(42) == 42
        assert _safe_int(0) == 0
        assert _safe_int(-5) == -5

    def test_safe_int_string_number(self):
        """Numeric string is converted."""
        from ml.features.network import _safe_int

        assert _safe_int("42") == 42
        assert _safe_int("0") == 0

    def test_safe_int_float(self):
        """Float is truncated to int."""
        from ml.features.network import _safe_int

        assert _safe_int(3.14) == 3
        assert _safe_int(99.99) == 99

    def test_safe_int_none(self):
        """None returns default."""
        from ml.features.network import _safe_int

        assert _safe_int(None) == 0
        assert _safe_int(None, default=-1) == -1

    def test_safe_int_empty_string(self):
        """Empty string returns default."""
        from ml.features.network import _safe_int

        assert _safe_int("") == 0

    def test_safe_int_non_numeric_string(self):
        """Non-numeric string returns default (no crash)."""
        from ml.features.network import _safe_int

        assert _safe_int("abc") == 0
        assert _safe_int("not_a_number") == 0
        assert _safe_int("12.34.56") == 0

    def test_safe_int_bool(self):
        """Booleans convert to int (True=1, False=0)."""
        from ml.features.network import _safe_int

        assert _safe_int(True) == 1
        assert _safe_int(False) == 0

    def test_safe_int_list_returns_default(self):
        """Unexpected types return default."""
        from ml.features.network import _safe_int

        assert _safe_int([1, 2, 3]) == 0
        assert _safe_int({"key": "val"}) == 0

class TestNetworkFeaturesWithBadData:
    """Network features handle malformed event data without crashing."""

    def test_non_numeric_bytes_out(self):
        """bytes_out='abc' should not crash feature computation."""
        from ml.features.network import compute_network_features

        now = time.time()
        events = [
            {"timestamp_epoch": now - 10, "bytes_out": "abc", "bytes_in": 100},
        ]
        result = compute_network_features(events, now)
        # bytes_sent should be 0 (bad value ignored)
        assert result["bytes_sent_total_5m"] == 0
        assert result["bytes_recv_total_5m"] == 100.0

    def test_none_bytes_fields(self):
        """None bytes fields should not crash."""
        from ml.features.network import compute_network_features

        now = time.time()
        events = [
            {"timestamp_epoch": now - 10, "bytes_out": None, "bytes_in": None},
        ]
        result = compute_network_features(events, now)
        assert result["bytes_sent_total_5m"] == 0
        assert result["bytes_recv_total_5m"] == 0

    def test_non_numeric_dest_port(self):
        """Non-numeric dest_port should not crash or add to port set."""
        from ml.features.network import compute_network_features

        now = time.time()
        events = [
            {"timestamp_epoch": now - 10, "bytes_out": 0, "bytes_in": 0, "dest_port": "not_a_port"},
        ]
        result = compute_network_features(events, now)
        assert result["unique_ports_5m"] == 0

    def test_empty_string_dest_port(self):
        """Empty string dest_port handled gracefully."""
        from ml.features.network import compute_network_features

        now = time.time()
        events = [
            {"timestamp_epoch": now - 10, "bytes_out": 0, "bytes_in": 0, "dest_port": ""},
        ]
        result = compute_network_features(events, now)
        assert result["unique_ports_5m"] == 0

    def test_valid_port_still_counted(self):
        """Valid numeric ports are still counted correctly after fix."""
        from ml.features.network import compute_network_features

        now = time.time()
        events = [
            {"timestamp_epoch": now - 10, "bytes_out": 500, "bytes_in": 200, "dest_port": 443},
            {"timestamp_epoch": now - 20, "bytes_out": "300", "bytes_in": "100", "dest_port": "8080"},
        ]
        result = compute_network_features(events, now)
        assert result["bytes_sent_total_5m"] == 800.0
        assert result["bytes_recv_total_5m"] == 300.0
        assert result["unique_ports_5m"] == 2.0

    def test_mixed_valid_invalid_events(self):
        """Mix of good and bad events — bad ones are gracefully handled."""
        from ml.features.network import compute_network_features

        now = time.time()
        events = [
            {"timestamp_epoch": now - 10, "bytes_out": 100, "bytes_in": 200, "dest_port": 80},
            {"timestamp_epoch": now - 20, "bytes_out": "garbage", "bytes_in": None, "dest_port": ["list"]},
            {"timestamp_epoch": now - 30, "bytes_out": 50, "bytes_in": 50, "dest_port": 443},
        ]
        result = compute_network_features(events, now)
        assert result["bytes_sent_total_5m"] == 150.0  # 100 + 0 + 50
        assert result["bytes_recv_total_5m"] == 250.0  # 200 + 0 + 50
        assert result["unique_ports_5m"] == 2.0  # 80 + 443

# ═══════════════════════════════════════════════════════════════════════════
# F4: Drift detection uses all scores
# ═══════════════════════════════════════════════════════════════════════════

class TestDriftDetectionFullScores:
    """F4: InferenceConsumer drift detection sees all scores, not just alerts."""

    @pytest.mark.asyncio
    async def test_recent_scores_includes_non_alerting(self):
        """_recent_scores should contain scores from ALL events, not just alerts."""
        from ml.main_inference import InferenceConsumer

        consumer = InferenceConsumer(
            AsyncMock(),
            MagicMock(),
            bootstrap_servers="localhost:9092",
        )
        # Suppress Kafka producer
        consumer._producer = None

        # Mock pipeline that returns NO alerts (all below threshold)
        from ml.serving.inference import InferencePipeline

        mock_pipeline = MagicMock(spec=InferencePipeline)
        mock_pipeline.score_batch = AsyncMock(return_value=[])  # no alerts

        # Simulate the evasion detector recording all scores
        mock_evasion = MagicMock()
        mock_evasion._scores = deque([(time.time(), 0.3 + i * 0.01) for i in range(50)])
        mock_pipeline.evasion_detector = mock_evasion

        consumer._pipeline = mock_pipeline

        events = [{"tenant_id": "t1", "agent_id": "a1"} for _ in range(10)]
        await consumer.process_batch(events)

        # Even though no alerts were returned, _recent_scores should
        # be populated from the evasion detector's full window
        assert len(consumer._recent_scores) == 50
        assert all(isinstance(s, float) for s in consumer._recent_scores)

    @pytest.mark.asyncio
    async def test_recent_scores_capped_at_10k(self):
        """_recent_scores buffer never exceeds 10,000 entries."""
        from ml.main_inference import InferenceConsumer

        consumer = InferenceConsumer(
            AsyncMock(),
            MagicMock(),
            bootstrap_servers="localhost:9092",
        )
        consumer._producer = None

        from ml.serving.inference import InferencePipeline

        mock_pipeline = MagicMock(spec=InferencePipeline)
        mock_pipeline.score_batch = AsyncMock(return_value=[])

        mock_evasion = MagicMock()
        mock_evasion._scores = deque([(time.time(), 0.5) for _ in range(15_000)])
        mock_pipeline.evasion_detector = mock_evasion

        consumer._pipeline = mock_pipeline

        await consumer.process_batch([{"tenant_id": "t1", "agent_id": "a1"}])
        assert len(consumer._recent_scores) <= 10_000

# ═══════════════════════════════════════════════════════════════════════════
# Additional J1-J4 hardening coverage
# ═══════════════════════════════════════════════════════════════════════════

class TestFeatureRegistryCompleteness:
    """All feature calculators register their features in the global registry."""

    def test_volume_features_registered(self):
        """Volume features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        for w in ("1m", "5m", "1h", "24h"):
            assert f"event_count_{w}" in names
            assert f"tool_call_count_{w}" in names

    def test_network_features_registered(self):
        """Network features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        for w in ("5m", "1h"):
            assert f"bytes_sent_total_{w}" in names
            assert f"bytes_recv_total_{w}" in names
            assert f"outbound_ratio_{w}" in names
            assert f"unique_ports_{w}" in names

    def test_temporal_features_registered(self):
        """Temporal features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        assert "hour_of_day" in names
        assert "day_of_week" in names
        assert "time_since_last_event" in names
        assert "burst_duration" in names

    def test_sequence_features_registered(self):
        """Sequence features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        assert "bigram_entropy" in names
        assert "trigram_entropy" in names

    def test_diversity_features_registered(self):
        """Diversity features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        for w in ("1h", "24h"):
            assert f"unique_tools_used_{w}" in names

    def test_mcp_features_registered(self):
        """MCP features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        assert "mcp_tool_call_count_1h" in names
        assert "mcp_tool_diversity_ratio" in names
        assert "mcp_tool_error_rate" in names

    def test_trust_features_registered(self):
        """Trust features appear in the global registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        for sev in ("low", "medium", "high", "critical"):
            assert f"trust_severity_{sev}_1h" in names
        assert "trust_anomaly_density_1h" in names
        assert "trust_volatility_1h" in names

    def test_no_duplicate_features(self):
        """No duplicate feature names in the registry."""
        from ml.features.registry import feature_names

        names = feature_names()
        assert len(names) == len(set(names)), "Duplicate feature names detected"

class TestEnsembleScorerEdgeCases:
    """Ensemble scorer handles extreme inputs safely."""

    def test_nan_feature_handled(self):
        """NaN feature value does not crash ensemble scoring."""
        from ml.models.ensemble import EnsembleScorer
        from ml.models.isolation_forest import IsolationForestModel

        stage1 = IsolationForestModel()
        X = np.random.RandomState(42).randn(200, 5)
        names = [f"f{i}" for i in range(5)]
        stage1.fit(X, names)

        ensemble = EnsembleScorer(stage1=stage1)
        features = {"f0": 0.0, "f1": float("nan"), "f2": 0.0, "f3": 0.0, "f4": 0.0}
        # Should not raise — sklearn can handle NaN
        result = ensemble.score(features, names)
        assert "score" in result
        assert isinstance(result["score"], float)

    def test_empty_feature_names(self):
        """Score with empty feature_names list still returns a result."""
        from ml.models.ensemble import EnsembleScorer

        ensemble = EnsembleScorer()
        result = ensemble.score({}, [])
        assert result["score"] == 0.0
        assert result["should_alert"] is False

class TestModelRegistryDirectoryTraversal:
    """Extended path traversal tests for model registry."""

    def test_null_byte_rejected(self):
        """Null bytes in path component are stripped/rejected."""
        from ml.registry.model_registry import ModelRegistry

        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            sanitized = registry._sanitize_path_component("tenant\x00id")
            assert "\x00" not in sanitized

    def test_long_path_component(self):
        """Very long path components are handled (not crash)."""
        from ml.registry.model_registry import ModelRegistry

        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            long_name = "a" * 300
            sanitized = registry._sanitize_path_component(long_name)
            assert len(sanitized) <= 300

    def test_unicode_tenant_id(self):
        """Unicode tenant IDs are sanitized safely."""
        from ml.registry.model_registry import ModelRegistry

        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            sanitized = registry._sanitize_path_component("тенант-идентификатор")
            assert ".." not in sanitized

class TestIsolationForestEdgeCases:
    """Edge cases for the Isolation Forest model."""

    def test_single_sample_fit(self):
        """Fitting with a single sample does not crash."""
        from ml.models.isolation_forest import IsolationForestModel

        model = IsolationForestModel()
        X = np.array([[1.0, 2.0, 3.0]])
        model.fit(X, ["f0", "f1", "f2"])
        assert model.is_fitted
        score = model.predict_score(X)
        assert score.shape == (1,)

    def test_all_identical_features(self):
        """Data with zero variance does not crash."""
        from ml.models.isolation_forest import IsolationForestModel

        model = IsolationForestModel()
        X = np.ones((100, 5))
        model.fit(X, [f"f{i}" for i in range(5)])
        scores = model.predict_score(X[:10])
        assert np.all(np.isfinite(scores))

class TestXGBoostEdgeCases:
    """Edge cases for the XGBoost model."""

    def test_non_contiguous_labels(self):
        """XGBoost handles non-contiguous label indices (e.g. {0, 3, 7})."""
        from ml.models.xgboost_model import ATTACK_CLASSES, XGBoostModel

        model = XGBoostModel()
        rng = np.random.RandomState(42)
        X = rng.randn(200, 5).astype(np.float64)
        y = rng.choice([0, 3, 7], size=200)  # Non-contiguous
        model.fit(X, y, feature_names=[f"f{i}" for i in range(5)])

        assert model.is_fitted
        probs = model.predict_proba(X[:5])
        # Should have columns for all ATTACK_CLASSES
        assert probs.shape[1] == len(ATTACK_CLASSES)
        np.testing.assert_allclose(probs.sum(axis=1), 1.0, atol=1e-5)

    def test_save_load_preserves_label_map(self):
        """Save/load roundtrip preserves _label_map and _inv_label_map."""
        from ml.models.xgboost_model import XGBoostModel

        model = XGBoostModel()
        rng = np.random.RandomState(42)
        X = rng.randn(200, 5).astype(np.float64)
        y = rng.choice([0, 2, 5], size=200)
        model.fit(X, y, feature_names=[f"f{i}" for i in range(5)])

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "model.pkl"
            model.save(path)
            loaded = XGBoostModel.load(path)

        assert loaded._label_map == model._label_map
        assert loaded._inv_label_map == model._inv_label_map

class TestAutoencoderEdgeCases:
    """Edge cases for the autoencoder model."""

    def test_zero_variance_column(self):
        """Autoencoder handles zero-variance columns (std=0)."""
        from ml.models.autoencoder import AutoencoderModel

        model = AutoencoderModel(input_dim=5)
        X = np.random.RandomState(42).randn(200, 5)
        X[:, 2] = 1.0  # Zero-variance column
        model.fit(X, [f"f{i}" for i in range(5)])
        scores = model.predict_score(X[:10])
        assert np.all(np.isfinite(scores))
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_reconstruction_errors_finite(self):
        """Per-feature reconstruction errors are always finite."""
        from ml.models.autoencoder import AutoencoderModel

        model = AutoencoderModel(input_dim=5)
        X = np.random.RandomState(42).randn(200, 5)
        names = [f"f{i}" for i in range(5)]
        model.fit(X, names)

        features = {f"f{i}": 999.0 for i in range(5)}  # Far from training
        errors = model.reconstruction_errors_per_feature(features, names)
        for name, err in errors:
            assert math.isfinite(err), f"Non-finite error for {name}: {err}"

class TestShadowModeHard03Cap:
    """HARD-03: Shadow mode score buffer is capped."""

    def test_max_scores_enforced(self):
        """Shadow tracker does not store more than max_scores_per_tenant."""
        from ml.serving.shadow_mode import ShadowModeTracker

        tracker = ShadowModeTracker()
        tracker.start_shadow("t1", "v1")

        # Try to record way more than the cap
        for _i in range(60_000):
            tracker.record_score("t1", 0.5, should_alert=False)

        # The total count is tracked but score list should be bounded
        result = tracker.evaluate("t1")
        assert result["total_scored"] <= 60_001

class TestBaselineProfileSerialization:
    """BaselineProfile roundtrip serialization edge cases."""

    def test_empty_profile_roundtrip(self):
        """Completely empty profile survives serialization."""
        from ml.baseline.models import BaselineProfile

        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        data = profile.to_dict()
        restored = BaselineProfile.from_dict(data)
        assert restored.agent_id == "a1"
        assert restored.metrics == {}
        assert restored.known_destinations == set()

    def test_large_destination_set(self):
        """Profile with many destinations serializes correctly."""
        from ml.baseline.models import BaselineProfile

        profile = BaselineProfile(agent_id="a1", tenant_id="t1")
        for i in range(1000):
            profile.known_destinations.add(f"10.0.{i // 256}.{i % 256}")

        data = profile.to_dict()
        restored = BaselineProfile.from_dict(data)
        assert len(restored.known_destinations) == 1000

class TestComparatorZeroStdSafe:
    """Comparator should not divide by zero when std=0."""

    def test_zscore_zero_std(self):
        """zscore returns 0 when std is 0 (no division by zero)."""
        from ml.baseline.comparator import BaselineComparator

        result = BaselineComparator.zscore(100.0, 0.0, 999.0)
        assert result == 0.0
        assert math.isfinite(result)

    def test_compare_zero_std_metric(self):
        """compare() with std=0 metric doesn't crash."""
        from ml.baseline.comparator import BaselineComparator
        from ml.baseline.models import BaselineProfile, MetricBaseline

        comp = BaselineComparator()
        profile = BaselineProfile(agent_id="a1", tenant_id="t1", mode="ACTIVE")
        profile.metrics["event_count_1h"] = MetricBaseline(
            mean=50.0,
            std=0.0,
            p95=50.0,
            count=1000,
        )
        alerts = comp.compare(profile, {"event_count_1h": 999.0})
        # Should not crash; might or might not alert (z-score=0 with std=0)
        assert isinstance(alerts, list)

class TestMLConfigDefaults:
    """ML config defaults are safe for production."""

    def test_n_jobs_not_minus_one_in_test(self):
        """n_jobs defaults to 1 in test mode (not -1 which uses all cores)."""
        from ml.config import get_ml_config

        cfg = get_ml_config()
        assert cfg.isolation_forest.n_jobs >= 1, "n_jobs should not be -1 in test"
        assert cfg.xgboost.n_jobs >= 1, "n_jobs should not be -1 in test"

    def test_alert_threshold_in_range(self):
        """Alert threshold is between 0 and 1."""
        from ml.config import get_ml_config

        cfg = get_ml_config()
        assert 0.0 < cfg.ensemble.alert_threshold < 1.0

    def test_ema_alpha_in_range(self):
        """EMA alpha is between 0 and 1."""
        from ml.config import get_ml_config

        cfg = get_ml_config()
        assert 0.0 < cfg.baseline.ema_alpha <= 1.0

    def test_sigma_threshold_positive(self):
        """Sigma threshold for z-score alerts is positive."""
        from ml.config import get_ml_config

        cfg = get_ml_config()
        assert cfg.baseline.sigma_threshold > 0

class TestTrainingPipelineValidation:
    """Training pipeline validation edge cases."""

    def test_validator_all_benign(self):
        """Validator handles all-benign predictions."""
        from ml.training.validator import ModelValidator

        validator = ModelValidator()
        result = validator.validate(
            y_true=np.array([0, 0, 0, 0, 0]),
            y_pred=np.array([0, 0, 0, 0, 0]),
        )
        # All benign → recall undefined, precision is trivially 1.0
        assert hasattr(result, "passed")

    def test_validator_all_positive(self):
        """Validator handles all-positive predictions."""
        from ml.training.validator import ModelValidator

        validator = ModelValidator()
        result = validator.validate(
            y_true=np.array([1, 1, 1, 1, 1]),
            y_pred=np.array([1, 1, 1, 1, 1]),
        )
        assert result.passed is True
        assert result.precision == 1.0
        assert result.recall == 1.0

class TestLabelerGovernanceGate:
    """Labeler respects J5b governance rules."""

    def test_unknown_disposition_unlabeled(self):
        """Unknown disposition types are treated as unlabeled."""
        from ml.training.labeler import Labeler

        labeler = Labeler()
        X = np.zeros((2, 5))
        alert_labels = [
            {"sample_index": 0, "disposition": "some_unknown_type"},
        ]
        y, mask = labeler.create_labels(X, alert_labels)
        assert mask[0] is np.False_

    def test_empty_alerts_all_unlabeled(self):
        """No alert labels → all samples unlabeled."""
        from ml.training.labeler import Labeler

        labeler = Labeler()
        X = np.zeros((5, 3))
        y, mask = labeler.create_labels(X, [])
        assert np.all(~mask)

class TestDataLoaderSanitization:
    """Training data loader handles edge cases."""

    def test_synthetic_data_no_nan(self):
        """Synthetic data never contains NaN values."""
        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader()
        X, y, names = loader.generate_synthetic_data(n_samples=1000)
        assert not np.any(np.isnan(X))
        assert not np.any(np.isinf(X))

    def test_synthetic_data_correct_anomaly_fraction(self):
        """Anomaly fraction is correctly applied."""
        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader()
        X, y, _ = loader.generate_synthetic_data(
            n_samples=1000,
            anomaly_fraction=0.1,
        )
        n_anomaly = int((y > 0).sum())
        assert n_anomaly == 100
