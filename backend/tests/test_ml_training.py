# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for ML Training Pipeline — DataLoader, Labeler, Validator, Trainer (J2).
Also tests the ModelRegistry.
"""

import tempfile

import numpy as np
import pytest

from ml.models.isolation_forest import IsolationForestModel
from ml.registry.model_registry import ModelRegistry
from ml.training.labeler import Labeler
from ml.training.validator import ModelValidator

# ── Helpers ──────────────────────────────────────────────────────────────────

FEATURE_NAMES = [f"f{i}" for i in range(10)]

def _make_data(n=200, features=10, seed=42):
    rng = np.random.RandomState(seed)
    return rng.randn(n, features).astype(np.float64)

# ── ModelRegistry Tests ──────────────────────────────────────────────────────

class TestModelRegistry:
    """Tests for the filesystem ModelRegistry."""

    def test_save_and_load(self):
        """Save a model and load it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry = ModelRegistry(base_dir=tmpdir)

            # Create and save a model
            stage1 = IsolationForestModel()
            stage1.fit(_make_data(), FEATURE_NAMES)

            mv = registry.save_model(
                tenant_id="tenant1",
                stage1=stage1,
                feature_names=FEATURE_NAMES,
                metrics={"precision": 0.95},
            )

            assert mv.version.startswith("v")
            assert mv.tenant_id == "tenant1"
            assert len(mv.feature_names) == 10

            # Load latest
            loaded = registry.load_latest("tenant1")
            assert loaded is not None
            assert loaded.version == mv.version

    def test_load_latest_none_for_unknown(self):
        """load_latest returns None for unknown tenant."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry = ModelRegistry(base_dir=tmpdir)
            assert registry.load_latest("nonexistent") is None

    def test_list_versions(self):
        """list_versions returns all saved versions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry = ModelRegistry(base_dir=tmpdir)

            stage1 = IsolationForestModel()
            stage1.fit(_make_data())

            # Save two versions
            import time

            registry.save_model("t1", stage1=stage1)
            time.sleep(1.1)  # Ensure different timestamp
            registry.save_model("t1", stage1=stage1)

            versions = registry.list_versions("t1")
            assert len(versions) == 2

    def test_load_models(self):
        """load_models returns dict of stage → model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            registry = ModelRegistry(base_dir=tmpdir)

            stage1 = IsolationForestModel()
            stage1.fit(_make_data(), FEATURE_NAMES)

            mv = registry.save_model("t1", stage1=stage1, feature_names=FEATURE_NAMES)
            models = registry.load_models(mv)

            assert "stage1" in models
            assert models["stage1"].is_fitted

# ── Labeler Tests ────────────────────────────────────────────────────────────

class TestLabeler:
    """Tests for the semi-supervised Labeler."""

    def test_label_confirmed(self):
        """Confirmed alerts → positive labels."""
        labeler = Labeler()
        X = np.zeros((3, 5))
        alert_labels = [
            {"sample_index": 0, "disposition": "confirmed", "attack_class_index": 1},
            {"sample_index": 1, "disposition": "confirmed", "attack_class_index": 2},
        ]
        y, mask = labeler.create_labels(X, alert_labels)
        assert mask[0] is np.True_
        assert mask[1] is np.True_
        assert y[0] == 1
        assert y[1] == 2

    def test_label_false_positive(self):
        """False positive alerts → negative labels (benign=0)."""
        labeler = Labeler()
        X = np.zeros((2, 5))
        alert_labels = [
            {"sample_index": 0, "disposition": "false_positive"},
        ]
        y, mask = labeler.create_labels(X, alert_labels)
        assert mask[0] is np.True_
        assert y[0] == 0

    def test_label_pending(self):
        """Pending alerts → unlabeled (mask=False)."""
        labeler = Labeler()
        X = np.zeros((2, 5))
        alert_labels = [
            {"sample_index": 0, "disposition": "pending_review"},
            {"sample_index": 1, "disposition": "dismissed"},
        ]
        y, mask = labeler.create_labels(X, alert_labels)
        assert mask[0] is np.False_
        assert mask[1] is np.False_

# ── Validator Tests ──────────────────────────────────────────────────────────

class TestModelValidator:
    """Tests for the ModelValidator."""

    def test_pass_validation(self):
        """Passes when all metrics meet thresholds."""
        validator = ModelValidator()
        result = validator.validate(
            y_true=np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1]),
            y_pred=np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1]),
        )
        assert result.passed is True
        assert result.precision >= 0.90
        assert result.recall >= 0.80

    def test_fail_precision(self):
        """Fails when precision is too low."""
        validator = ModelValidator()
        # Many false positives
        result = validator.validate(
            y_true=np.array([0, 0, 0, 0, 0, 0, 0, 0, 1, 1]),
            y_pred=np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        )
        assert result.passed is False
        assert result.precision < 0.90

    def test_fail_recall(self):
        """Fails when recall is too low."""
        validator = ModelValidator()
        # Many false negatives
        result = validator.validate(
            y_true=np.array([1, 1, 1, 1, 1, 1, 1, 1, 0, 0]),
            y_pred=np.array([0, 0, 0, 0, 0, 0, 0, 1, 0, 0]),
        )
        assert result.passed is False
        assert result.recall < 0.80

    def test_validation_result_fields(self):
        """ValidationResult has all expected fields."""
        validator = ModelValidator()
        result = validator.validate(
            y_true=np.array([0, 1, 0, 1]),
            y_pred=np.array([0, 1, 0, 1]),
        )
        assert hasattr(result, "passed")
        assert hasattr(result, "precision")
        assert hasattr(result, "recall")
        assert hasattr(result, "fpr")

# ── Config Tests ─────────────────────────────────────────────────────────────

class TestMLConfig:
    """Tests for ML configuration."""

    def test_default_config(self):
        """MLConfig creates with safe defaults."""
        from ml.config import get_ml_config

        cfg = get_ml_config()
        assert cfg.baseline.learning_days == 7
        assert cfg.baseline.sigma_threshold == 3.0
        assert cfg.baseline.ema_alpha == 0.1
        assert cfg.ensemble.alert_threshold == 0.7
        assert cfg.training.precision_threshold == 0.90

    def test_feature_windows(self):
        """Standard windows are configured."""
        from ml.config import WINDOWS

        names = [w.name for w in WINDOWS]
        assert "1m" in names
        assert "5m" in names
        assert "1h" in names
        assert "24h" in names

    def test_redis_prefixes(self):
        """Redis key prefixes are configured."""
        from ml.config import REDIS_EVENT_STREAM_PREFIX, REDIS_FEATURE_PREFIX

        assert REDIS_FEATURE_PREFIX.startswith("ml:")
        assert REDIS_EVENT_STREAM_PREFIX.startswith("ml:")

# ── Sprint 3 Audit: Path Traversal Protection ───────────────────────────────

class TestRegistryPathSanitization:
    """Verify path traversal protection in ModelRegistry."""

    def test_traversal_tenant_id_rejected(self):
        """tenant_id with path traversal chars is sanitized."""
        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            # Should not throw, chars are sanitized
            sanitized = registry._sanitize_path_component("../../etc")
            assert ".." not in sanitized
            assert "/" not in sanitized
            assert "\\" not in sanitized

    def test_empty_path_component_rejected(self):
        """Empty string as path component raises ValueError."""
        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            with pytest.raises(ValueError):
                registry._sanitize_path_component("")

    def test_dot_rejected(self):
        """Single dot path component raises ValueError."""
        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            with pytest.raises(ValueError):
                registry._sanitize_path_component(".")

    def test_normal_tenant_id_passes(self):
        """Normal tenant ID passes through sanitization."""
        with tempfile.TemporaryDirectory() as td:
            registry = ModelRegistry(base_dir=td)
            result = registry._sanitize_path_component("tenant-123_abc")
            assert result == "tenant-123_abc"

# ── TrainingDataLoader Tests ─────────────────────────────────────────────────

class TestTrainingDataLoader:
    """Tests for ClickHouse data loader and synthetic generation."""

    def test_load_features_no_client_returns_empty(self):
        """load_features with no ClickHouse client returns empty arrays."""
        import asyncio

        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader(clickhouse_client=None)
        X, features, agents = asyncio.run(loader.load_features("test-tenant", lookback_days=7))
        assert X.shape == (0, 0)
        assert features == []
        assert agents == []

    def test_column_map_completeness(self):
        """Column map has at least 10 entries mapping CH → feature names."""
        from ml.training.data_loader import _CH_COLUMN_MAP, _CH_SELECT_COLUMNS, _FEATURE_NAMES

        assert len(_CH_COLUMN_MAP) >= 10
        assert len(_CH_SELECT_COLUMNS) == len(_CH_COLUMN_MAP)
        assert len(_FEATURE_NAMES) == len(_CH_COLUMN_MAP)

    def test_column_map_keys_match_select(self):
        """SELECT columns are exactly the keys of the column map."""
        from ml.training.data_loader import _CH_COLUMN_MAP, _CH_SELECT_COLUMNS

        assert list(_CH_COLUMN_MAP.keys()) == _CH_SELECT_COLUMNS

    def test_feature_names_match_values(self):
        """Feature name list matches column map values."""
        from ml.training.data_loader import _CH_COLUMN_MAP, _FEATURE_NAMES

        assert list(_CH_COLUMN_MAP.values()) == _FEATURE_NAMES

    def test_generate_synthetic_data_shape(self):
        """Synthetic data generator produces correct shapes."""
        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader()
        X, y, names = loader.generate_synthetic_data(n_samples=500, n_features=20, anomaly_fraction=0.1)
        assert X.shape == (500, 20)
        assert y.shape == (500,)
        assert len(names) == 20

    def test_generate_synthetic_data_labels(self):
        """Synthetic data has correct label distribution."""
        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader()
        X, y, names = loader.generate_synthetic_data(n_samples=1000, n_features=10, anomaly_fraction=0.05)
        n_benign = int((y == 0).sum())
        n_anomaly = int((y > 0).sum())
        assert n_benign == 950
        assert n_anomaly == 50
        # Attack classes should be 1..7
        assert set(y[y > 0].tolist()).issubset({1, 2, 3, 4, 5, 6, 7})

    def test_generate_synthetic_reproducible(self):
        """Synthetic data with same seed produces identical results."""
        from ml.training.data_loader import TrainingDataLoader

        loader = TrainingDataLoader()
        X1, y1, _ = loader.generate_synthetic_data(random_state=99)
        X2, y2, _ = loader.generate_synthetic_data(random_state=99)
        np.testing.assert_array_equal(X1, X2)
        np.testing.assert_array_equal(y1, y2)

    def test_load_features_mock_client(self):
        """load_features with a mock ClickHouse client parses rows correctly."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from ml.training.data_loader import _CH_SELECT_COLUMNS, TrainingDataLoader

        n_cols = len(_CH_SELECT_COLUMNS)
        mock_result = MagicMock()
        mock_result.result_rows = [
            ["agent-1"] + [float(i) for i in range(n_cols)],
            ["agent-2"] + [float(i + 10) for i in range(n_cols)],
        ]

        mock_ch = MagicMock()
        mock_ch.query = AsyncMock(return_value=mock_result)

        loader = TrainingDataLoader(clickhouse_client=mock_ch)
        X, features, agents = asyncio.run(loader.load_features("test-tenant"))
        assert X.shape == (2, n_cols)
        assert agents == ["agent-1", "agent-2"]
        assert len(features) == n_cols

    def test_load_features_nan_guard(self):
        """NaN and Inf values in rows are replaced with 0.0."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from ml.training.data_loader import _CH_SELECT_COLUMNS, TrainingDataLoader

        n_cols = len(_CH_SELECT_COLUMNS)
        row = ["agent-nan"] + [float("nan")] * n_cols
        mock_result = MagicMock()
        mock_result.result_rows = [row]

        mock_ch = MagicMock()
        mock_ch.query = AsyncMock(return_value=mock_result)

        loader = TrainingDataLoader(clickhouse_client=mock_ch)
        X, _, _ = asyncio.run(loader.load_features("tenant-x"))
        assert not np.any(np.isnan(X))
        assert not np.any(np.isinf(X))
