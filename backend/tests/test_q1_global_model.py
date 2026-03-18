# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q1 Tests: Global Starter Model.

Tests for:
  - GlobalSyntheticGenerator: data shapes, feature names, class distribution
  - GlobalModelTrainer: full training pipeline, model quality
  - GlobalModelManager: loading, caching, thread safety
  - EnsembleFusion: weight computation, blending, edge cases
  - ModelLoader Q1 integration: fallback, fused scoring
"""

from __future__ import annotations

import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pytest

# Ensure backend/ is on sys.path
_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from ml.config import (
    EnsembleFusionConfig,
    get_ml_config,
)
from ml.global_model.fusion import EnsembleFusion, FusionWeights
from ml.global_model.manager import GlobalModelManager
from ml.global_model.synthetic_generator import (
    GLOBAL_FEATURE_NAMES,
    GlobalSyntheticGenerator,
)
from ml.models.ensemble import EnsembleScorer
from ml.registry.model_registry import ModelRegistry

# ═══════════════════════════════════════════════════════════════════════
# Q1-SYNTH: Synthetic Data Generator Tests
# ═══════════════════════════════════════════════════════════════════════

class TestGlobalSyntheticGenerator:
    """Test the synthetic behavioral data generator."""

    def test_generate_default_params(self):
        """Generator produces correct shape with default parameters."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, y, names = gen.generate(n_samples=1000, anomaly_fraction=0.1)
        assert X.shape == (1000, 62)
        assert y.shape == (1000,)
        assert len(names) == 62

    def test_generate_custom_params(self):
        """Generator respects custom sample count and anomaly fraction."""
        gen = GlobalSyntheticGenerator(random_state=99)
        X, y, names = gen.generate(n_samples=1000, anomaly_fraction=0.1)
        assert X.shape == (1000, 62)
        assert y.shape == (1000,)
        n_anomaly = (y > 0).sum()
        assert n_anomaly == 100  # 10% of 1000

    def test_feature_names_match(self):
        """Generated feature names match GLOBAL_FEATURE_NAMES constant."""
        gen = GlobalSyntheticGenerator(random_state=42)
        _, _, names = gen.generate(n_samples=100, anomaly_fraction=0.1)
        assert names == GLOBAL_FEATURE_NAMES

    def test_all_classes_represented(self):
        """All 8 classes (0-7) are present in generated data."""
        gen = GlobalSyntheticGenerator(random_state=42)
        _, y, _ = gen.generate(n_samples=2000, anomaly_fraction=0.15)
        classes = set(y)
        assert classes == {0, 1, 2, 3, 4, 5, 6, 7}

    def test_benign_majority(self):
        """Benign class is the majority (1 - anomaly_fraction)."""
        gen = GlobalSyntheticGenerator(random_state=42)
        _, y, _ = gen.generate(n_samples=2000, anomaly_fraction=0.08)
        benign_count = (y == 0).sum()
        assert benign_count == 1840  # 92% of 2000

    def test_no_negative_values(self):
        """All feature values are non-negative (behavioral features)."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, _, _ = gen.generate(n_samples=1000, anomaly_fraction=0.1)
        assert np.all(X >= 0), "Features must be non-negative"

    def test_no_nan_or_inf(self):
        """No NaN or Inf values in generated data."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, y, _ = gen.generate(n_samples=1000, anomaly_fraction=0.1)
        assert not np.any(np.isnan(X))
        assert not np.any(np.isinf(X))
        assert not np.any(np.isnan(y))

    def test_reproducibility(self):
        """Same seed produces identical data."""
        gen1 = GlobalSyntheticGenerator(random_state=42)
        gen2 = GlobalSyntheticGenerator(random_state=42)
        X1, y1, _ = gen1.generate(n_samples=1000, anomaly_fraction=0.1)
        X2, y2, _ = gen2.generate(n_samples=1000, anomaly_fraction=0.1)
        np.testing.assert_array_equal(X1, X2)
        np.testing.assert_array_equal(y1, y2)

    def test_different_seeds_differ(self):
        """Different seeds produce different data."""
        gen1 = GlobalSyntheticGenerator(random_state=42)
        gen2 = GlobalSyntheticGenerator(random_state=99)
        X1, _, _ = gen1.generate(n_samples=1000, anomaly_fraction=0.1)
        X2, _, _ = gen2.generate(n_samples=1000, anomaly_fraction=0.1)
        assert not np.array_equal(X1, X2)

    def test_data_fingerprint(self):
        """Fingerprint is deterministic and changes with different data."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, y, _ = gen.generate(n_samples=1000, anomaly_fraction=0.1)
        fp1 = gen.data_fingerprint(X, y)
        fp2 = gen.data_fingerprint(X, y)
        assert fp1 == fp2  # Same data → same fingerprint
        assert len(fp1) == 64  # SHA-256 hex digest

        # Different data → different fingerprint
        gen2 = GlobalSyntheticGenerator(random_state=99)
        X2, y2, _ = gen2.generate(n_samples=1000, anomaly_fraction=0.1)
        fp3 = gen2.data_fingerprint(X2, y2)
        assert fp3 != fp1

    def test_invalid_feature_count_raises(self):
        """Requesting non-62 features raises ValueError."""
        gen = GlobalSyntheticGenerator(random_state=42)
        with pytest.raises(ValueError, match="62 features"):
            gen.generate(n_samples=100, anomaly_fraction=0.1, n_features=30)

    def test_class_balance_even_distribution(self):
        """Attack classes 1-7 have roughly equal representation."""
        gen = GlobalSyntheticGenerator(random_state=42)
        _, y, _ = gen.generate(n_samples=7000, anomaly_fraction=0.1)
        for cls in range(1, 8):
            count = (y == cls).sum()
            # Each class should get ~1/7 of 10% of 7000 = ~100
            assert 90 <= count <= 110, f"Class {cls} has {count} samples"

    def test_feature_62_names(self):
        """The GLOBAL_FEATURE_NAMES list has exactly 62 entries."""
        assert len(GLOBAL_FEATURE_NAMES) == 62

    def test_attack_profiles_differ(self):
        """Different attack classes produce different feature distributions."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, y, _ = gen.generate(n_samples=2000, anomaly_fraction=0.5)

        # Compare class 0 (benign) with class 3 (DoS)
        benign_mean = X[y == 0].mean(axis=0)
        dos_mean = X[y == 3].mean(axis=0)
        # They should differ significantly
        diff = np.abs(benign_mean - dos_mean).max()
        assert diff > 1.0, "Benign and DoS profiles should differ significantly"

    def test_time_window_decay(self):
        """Longer time windows have larger average values than shorter ones."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, y, names = gen.generate(n_samples=2000, anomaly_fraction=0.05)
        # event_count_1m (idx 0) < event_count_24h (idx 3)
        benign = X[y == 0]
        assert benign[:, 0].mean() < benign[:, 3].mean(), "1m window should have smaller values than 24h"

    def test_zero_anomaly_fraction(self):
        """Zero anomaly fraction produces only benign samples."""
        gen = GlobalSyntheticGenerator(random_state=42)
        X, y, _ = gen.generate(n_samples=1000, anomaly_fraction=0.0)
        assert np.all(y == 0)
        assert X.shape == (1000, 62)

# ═══════════════════════════════════════════════════════════════════════
# Q1-FUSION: Ensemble Fusion Tests
# ═══════════════════════════════════════════════════════════════════════

class TestEnsembleFusion:
    """Test adaptive weight computation and score blending."""

    def setup_method(self):
        self.fusion = EnsembleFusion()

    def test_no_tenant_model_pure_global(self):
        """No tenant samples → 100% global weight."""
        w = self.fusion.compute_weights(tenant_samples=0)
        assert w.global_weight == 1.0
        assert w.tenant_weight == 0.0
        assert w.reason == "no_tenant_model"

    def test_negative_samples_treated_as_zero(self):
        """Negative sample count treated as no tenant model."""
        w = self.fusion.compute_weights(tenant_samples=-5)
        assert w.global_weight == 1.0
        assert w.tenant_weight == 0.0

    def test_low_precision_pure_global(self):
        """Tenant model with low precision → 100% global."""
        w = self.fusion.compute_weights(
            tenant_samples=5000,
            tenant_precision=0.5,
        )
        assert w.global_weight == 1.0
        assert w.tenant_weight == 0.0
        assert w.reason == "tenant_precision_below_threshold"

    def test_crossover_roughly_balanced(self):
        """At crossover_samples, weights should be roughly balanced."""
        cfg = get_ml_config().ensemble_fusion
        w = self.fusion.compute_weights(
            tenant_samples=cfg.crossover_samples,
            tenant_precision=0.9,
        )
        # At crossover: sigmoid(0) = 0.5, so tenant_weight ≈ 0.5 * (1 - min_global)
        expected_tenant = 0.5 * (1.0 - cfg.min_global_weight)
        assert abs(w.tenant_weight - expected_tenant) < 0.01

    def test_large_samples_approaches_max_tenant(self):
        """Very large sample count → tenant weight approaches max."""
        cfg = get_ml_config().ensemble_fusion
        w = self.fusion.compute_weights(
            tenant_samples=100_000,
            tenant_precision=0.95,
        )
        max_tenant = 1.0 - cfg.min_global_weight
        assert w.tenant_weight > max_tenant * 0.95
        assert w.global_weight >= cfg.min_global_weight

    def test_weights_sum_to_one(self):
        """Global + tenant weights always sum to 1.0."""
        for samples in [0, 100, 1000, 5000, 10000, 50000]:
            w = self.fusion.compute_weights(
                tenant_samples=samples,
                tenant_precision=0.9,
            )
            assert abs(w.global_weight + w.tenant_weight - 1.0) < 1e-10

    def test_global_never_below_min(self):
        """Global weight never drops below min_global_weight."""
        cfg = get_ml_config().ensemble_fusion
        for samples in [50000, 100000, 1000000]:
            w = self.fusion.compute_weights(
                tenant_samples=samples,
                tenant_precision=0.99,
            )
            assert w.global_weight >= cfg.min_global_weight - 1e-10

    def test_fusion_weights_to_dict(self):
        """FusionWeights.to_dict() returns expected structure."""
        w = FusionWeights(
            global_weight=0.6,
            tenant_weight=0.4,
            tenant_samples=2500,
            reason="sigmoid_transition",
        )
        d = w.to_dict()
        assert d["global_weight"] == 0.6
        assert d["tenant_weight"] == 0.4
        assert d["tenant_samples"] == 2500
        assert d["reason"] == "sigmoid_transition"

    def test_monotonic_decrease_global_weight(self):
        """Global weight monotonically decreases as samples increase."""
        prev_w = 1.0
        for samples in range(0, 20001, 500):
            w = self.fusion.compute_weights(
                tenant_samples=samples,
                tenant_precision=0.9,
            )
            assert w.global_weight <= prev_w + 1e-10
            prev_w = w.global_weight

    def test_score_global_only(self):
        """Scoring with only global model returns global scores."""
        mock_global = MagicMock(spec=EnsembleScorer)
        mock_global.score.return_value = {
            "score": 0.8,
            "should_alert": True,
            "stage_scores": {"isolation_forest": 0.8},
            "attack_class": "dos",
            "probabilities": {"dos": 0.8, "benign": 0.2},
            "threshold": 0.7,
            "stages_active": ["isolation_forest"],
        }

        result = self.fusion.score(
            global_ensemble=mock_global,
            tenant_ensemble=None,
            features={"f1": 1.0},
            feature_names=["f1"],
            tenant_samples=0,
        )
        assert result["score"] == 0.8
        assert result["attack_class"] == "dos"
        assert result["fusion_weights"]["global_weight"] == 1.0

    def test_score_fused(self):
        """Scoring with both models produces blended score."""
        mock_global = MagicMock(spec=EnsembleScorer)
        mock_global.score.return_value = {
            "score": 0.6,
            "should_alert": False,
            "stage_scores": {"isolation_forest": 0.6},
            "attack_class": "benign",
            "probabilities": {"benign": 0.6},
            "threshold": 0.7,
            "stages_active": ["isolation_forest"],
        }

        mock_tenant = MagicMock(spec=EnsembleScorer)
        mock_tenant.score.return_value = {
            "score": 0.9,
            "should_alert": True,
            "stage_scores": {"isolation_forest": 0.9},
            "attack_class": "data_exfiltration",
            "probabilities": {"data_exfiltration": 0.9},
            "threshold": 0.7,
            "stages_active": ["isolation_forest"],
        }

        result = self.fusion.score(
            global_ensemble=mock_global,
            tenant_ensemble=mock_tenant,
            features={"f1": 1.0},
            feature_names=["f1"],
            tenant_samples=5000,
            tenant_precision=0.9,
        )

        # Fused score should be between 0.6 and 0.9
        assert 0.6 <= result["score"] <= 0.9
        # Tenant model has higher score → use tenant's attack class
        assert result["attack_class"] == "data_exfiltration"
        assert result["fusion_weights"]["tenant_weight"] > 0

    def test_score_tenant_error_fallback(self):
        """If tenant scoring fails, falls back to global-only."""
        mock_global = MagicMock(spec=EnsembleScorer)
        mock_global.score.return_value = {
            "score": 0.8,
            "should_alert": True,
            "stage_scores": {"isolation_forest": 0.8},
            "attack_class": "dos",
            "probabilities": {"dos": 0.8},
            "threshold": 0.7,
            "stages_active": ["isolation_forest"],
        }

        mock_tenant = MagicMock(spec=EnsembleScorer)
        mock_tenant.score.side_effect = RuntimeError("model corrupt")

        result = self.fusion.score(
            global_ensemble=mock_global,
            tenant_ensemble=mock_tenant,
            features={"f1": 1.0},
            feature_names=["f1"],
            tenant_samples=5000,
            tenant_precision=0.9,
        )

        assert result["score"] == 0.8
        assert result["fusion_weights"]["reason"] == "tenant_scoring_error"

    def test_score_clamped(self):
        """Fused score is clamped to [0, 1]."""
        mock_global = MagicMock(spec=EnsembleScorer)
        mock_global.score.return_value = {
            "score": 1.0,
            "should_alert": True,
            "stage_scores": {},
            "attack_class": "dos",
            "probabilities": {},
            "threshold": 0.7,
            "stages_active": [],
        }
        mock_tenant = MagicMock(spec=EnsembleScorer)
        mock_tenant.score.return_value = {
            "score": 1.0,
            "should_alert": True,
            "stage_scores": {},
            "attack_class": "dos",
            "probabilities": {},
            "threshold": 0.7,
            "stages_active": [],
        }

        result = self.fusion.score(
            global_ensemble=mock_global,
            tenant_ensemble=mock_tenant,
            features={"f1": 1.0},
            feature_names=["f1"],
            tenant_samples=5000,
            tenant_precision=0.9,
        )
        assert 0.0 <= result["score"] <= 1.0

    def test_merge_stage_scores(self):
        """Stage scores are properly merged with weights."""
        weights = FusionWeights(0.4, 0.6, 5000, "sigmoid_transition")
        merged = EnsembleFusion._merge_stage_scores(
            {"isolation_forest": 0.5, "xgboost": 0.6},
            {"isolation_forest": 0.8, "xgboost": 0.9},
            weights,
        )
        expected_if = 0.4 * 0.5 + 0.6 * 0.8
        expected_xgb = 0.4 * 0.6 + 0.6 * 0.9
        assert abs(merged["isolation_forest"] - expected_if) < 1e-10
        assert abs(merged["xgboost"] - expected_xgb) < 1e-10

    def test_custom_config(self):
        """EnsembleFusion accepts custom config."""
        cfg = EnsembleFusionConfig(
            initial_global_weight=0.8,
            min_global_weight=0.3,
            crossover_samples=1000,
            decay_rate=0.002,
            min_tenant_precision=0.5,
        )
        fusion = EnsembleFusion(config=cfg)
        w = fusion.compute_weights(tenant_samples=1000, tenant_precision=0.9)
        # At crossover, should be roughly balanced
        max_tenant = 1.0 - 0.3  # 0.7
        expected = 0.5 * max_tenant  # 0.35
        assert abs(w.tenant_weight - expected) < 0.01

# ═══════════════════════════════════════════════════════════════════════
# Q1-MANAGER: Global Model Manager Tests
# ═══════════════════════════════════════════════════════════════════════

class TestGlobalModelManager:
    """Test global model loading, caching, and lifecycle."""

    def test_init_not_loaded(self):
        """Manager starts with no model loaded."""
        registry = ModelRegistry(base_dir=tempfile.mkdtemp())
        manager = GlobalModelManager(registry)
        assert not manager.is_loaded
        assert manager.version is None
        assert manager.feature_names == []

    def test_get_info_defaults(self):
        """get_info() returns expected structure."""
        registry = ModelRegistry(base_dir=tempfile.mkdtemp())
        manager = GlobalModelManager(registry)
        info = manager.get_info()
        assert info["loaded"] is False
        assert info["version"] is None
        assert info["n_features"] == 0
        assert info["training_in_progress"] is False

    def test_try_load_from_empty_registry(self):
        """Loading from empty registry returns False."""
        registry = ModelRegistry(base_dir=tempfile.mkdtemp())
        manager = GlobalModelManager(registry)
        assert not manager._try_load_from_registry()

    def test_train_and_register(self):
        """Train and register produces valid model."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)

        success = manager.train_and_register()
        assert success
        assert manager.is_loaded
        assert manager.version is not None
        assert len(manager.feature_names) == 62

    def test_get_ensemble_lazy_load(self):
        """get_ensemble() trains on first call if no model exists."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)

        ensemble = manager.get_ensemble()
        assert ensemble is not None
        assert isinstance(ensemble, EnsembleScorer)
        assert manager.is_loaded

    def test_get_ensemble_cached(self):
        """Subsequent get_ensemble() calls return cached instance."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)

        e1 = manager.get_ensemble()
        e2 = manager.get_ensemble()
        assert e1 is e2  # Same object

    def test_reload_after_save(self):
        """reload() loads a model saved to the registry."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)

        # Train and save
        manager.train_and_register()
        v1 = manager.version

        # Create a new manager pointing to same registry
        manager2 = GlobalModelManager(registry)
        assert not manager2.is_loaded

        # Reload should find the saved model
        assert manager2.reload()
        assert manager2.is_loaded
        assert manager2.version == v1

    def test_thread_safety(self):
        """Multiple threads calling get_ensemble() is safe."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)

        results = []
        errors = []

        def worker():
            try:
                e = manager.get_ensemble()
                results.append(e is not None)
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert all(results), "All threads should get a valid ensemble"

# ═══════════════════════════════════════════════════════════════════════
# Q1-LOADER: ModelLoader Integration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestModelLoaderQ1Integration:
    """Test ModelLoader with global model fallback."""

    def test_loader_accepts_global_manager(self):
        """ModelLoader can be constructed with a GlobalModelManager."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)
        assert loader.global_manager is manager

    def test_loader_creates_default_global_manager(self):
        """ModelLoader creates a default GlobalModelManager if none provided."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        loader = ModelLoader(registry=registry)
        assert loader.global_manager is not None

    def test_fused_scoring_global_only(self):
        """Fused scoring works with only global model (no tenant model)."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)

        # Train global model
        manager.train_and_register()

        # Score with a tenant that has no model
        features = {name: 0.5 for name in manager.feature_names}
        result = loader.get_fused_ensemble_result(
            "tenant_abc",
            features,
            manager.feature_names,
        )

        assert result is not None
        assert "score" in result
        assert "fusion_weights" in result
        assert result["fusion_weights"]["global_weight"] == 1.0

    def test_update_tenant_metadata(self):
        """Tenant metadata updates affect fusion weights."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        loader = ModelLoader(registry=registry)

        # Initially, no metadata
        w = loader.get_fusion_weights("tenant_x")
        assert w.global_weight == 1.0
        assert w.tenant_weight == 0.0

        # Update metadata
        loader.update_tenant_metadata("tenant_x", samples=5000, precision=0.9)
        w = loader.get_fusion_weights("tenant_x")
        assert w.tenant_weight > 0

    def test_get_global_ensemble(self):
        """get_global_ensemble() returns the global model."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)

        # Before training, should be None (lazy)
        # But get_global_ensemble triggers lazy load
        ensemble = loader.get_global_ensemble()
        assert ensemble is not None

# Need to import ModelLoader after all patches are set up
from ml.serving.model_loader import ModelLoader

# ═══════════════════════════════════════════════════════════════════════
# Q1-TRAINER: Global Model Trainer Tests
# ═══════════════════════════════════════════════════════════════════════

# Module-level cache: train ONCE, reuse across all tests in this class.
# This avoids training the full 3-stage pipeline 9+ separate times.
_cached_trainer_results: dict | None = None

def _get_trainer_results(n_samples: int = 500, random_state: int = 42) -> dict:
    """Return cached training results (trains on first call only)."""
    global _cached_trainer_results
    if _cached_trainer_results is None:
        from ml.global_model.trainer import GlobalModelTrainer

        trainer = GlobalModelTrainer()
        _cached_trainer_results = trainer.train(n_samples=n_samples, random_state=random_state)
    return _cached_trainer_results

class TestGlobalModelTrainer:
    """Test the global model training pipeline."""

    def test_train_produces_all_stages(self):
        """Training produces stage1, stage2, and stage3 models."""
        results = _get_trainer_results()

        assert results["stage1"]["model"] is not None
        assert results["stage1"]["model"].is_fitted
        assert results["stage2"]["model"] is not None
        assert results["stage2"]["model"].is_fitted
        assert results["stage3"]["model"] is not None
        assert results["stage3"]["model"].is_fitted

    def test_train_feature_names(self):
        """Training uses correct 62-feature names."""
        results = _get_trainer_results()
        assert len(results["feature_names"]) == 62
        assert results["feature_names"] == GLOBAL_FEATURE_NAMES

    def test_train_data_fingerprint(self):
        """Training produces a data fingerprint."""
        results = _get_trainer_results()
        assert "data_fingerprint" in results
        assert len(results["data_fingerprint"]) == 64

    def test_train_reproducible(self):
        """Same seed produces same data fingerprint."""
        from ml.global_model.trainer import GlobalModelTrainer

        t1 = GlobalModelTrainer()
        t2 = GlobalModelTrainer()
        r1 = t1.train(n_samples=500, random_state=42)
        r2 = t2.train(n_samples=500, random_state=42)
        assert r1["data_fingerprint"] == r2["data_fingerprint"]

    def test_train_manifest_signed(self):
        """Training produces a signed manifest."""
        results = _get_trainer_results()
        assert "manifest" in results
        manifest = results["manifest"]
        assert "signature" in manifest or "content_hash" in manifest

    def test_train_audit_chain_valid(self):
        """Training produces a valid audit chain."""
        results = _get_trainer_results()
        assert results["audit_chain_valid"] is True

    def test_train_validation_metrics(self):
        """Training produces validation metrics for each stage."""
        results = _get_trainer_results()

        s1_val = results["stage1"]["validation"]
        assert hasattr(s1_val, "precision")
        assert 0.0 <= s1_val.precision <= 1.0
        assert hasattr(s1_val, "recall")
        assert 0.0 <= s1_val.recall <= 1.0

    def test_train_sanitization(self):
        """Training includes data sanitization."""
        results = _get_trainer_results()
        assert "sanitization" in results

    def test_train_timing(self):
        """Training records timing information."""
        results = _get_trainer_results()
        assert "training_time_seconds" in results
        assert results["training_time_seconds"] > 0

# ═══════════════════════════════════════════════════════════════════════
# Q1 Hardening Tests ( audit)
# ═══════════════════════════════════════════════════════════════════════

class TestSyntheticGeneratorBounds:
    """BUG-01: anomaly_fraction must be clamped to [0, 1]."""

    def test_anomaly_fraction_above_one_clamped(self):
        gen = GlobalSyntheticGenerator(random_state=99)
        X, y, names = gen.generate(n_samples=100, anomaly_fraction=1.5)
        assert X.shape[0] == 100
        assert len(y) == 100
        # All should be anomaly (clamped to 1.0)
        assert (y > 0).sum() == 100

    def test_anomaly_fraction_negative_clamped(self):
        gen = GlobalSyntheticGenerator(random_state=99)
        X, y, names = gen.generate(n_samples=100, anomaly_fraction=-0.5)
        assert X.shape[0] == 100
        # All should be benign (clamped to 0.0)
        assert (y == 0).sum() == 100

    def test_n_samples_zero_clamped(self):
        gen = GlobalSyntheticGenerator(random_state=99)
        X, y, names = gen.generate(n_samples=0, anomaly_fraction=0.1)
        assert X.shape[0] >= 1  # Clamped to at least 1

class TestFusionFeatureNamesFalsy:
    """BUG-08: empty list global_feature_names should NOT fall through."""

    def test_empty_list_not_treated_as_none(self):
        fusion = EnsembleFusion()

        mock_global = MagicMock(spec=EnsembleScorer)
        mock_global.score.return_value = {
            "score": 0.3,
            "attack_class": "benign",
            "probabilities": {},
            "stage_scores": {},
            "stages_active": [],
            "threshold": 0.7,
        }

        fusion.score(
            global_ensemble=mock_global,
            tenant_ensemble=None,
            features={"f1": 1.0},
            feature_names=["f1"],
            global_feature_names=[],  # Explicitly empty
        )
        # Should have called score with [] not ["f1"]
        call_args = mock_global.score.call_args
        assert call_args[0][1] == []  # global_feature_names=[] preserved

class TestManagerGetInfoLock:
    """BUG-05: get_info() must hold the lock."""

    def test_get_info_returns_consistent_snapshot(self):
        registry = MagicMock(spec=ModelRegistry)
        manager = GlobalModelManager(registry)
        info = manager.get_info()
        assert info["loaded"] is False
        assert info["version"] is None
        assert info["n_features"] == 0
        assert info["training_in_progress"] is False
