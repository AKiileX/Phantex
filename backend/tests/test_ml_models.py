# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for ML Models — Isolation Forest, XGBoost, Autoencoder, Ensemble (J2).
"""

import tempfile
from pathlib import Path

import numpy as np
import pytest

from ml.models.autoencoder import AutoencoderModel
from ml.models.ensemble import EnsembleScorer
from ml.models.isolation_forest import IsolationForestModel
from ml.models.xgboost_model import ATTACK_CLASSES, XGBoostModel

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_normal_data(n=500, features=10, seed=42):
    """Generate normal-looking feature data."""
    rng = np.random.RandomState(seed)
    return rng.randn(n, features).astype(np.float64)

def _make_anomalous_data(n=50, features=10, seed=99):
    """Generate anomalous feature data (shifted distribution)."""
    rng = np.random.RandomState(seed)
    return (rng.randn(n, features) * 5 + 10).astype(np.float64)

FEATURE_NAMES = [f"f{i}" for i in range(10)]

# ── Isolation Forest Tests ───────────────────────────────────────────────────

class TestIsolationForest:
    """Tests for the Isolation Forest wrapper."""

    def test_fit_and_predict(self):
        """Fit on normal data, score normal + anomalous."""
        model = IsolationForestModel()
        X_train = _make_normal_data()
        meta = model.fit(X_train, FEATURE_NAMES)

        assert model.is_fitted
        assert meta["n_samples"] == 500
        assert meta["n_features"] == 10

        # Normal data should get lower scores
        normal_scores = model.predict_score(_make_normal_data(n=100, seed=0))
        anomaly_scores = model.predict_score(_make_anomalous_data())

        assert normal_scores.mean() < anomaly_scores.mean()

    def test_scores_in_range(self):
        """All scores should be in [0, 1]."""
        model = IsolationForestModel()
        model.fit(_make_normal_data())
        scores = model.predict_score(_make_normal_data(n=100))
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_predict_single(self):
        """predict_single works with dict input."""
        model = IsolationForestModel()
        model.fit(_make_normal_data(), FEATURE_NAMES)

        features = {f"f{i}": 0.0 for i in range(10)}
        score = model.predict_single(features, FEATURE_NAMES)
        assert 0.0 <= score <= 1.0

    def test_unfitted_raises(self):
        """predict_score raises when model not fitted."""
        model = IsolationForestModel()
        with pytest.raises(RuntimeError, match="not fitted"):
            model.predict_score(_make_normal_data(n=10))

    def test_save_load_roundtrip(self):
        """Model can be saved and loaded."""
        model = IsolationForestModel()
        model.fit(_make_normal_data(), FEATURE_NAMES)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "model.pkl"
            model.save(path)
            loaded = IsolationForestModel.load(path)

        assert loaded.is_fitted
        # Same scores after load
        X = _make_normal_data(n=5, seed=7)
        np.testing.assert_allclose(
            model.predict_score(X),
            loaded.predict_score(X),
        )

    def test_feature_importances(self):
        """feature_importances returns (name, importance) pairs."""
        model = IsolationForestModel()
        model.fit(_make_normal_data(), FEATURE_NAMES)
        X = _make_normal_data(n=50)
        importances = model.feature_importances(X)
        assert len(importances) == 10
        assert all(isinstance(name, str) for name, _ in importances)
        assert all(isinstance(val, float) for _, val in importances)

# ── XGBoost Tests ────────────────────────────────────────────────────────────

class TestXGBoost:
    """Tests for the XGBoost classifier wrapper."""

    def _fit_model(self):
        """Helper to create a fitted XGBoost model."""
        model = XGBoostModel()
        rng = np.random.RandomState(42)
        X = rng.randn(200, 10).astype(np.float64)
        y = rng.randint(0, len(ATTACK_CLASSES), size=200)
        model.fit(X, y, feature_names=FEATURE_NAMES)
        return model

    def test_fit_and_predict(self):
        """Fit on random data, produce probability predictions."""
        model = self._fit_model()
        assert model.is_fitted

        X = np.random.randn(10, 10)
        probs = model.predict_proba(X)
        assert probs.shape == (10, len(ATTACK_CLASSES))
        # Probabilities sum to 1
        np.testing.assert_allclose(probs.sum(axis=1), 1.0, atol=1e-5)

    def test_predict_single(self):
        """predict_single returns score, attack_class, probabilities."""
        model = self._fit_model()
        features = {f"f{i}": 0.5 for i in range(10)}
        result = model.predict_single(features, FEATURE_NAMES)

        assert "score" in result
        assert "attack_class" in result
        assert "probabilities" in result
        assert 0.0 <= result["score"] <= 1.0
        assert result["attack_class"] in ATTACK_CLASSES

    def test_unfitted_raises(self):
        """predict_proba raises when not fitted."""
        model = XGBoostModel()
        with pytest.raises(RuntimeError, match="not fitted"):
            model.predict_proba(np.zeros((1, 10)))

    def test_save_load_roundtrip(self):
        """Model can be saved and loaded."""
        model = self._fit_model()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "xgb.pkl"
            model.save(path)
            loaded = XGBoostModel.load(path)

        assert loaded.is_fitted
        assert loaded.attack_classes == model.attack_classes

    def test_attack_classes_default(self):
        """Default attack classes are present."""
        assert "benign" in ATTACK_CLASSES
        assert "credential_theft" in ATTACK_CLASSES
        assert len(ATTACK_CLASSES) == 8

# ── Autoencoder Tests ────────────────────────────────────────────────────────

class TestAutoencoder:
    """Tests for the PyTorch autoencoder."""

    def test_fit_and_predict(self):
        """Fit on normal data, anomalous data scores higher."""
        model = AutoencoderModel(input_dim=10)
        X_normal = _make_normal_data()
        meta = model.fit(X_normal, FEATURE_NAMES)

        assert model.is_fitted
        assert meta["n_samples"] == 500
        assert meta["threshold_p95"] > 0

        normal_scores = model.predict_score(_make_normal_data(n=100, seed=0))
        anomaly_scores = model.predict_score(_make_anomalous_data())

        # Anomalous data should generally score higher
        assert anomaly_scores.mean() > normal_scores.mean()

    def test_scores_in_range(self):
        """All scores should be in [0, 1]."""
        model = AutoencoderModel(input_dim=10)
        model.fit(_make_normal_data())
        scores = model.predict_score(_make_normal_data(n=100))
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_predict_single(self):
        """predict_single returns float in [0, 1]."""
        model = AutoencoderModel(input_dim=10)
        model.fit(_make_normal_data(), FEATURE_NAMES)
        features = {f"f{i}": 0.0 for i in range(10)}
        score = model.predict_single(features, FEATURE_NAMES)
        assert 0.0 <= score <= 1.0

    def test_unfitted_raises(self):
        """predict_score raises when not fitted."""
        model = AutoencoderModel(input_dim=10)
        with pytest.raises(RuntimeError, match="not fitted"):
            model.predict_score(np.zeros((1, 10)))

    def test_reconstruction_errors_per_feature(self):
        """Per-feature errors are returned for explainability."""
        model = AutoencoderModel(input_dim=10)
        model.fit(_make_normal_data(), FEATURE_NAMES)
        features = {f"f{i}": 0.0 for i in range(10)}
        errors = model.reconstruction_errors_per_feature(features, FEATURE_NAMES)
        assert len(errors) == 10
        assert all(isinstance(name, str) for name, _ in errors)

# ── Ensemble Tests ───────────────────────────────────────────────────────────

class TestEnsemble:
    """Tests for the EnsembleScorer."""

    def test_score_with_all_stages(self):
        """Score with all 3 stages returns complete result."""
        stage1 = IsolationForestModel()
        stage1.fit(_make_normal_data(), FEATURE_NAMES)

        stage2 = XGBoostModel()
        rng = np.random.RandomState(42)
        X = rng.randn(200, 10).astype(np.float64)
        y = rng.randint(0, 8, size=200)
        stage2.fit(X, y, feature_names=FEATURE_NAMES)

        stage3 = AutoencoderModel(input_dim=10)
        stage3.fit(_make_normal_data(), FEATURE_NAMES)

        ensemble = EnsembleScorer(stage1, stage2, stage3)
        features = {f"f{i}": 0.0 for i in range(10)}
        result = ensemble.score(features, FEATURE_NAMES)

        assert "score" in result
        assert "should_alert" in result
        assert "stage_scores" in result
        assert "attack_class" in result
        assert 0.0 <= result["score"] <= 1.0
        assert len(result["stages_active"]) == 3

    def test_score_with_no_stages(self):
        """Score returns 0 and no alert when no stages available."""
        ensemble = EnsembleScorer()
        features = {f"f{i}": 0.0 for i in range(10)}
        result = ensemble.score(features, FEATURE_NAMES)

        assert result["score"] == 0.0
        assert result["should_alert"] is False
        assert len(result["stages_active"]) == 0

    def test_score_with_single_stage(self):
        """Score works with only Stage 1 (Isolation Forest)."""
        stage1 = IsolationForestModel()
        stage1.fit(_make_normal_data(), FEATURE_NAMES)

        ensemble = EnsembleScorer(stage1=stage1)
        features = {f"f{i}": 0.0 for i in range(10)}
        result = ensemble.score(features, FEATURE_NAMES)

        assert 0.0 <= result["score"] <= 1.0
        assert len(result["stages_active"]) == 1
        assert "isolation_forest" in result["stages_active"]

    def test_weight_renormalization(self):
        """When a stage is missing, remaining weights are renormalized."""
        stage1 = IsolationForestModel()
        stage1.fit(_make_normal_data(), FEATURE_NAMES)

        # Only stage1 → weight becomes 1.0 (renormalized from 0.3)
        ensemble = EnsembleScorer(stage1=stage1)
        features = {f"f{i}": 0.0 for i in range(10)}
        result = ensemble.score(features, FEATURE_NAMES)

        # Score should equal the IF score exactly (since it's the only stage)
        assert result["score"] == pytest.approx(result["stage_scores"]["isolation_forest"], abs=1e-6)

    def test_threshold_property(self):
        """alert_threshold returns configured value."""
        ensemble = EnsembleScorer()
        assert ensemble.alert_threshold == 0.7
