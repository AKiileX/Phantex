# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for ML Serving — Inference Pipeline, Model Loader, Shadow Mode (J3).
"""

import time
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import pytest

from ml.models.ensemble import EnsembleScorer
from ml.models.isolation_forest import IsolationForestModel
from ml.serving.inference import InferencePipeline
from ml.serving.model_loader import ModelLoader
from ml.serving.shadow_mode import ShadowModeTracker

# ── Helpers ──────────────────────────────────────────────────────────────────

FEATURE_NAMES = [f"f{i}" for i in range(10)]

def _mock_feature_extractor():
    """Create a mock FeatureExtractor."""
    extractor = AsyncMock()
    extractor.get_features = AsyncMock(return_value={f"f{i}": 0.1 * i for i in range(10)})
    return extractor

def _mock_model_loader(ensemble=None, names=None, fused_result=None):
    """Create a mock ModelLoader.

    Args:
        ensemble: The ensemble scorer to return from get_ensemble.
        names: Feature names list.
        fused_result: If provided, returned by get_fused_ensemble_result.
            If None and ensemble is None, get_fused_ensemble_result returns None.
            If None and ensemble is provided, auto-delegates to ensemble.score().
    """
    loader = MagicMock(spec=ModelLoader)
    loader.get_ensemble = MagicMock(return_value=ensemble)
    loader.get_feature_names = MagicMock(return_value=names or FEATURE_NAMES)
    loader.get_shadow_ensemble = MagicMock(return_value=None)

    if fused_result is not None:
        loader.get_fused_ensemble_result = MagicMock(return_value=fused_result)
    elif ensemble is not None:
        # Delegate to the ensemble's score method so tests that set up
        # mock_ensemble.score work transparently through the Q1 fused path.
        def _fused_side_effect(tenant_id, features, feature_names, **kw):
            return ensemble.score(features, feature_names)

        loader.get_fused_ensemble_result = MagicMock(side_effect=_fused_side_effect)
    else:
        loader.get_fused_ensemble_result = MagicMock(return_value=None)
    return loader

def _fitted_ensemble():
    """Return a fitted ensemble that always triggers alerts."""
    stage1 = IsolationForestModel()
    # Train on data that looks very different from what we'll inference on
    normal = np.random.RandomState(42).randn(200, 10)
    stage1.fit(normal, FEATURE_NAMES)
    return EnsembleScorer(stage1=stage1)

# ── InferencePipeline Tests ──────────────────────────────────────────────────

class TestInferencePipeline:
    """Tests for the InferencePipeline class."""

    @pytest.mark.asyncio
    async def test_score_event_returns_alert(self):
        """score_event returns alert dict when score exceeds threshold."""
        _fitted_ensemble()
        # Manually create an ensemble that will always alert
        mock_ensemble = MagicMock()
        mock_ensemble.score = MagicMock(
            return_value={
                "score": 0.9,
                "should_alert": True,
                "stage_scores": {"isolation_forest": 0.9},
                "attack_class": "data_exfiltration",
                "probabilities": {},
                "threshold": 0.7,
                "stages_active": ["isolation_forest"],
            }
        )

        loader = _mock_model_loader(ensemble=mock_ensemble)
        extractor = _mock_feature_extractor()
        pipeline = InferencePipeline(extractor, loader)

        event = {"tenant_id": "t1", "agent_id": "a1", "event_id": "e1"}
        alert = await pipeline.score_event(event)

        assert alert is not None
        assert alert["alert_type"] == "ml_ensemble"
        assert alert["score"] == 0.9
        assert alert["attack_class"] == "data_exfiltration"

    @pytest.mark.asyncio
    async def test_score_event_no_alert_below_threshold(self):
        """score_event returns None when score is below threshold."""
        mock_ensemble = MagicMock()
        mock_ensemble.score = MagicMock(
            return_value={
                "score": 0.3,
                "should_alert": False,
                "stage_scores": {},
                "attack_class": "benign",
                "probabilities": {},
                "threshold": 0.7,
                "stages_active": [],
            }
        )

        loader = _mock_model_loader(ensemble=mock_ensemble)
        extractor = _mock_feature_extractor()
        pipeline = InferencePipeline(extractor, loader)

        event = {"tenant_id": "t1", "agent_id": "a1"}
        alert = await pipeline.score_event(event)
        assert alert is None

    @pytest.mark.asyncio
    async def test_score_event_no_model(self):
        """score_event returns None when no model is loaded."""
        loader = _mock_model_loader(ensemble=None)
        extractor = _mock_feature_extractor()
        pipeline = InferencePipeline(extractor, loader)

        event = {"tenant_id": "t1", "agent_id": "a1"}
        alert = await pipeline.score_event(event)
        assert alert is None

    @pytest.mark.asyncio
    async def test_score_event_missing_fields(self):
        """score_event returns None for events without tenant/agent."""
        loader = _mock_model_loader()
        extractor = _mock_feature_extractor()
        pipeline = InferencePipeline(extractor, loader)

        assert await pipeline.score_event({}) is None
        assert await pipeline.score_event({"tenant_id": "t1"}) is None

    @pytest.mark.asyncio
    async def test_score_batch(self):
        """score_batch processes multiple events."""
        mock_ensemble = MagicMock()
        mock_ensemble.score = MagicMock(
            return_value={
                "score": 0.8,
                "should_alert": True,
                "stage_scores": {"isolation_forest": 0.8},
                "attack_class": "credential_theft",
                "probabilities": {},
                "threshold": 0.7,
                "stages_active": ["isolation_forest"],
            }
        )

        loader = _mock_model_loader(ensemble=mock_ensemble)
        extractor = _mock_feature_extractor()
        pipeline = InferencePipeline(extractor, loader)

        events = [{"tenant_id": "t1", "agent_id": f"a{i}", "event_id": f"e{i}"} for i in range(5)]
        alerts = await pipeline.score_batch(events)
        assert len(alerts) == 5

# ── Shadow Mode Tests ────────────────────────────────────────────────────────

class TestShadowMode:
    """Tests for the ShadowModeTracker."""

    def test_start_and_check_shadow(self):
        """start_shadow puts tenant in shadow mode."""
        tracker = ShadowModeTracker()
        assert not tracker.is_in_shadow("t1")

        tracker.start_shadow("t1", "v1")
        assert tracker.is_in_shadow("t1")

    def test_shadow_expires(self):
        """Shadow mode expires after duration."""
        tracker = ShadowModeTracker()
        tracker.start_shadow("t1", "v1")

        # Manipulate start time to simulate expiry
        tracker._shadow_start["t1"] = time.time() - 7200  # 2h ago
        assert not tracker.is_in_shadow("t1")

    def test_record_and_evaluate(self):
        """Shadow mode tracks alert rate correctly."""
        tracker = ShadowModeTracker()
        tracker.start_shadow("t1", "v123")

        # 100 scores, 5 alerts → alert_rate = 5%
        for i in range(100):
            tracker.record_score("t1", 0.3, should_alert=(i < 5))

        result = tracker.evaluate("t1")
        assert result["passed"] is True
        assert result["alert_rate"] == pytest.approx(0.05, abs=0.01)
        assert result["total_scored"] == 100
        assert result["version"] == "v123"

    def test_high_alert_rate_fails(self):
        """Shadow mode fails when alert rate exceeds threshold."""
        tracker = ShadowModeTracker()
        tracker.start_shadow("t1", "v999")

        # 100 scores, 20 alerts → alert_rate = 20% > 10% max
        for i in range(100):
            tracker.record_score("t1", 0.8, should_alert=(i < 20))

        result = tracker.evaluate("t1")
        assert result["passed"] is False
        assert result["alert_rate"] == pytest.approx(0.20, abs=0.01)

    def test_evaluate_cleans_state(self):
        """evaluate() cleans up shadow state."""
        tracker = ShadowModeTracker()
        tracker.start_shadow("t1", "v1")
        tracker.record_score("t1", 0.5, False)
        tracker.evaluate("t1")

        # State should be cleaned
        assert "t1" not in tracker._shadow_start

# ── Model Loader Tests ───────────────────────────────────────────────────────

class TestModelLoader:
    """Tests for the ModelLoader."""

    def test_get_ensemble_returns_none_cold_start(self):
        """get_ensemble returns None when no model has been loaded."""
        registry = MagicMock()
        registry.load_latest = MagicMock(return_value=None)
        loader = ModelLoader(registry)

        result = loader.get_ensemble("t1")
        assert result is None

    def test_force_reload_false_when_no_model(self):
        """force_reload returns False when no model available."""
        registry = MagicMock()
        registry.load_latest = MagicMock(return_value=None)
        loader = ModelLoader(registry)

        assert loader.force_reload("t1") is False

    def test_get_feature_names_empty(self):
        """get_feature_names returns empty list for unknown tenant."""
        registry = MagicMock()
        loader = ModelLoader(registry)
        assert loader.get_feature_names("unknown") == []

# ── Sprint 3 Audit: Shadow Mode Integration Tests ───────────────────────────

class TestModelLoaderShadowIntegration:
    """Tests for shadow mode wiring in ModelLoader."""

    def test_shadow_tracker_accessible(self):
        """ModelLoader exposes shadow_tracker property."""
        registry = MagicMock()
        registry.load_latest = MagicMock(return_value=None)
        loader = ModelLoader(registry)
        assert loader.shadow_tracker is not None
        assert isinstance(loader.shadow_tracker, ShadowModeTracker)

    def test_get_shadow_ensemble_none_when_not_in_shadow(self):
        """get_shadow_ensemble returns None outside shadow mode."""
        registry = MagicMock()
        registry.load_latest = MagicMock(return_value=None)
        loader = ModelLoader(registry)
        assert loader.get_shadow_ensemble("t1") is None

    def test_cold_start_skips_shadow(self):
        """First model load for a tenant activates immediately (no shadow)."""
        # Create a mock registry that returns a model version
        from ml.registry.model_registry import ModelVersion

        mv = MagicMock(spec=ModelVersion)
        mv.version = "v1"
        mv.feature_names = ["f1", "f2"]
        mv.path = MagicMock()

        registry = MagicMock()
        registry.load_latest = MagicMock(return_value=mv)
        registry.load_models = MagicMock(
            return_value={
                "stage1": None,
                "stage2": None,
                "stage3": None,
            }
        )

        loader = ModelLoader(registry)
        ensemble = loader.get_ensemble("t1")

        # Should be activated immediately (not in shadow)
        assert ensemble is not None
        assert not loader.shadow_tracker.is_in_shadow("t1")
