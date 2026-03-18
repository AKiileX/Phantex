# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for J5 Integration — wiring J5 modules into the live ML pipeline.

Covers:
  - Inference pipeline with explainability + evasion detection
  - Labeler with LabelGovernance integration
  - Meta-detection (staleness, accuracy, evasion alerting)
  - Training pipeline with sanitization + audit + manifest
  - Config caching
  - Shadow mode alert_rate rename
  - __init__.py exports
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import pytest

from ml.config import get_ml_config

# ── Helpers ──────────────────────────────────────────────────────────────────

FEATURE_NAMES = [f"f{i}" for i in range(10)]

def _alerting_ensemble():
    """Return a mock ensemble that always triggers alerts."""
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
    """Return a mock ensemble that never triggers."""
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
        # Delegate fused scoring to ensemble.score so Q1 path works
        def _fused(tenant_id, features, feature_names, **kw):
            return ensemble.score(features, feature_names)

        loader.get_fused_ensemble_result = MagicMock(side_effect=_fused)
    else:
        loader.get_fused_ensemble_result = MagicMock(return_value=None)
    return loader

# ── Inference + Explainability (J5c) ────────────────────────────────────────

class TestInferenceExplainability:
    """Inference pipeline now produces explanation dicts on alerts."""

    @pytest.mark.asyncio
    async def test_alert_contains_explanation(self):
        """Alerts include a non-empty explanation dict with J5c fields."""
        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        ensemble = _alerting_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()
        explainer = EnsembleExplainer()

        pipeline = InferencePipeline(extractor, loader, explainer=explainer)
        event = {"tenant_id": "t1", "agent_id": "a1", "event_id": "e1"}
        alert = await pipeline.score_event(event)

        assert alert is not None
        assert "explanation" in alert
        explanation = alert["explanation"]
        assert "score" in explanation
        assert "summary" in explanation
        assert "stage_contributions" in explanation
        assert "confidence" in explanation
        assert explanation["confidence"] in {"high", "medium", "low"}

    @pytest.mark.asyncio
    async def test_no_alert_no_explanation(self):
        """No alert means no explanation overhead."""
        from ml.serving.inference import InferencePipeline

        ensemble = _quiet_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        pipeline = InferencePipeline(extractor, loader)
        event = {"tenant_id": "t1", "agent_id": "a1"}
        alert = await pipeline.score_event(event)
        assert alert is None

    @pytest.mark.asyncio
    async def test_explanation_failure_graceful(self):
        """If explainer raises, alert is still produced (without explanation)."""
        from ml.explainability.ensemble_explainer import EnsembleExplainer
        from ml.serving.inference import InferencePipeline

        bad_explainer = MagicMock(spec=EnsembleExplainer)
        bad_explainer.explain = MagicMock(side_effect=RuntimeError("boom"))

        ensemble = _alerting_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        pipeline = InferencePipeline(extractor, loader, explainer=bad_explainer)
        event = {"tenant_id": "t1", "agent_id": "a1", "event_id": "e1"}
        alert = await pipeline.score_event(event)

        assert alert is not None
        assert alert["explanation"] == {}  # Graceful fallback

# ── Inference + Evasion Detection (J5d) ─────────────────────────────────────

class TestInferenceEvasion:
    """Evasion detector is wired into the inference pipeline."""

    @pytest.mark.asyncio
    async def test_evasion_records_scores(self):
        """Every score_event call records a score in the evasion detector."""
        from ml.meta.evasion_detector import EvasionDetector
        from ml.serving.inference import InferencePipeline

        evasion = EvasionDetector()
        ensemble = _quiet_ensemble()
        loader = _mock_model_loader(ensemble=ensemble)
        extractor = _mock_feature_extractor()

        pipeline = InferencePipeline(extractor, loader, evasion_detector=evasion)

        for i in range(10):
            await pipeline.score_event({"tenant_id": "t1", "agent_id": f"a{i}"})

        assert len(evasion._scores) == 10

    @pytest.mark.asyncio
    async def test_evasion_detector_accessible(self):
        """Pipeline exposes the evasion detector."""
        from ml.meta.evasion_detector import EvasionDetector
        from ml.serving.inference import InferencePipeline

        evasion = EvasionDetector()
        loader = _mock_model_loader(ensemble=_quiet_ensemble())
        extractor = _mock_feature_extractor()

        pipeline = InferencePipeline(extractor, loader, evasion_detector=evasion)
        assert pipeline.evasion_detector is evasion

# ── score_batch concurrency (Bug #4 fix) ────────────────────────────────────

class TestScoreBatchConcurrency:
    """score_batch now uses asyncio.gather instead of sequential loop."""

    @pytest.mark.asyncio
    async def test_score_batch_handles_exceptions(self):
        """Exceptions in one event don't block others."""
        from ml.serving.inference import InferencePipeline

        call_count = 0

        async def _flaky_score(event):
            nonlocal call_count
            call_count += 1
            if event.get("agent_id") == "bad":
                raise RuntimeError("flaky")
            return {"alert_type": "ml_ensemble", "score": 0.9}

        loader = _mock_model_loader(ensemble=_alerting_ensemble())
        extractor = _mock_feature_extractor()
        pipeline = InferencePipeline(extractor, loader)

        # Patch score_event with the flaky version
        pipeline.score_event = _flaky_score

        events = [
            {"tenant_id": "t1", "agent_id": "a1"},
            {"tenant_id": "t1", "agent_id": "bad"},
            {"tenant_id": "t1", "agent_id": "a3"},
        ]
        alerts = await pipeline.score_batch(events)
        assert len(alerts) == 2  # bad one filtered, other two succeed
        assert call_count == 3

# ── Labeler + LabelGovernance (Bug #2 fix) ──────────────────────────────────

class TestLabelerGovernance:
    """Labeler respects LabelGovernance dual-approval workflow."""

    def test_without_governance(self):
        """Without governance, labeler uses raw disposition mapping."""
        from ml.training.labeler import Labeler

        labeler = Labeler()
        X = np.zeros((5, 3))
        labels = [
            {"sample_index": 0, "disposition": "confirmed", "attack_class_index": 1},
            {"sample_index": 1, "disposition": "false_positive"},
            {"sample_index": 2, "disposition": "pending_review"},
        ]
        y, mask = labeler.create_labels(X, labels)

        assert mask[0] == True  # confirmed  # noqa: E712
        assert y[0] == 1
        assert mask[1] == True  # false_positive → negative  # noqa: E712
        assert y[1] == 0
        assert mask[2] == False  # pending → unlabeled  # noqa: E712

    def test_with_governance_filters_unapproved(self):
        """With governance, only dual-approved labels are used."""
        from ml.integrity.label_governance import LabelGovernance
        from ml.training.labeler import Labeler

        gov = LabelGovernance()
        # Alert "a1" confirmed by analyst
        gov.analyst_confirm("a1", "analyst_1")
        # Alert "a2" dismissed by analyst but NOT approved by admin
        gov.analyst_dismiss("a2", "analyst_1", reason="looks benign")
        # Alert "a3" dismissed + admin approved
        gov.analyst_dismiss("a3", "analyst_1", reason="benign pattern")
        gov.admin_approve_dismissal("a3", "admin_1")

        labeler = Labeler(governance=gov)
        X = np.zeros((5, 3))
        labels = [
            {"sample_index": 0, "alert_id": "a1", "disposition": "confirmed", "attack_class_index": 1},
            {"sample_index": 1, "alert_id": "a2", "disposition": "false_positive"},
            {"sample_index": 2, "alert_id": "a3", "disposition": "false_positive"},
            {"sample_index": 3, "alert_id": "a_unknown", "disposition": "confirmed"},
        ]
        y, mask = labeler.create_labels(X, labels)

        assert mask[0] == True  # a1 confirmed → positive  # noqa: E712
        assert y[0] == 1
        assert mask[1] == False  # a2 not approved by admin → excluded  # noqa: E712
        assert mask[2] == True  # a3 admin-approved dismissal → negative  # noqa: E712
        assert y[2] == 0
        assert mask[3] == False  # unknown alert_id → excluded  # noqa: E712

    def test_without_alert_id_falls_back(self):
        """Labels without alert_id use raw disposition even with governance."""
        from ml.integrity.label_governance import LabelGovernance
        from ml.training.labeler import Labeler

        labeler = Labeler(governance=LabelGovernance())
        X = np.zeros((3, 3))
        labels = [
            {"sample_index": 0, "disposition": "confirmed", "attack_class_index": 1},
        ]
        y, mask = labeler.create_labels(X, labels)
        assert mask[0] == True  # noqa: E712
        assert y[0] == 1

# ── Meta-Detection (J5d) ────────────────────────────────────────────────────

class TestMetaDetection:
    """Meta-detection components are correctly integrated."""

    def test_staleness_checker(self):
        """Staleness checker detects old models."""
        from ml.meta.staleness_checker import StalenessChecker

        checker = StalenessChecker(max_age_days=7)
        # Register a model trained 10 days ago
        checker.register_model("m1", trained_at=time.time() - 10 * 86400)
        checker.register_model("m2", trained_at=time.time())  # Fresh

        stale = checker.get_stale_models()
        assert len(stale) == 1
        assert stale[0].model_id == "m1"

    def test_accuracy_tracker_compute(self):
        """Accuracy tracker computes metrics from recorded predictions."""
        from ml.meta.accuracy_tracker import AccuracyTracker

        tracker = AccuracyTracker()
        # 8 TP, 2 FP, 0 FN
        for i in range(10):
            tracker.record(predicted_positive=True, actual_positive=(i < 8))

        snapshot = tracker.compute()
        assert snapshot.precision == pytest.approx(0.8, abs=0.01)
        assert snapshot.true_positives == 8
        assert snapshot.false_positives == 2

    def test_meta_alerter_fires_and_queries(self):
        """MetaAlerter stores and queries meta-alerts."""
        from ml.meta.alerter import MetaAlerter, MetaAlertSeverity, MetaAlertType

        alerter = MetaAlerter()
        alert = alerter.fire(MetaAlertType.EVASION_PATTERN, "Test evasion")
        assert alert.severity == MetaAlertSeverity.CRITICAL
        assert "ops_team" in alert.channels

        results = alerter.get_alerts(alert_type=MetaAlertType.EVASION_PATTERN)
        assert len(results) == 1
        assert alerter.alert_count == 1

# ── Training Pipeline Integration (J5a/b/e) ─────────────────────────────────

class TestTrainingIntegration:
    """Training pipeline includes sanitization, audit, manifest."""

    def test_train_all_includes_sanitization(self):
        """train_all results include sanitization report."""
        from ml.training.trainer import TrainingPipeline

        pipeline = TrainingPipeline()
        result = pipeline.train_all()

        assert "sanitization" in result
        assert result["sanitization"]["retained_samples"] > 0

    def test_train_all_includes_manifest(self):
        """train_all results include a signed manifest."""
        from ml.training.trainer import TrainingPipeline

        pipeline = TrainingPipeline()
        result = pipeline.train_all()

        assert "manifest" in result
        manifest = result["manifest"]
        assert "model_id" in manifest
        assert "signature" in manifest
        assert manifest["signature"] is not None

    def test_train_all_audit_chain_valid(self):
        """train_all verifies audit chain integrity."""
        from ml.training.trainer import TrainingPipeline

        pipeline = TrainingPipeline()
        result = pipeline.train_all()

        assert result["audit_chain_valid"] is True

    def test_train_all_audit_log_accessible(self):
        """Audit log is accessible after training."""
        from ml.training.trainer import TrainingPipeline

        pipeline = TrainingPipeline()
        pipeline.train_all(tenant_id="test-tenant", operator_id="test-op")

        log = pipeline.audit_log
        entries = log.get_entries()
        assert len(entries) >= 3  # STARTED, DATA_LOADED, SANITIZATION, COMPLETED

        actions = [e.action for e in entries]
        assert "training_started" in actions
        assert "training_completed" in actions

# ── Config Caching (Bug #5 fix) ─────────────────────────────────────────────

class TestConfigCaching:
    """get_ml_config() returns the same instance (lru_cache)."""

    def test_cache_same_instance(self):
        cfg1 = get_ml_config()
        cfg2 = get_ml_config()
        assert cfg1 is cfg2

# ── Shadow Mode rename (Bug #3 fix) ─────────────────────────────────────────

class TestShadowModeAlertRate:
    """Shadow mode evaluate() uses 'alert_rate' not 'fpr'."""

    def test_evaluate_returns_alert_rate(self):
        from ml.serving.shadow_mode import ShadowModeTracker

        tracker = ShadowModeTracker()
        tracker.start_shadow("t1", "v1")
        for _ in range(10):
            tracker.record_score("t1", 0.5, False)
        result = tracker.evaluate("t1")

        assert "alert_rate" in result
        assert "fpr" not in result
        assert "max_alert_rate" in result

# ── __init__.py Exports (Bug #1 fix) ────────────────────────────────────────

class TestPackageExports:
    """All J5 packages export meaningful symbols."""

    def test_adversarial_exports(self):
        from ml.adversarial import augment_training_data, fgsm_attack

        assert callable(fgsm_attack)
        assert callable(augment_training_data)

    def test_integrity_exports(self):
        from ml.integrity import DataSanitizer, LabelGovernance

        assert LabelGovernance is not None
        assert DataSanitizer is not None

    def test_explainability_exports(self):
        from ml.explainability import EnsembleExplainer

        assert EnsembleExplainer is not None

    def test_meta_exports(self):
        from ml.meta import EvasionDetector

        assert EvasionDetector is not None

    def test_provenance_exports(self):
        from ml.provenance import ManifestBuilder, compute_data_hash

        assert ManifestBuilder is not None
        assert callable(compute_data_hash)

    def test_privacy_exports(self):
        from ml.privacy import add_laplace_noise

        assert callable(add_laplace_noise)
