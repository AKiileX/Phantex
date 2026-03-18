# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q2 Tests: Auto-Retrain Pipeline.

Tests for:
  - RetrainScheduler: label tracking, trigger logic, rate limiting
  - QualityGate: validation thresholds, pass/fail conditions
  - RetrainPipeline: full retrain cycle, model promotion, failure handling
  - RetrainWorker: background task lifecycle
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# Ensure backend/ is on sys.path
_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

import contextlib

from ml.config import get_ml_config
from ml.global_model.manager import GlobalModelManager
from ml.global_model.synthetic_generator import GlobalSyntheticGenerator
from ml.registry.model_registry import ModelRegistry
from ml.retrain.pipeline import RetrainPipeline
from ml.retrain.quality_gate import QualityGate, QualityResult
from ml.retrain.scheduler import RetrainScheduler, RetrainTrigger
from ml.retrain.worker import RetrainWorker
from ml.serving.model_loader import ModelLoader

# ═══════════════════════════════════════════════════════════════════════
# Q2-SCHEDULER: Retrain Scheduler Tests
# ═══════════════════════════════════════════════════════════════════════

class TestRetrainScheduler:
    """Test label tracking and retrain triggering."""

    def test_initial_state(self):
        """Fresh scheduler has no labels and is enabled."""
        scheduler = RetrainScheduler()
        assert scheduler.enabled
        status = scheduler.get_status("any_tenant")
        assert status["new_labels"] == 0
        assert status["total_labels"] == 0
        assert status["is_retraining"] is False

    def test_record_labels(self):
        """Recording labels increments counts."""
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=10)
        status = scheduler.get_status("t1")
        assert status["new_labels"] == 10
        assert status["total_labels"] == 10

    def test_record_labels_cumulative(self):
        """Multiple label recordings accumulate."""
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=10)
        scheduler.record_labels("t1", count=25)
        scheduler.record_labels("t1", count=20)
        status = scheduler.get_status("t1")
        assert status["new_labels"] == 55
        assert status["total_labels"] == 55

    def test_record_zero_labels_ignored(self):
        """Recording zero or negative labels is ignored."""
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=0)
        scheduler.record_labels("t1", count=-5)
        status = scheduler.get_status("t1")
        assert status["new_labels"] == 0

    def test_check_insufficient_labels(self):
        """Check returns no-trigger when labels below threshold."""
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=10)
        trigger = scheduler.check("t1")
        assert not trigger.should_retrain
        assert trigger.reason == "insufficient_new_labels"

    def test_check_threshold_met(self):
        """Check returns trigger when labels meet threshold."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        trigger = scheduler.check("t1")
        assert trigger.should_retrain
        assert trigger.reason == "threshold_met"
        assert trigger.new_labels == cfg.min_new_labels

    def test_check_above_threshold(self):
        """Check triggers when labels exceed threshold."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels + 100)
        trigger = scheduler.check("t1")
        assert trigger.should_retrain

    def test_check_disabled(self):
        """Check returns no-trigger when scheduler is disabled."""
        scheduler = RetrainScheduler()
        scheduler.enabled = False
        scheduler.record_labels("t1", count=1000)
        trigger = scheduler.check("t1")
        assert not trigger.should_retrain
        assert trigger.reason == "auto_retrain_disabled"

    def test_check_already_retraining(self):
        """Check returns no-trigger when tenant is already retraining."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        scheduler.mark_retrain_started("t1")
        trigger = scheduler.check("t1")
        assert not trigger.should_retrain
        assert trigger.reason == "retrain_already_in_progress"

    def test_check_max_concurrent(self):
        """Check returns no-trigger when max concurrent retrains reached."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain

        # Start max concurrent retrains
        for i in range(cfg.max_concurrent_retrains):
            scheduler.record_labels(f"t{i}", count=cfg.min_new_labels)
            scheduler.mark_retrain_started(f"t{i}")

        # New tenant should be blocked
        scheduler.record_labels("t_new", count=cfg.min_new_labels)
        trigger = scheduler.check("t_new")
        assert not trigger.should_retrain
        assert trigger.reason == "max_concurrent_retrains_reached"

    def test_check_rate_limited(self):
        """Check returns no-trigger when within rate limit window."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain

        # First retrain completes
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        scheduler.mark_retrain_started("t1")
        scheduler.mark_retrain_completed("t1", success=True)

        # Immediately add more labels
        scheduler.record_labels("t1", count=cfg.min_new_labels)

        # Should be rate limited
        trigger = scheduler.check("t1")
        assert not trigger.should_retrain
        assert trigger.reason == "rate_limited"

    def test_mark_retrain_completed_resets_labels(self):
        """Successful retrain resets new_label count."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        scheduler.mark_retrain_started("t1")
        scheduler.mark_retrain_completed("t1", success=True)
        status = scheduler.get_status("t1")
        assert status["new_labels"] == 0
        assert status["total_labels"] == cfg.min_new_labels
        assert status["is_retraining"] is False

    def test_mark_retrain_failed_keeps_labels(self):
        """Failed retrain preserves label count for retry."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        scheduler.mark_retrain_started("t1")
        scheduler.mark_retrain_completed("t1", success=False, reset_labels=False)
        status = scheduler.get_status("t1")
        assert status["new_labels"] == cfg.min_new_labels

    def test_check_all_multiple_tenants(self):
        """check_all() returns triggers for all eligible tenants."""
        scheduler = RetrainScheduler()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        scheduler.record_labels("t2", count=cfg.min_new_labels)
        scheduler.record_labels("t3", count=5)  # Below threshold

        triggers = scheduler.check_all()
        tenant_ids = {t.tenant_id for t in triggers}
        assert "t1" in tenant_ids
        assert "t2" in tenant_ids
        assert "t3" not in tenant_ids

    def test_get_all_status(self):
        """get_all_status() returns status for all tracked tenants."""
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=10)
        scheduler.record_labels("t2", count=20)
        all_status = scheduler.get_all_status()
        assert "t1" in all_status
        assert "t2" in all_status
        assert all_status["t1"]["new_labels"] == 10
        assert all_status["t2"]["new_labels"] == 20

    def test_trigger_to_dict(self):
        """RetrainTrigger.to_dict() returns expected structure."""
        trigger = RetrainTrigger(
            should_retrain=True,
            tenant_id="t1",
            new_labels=50,
            reason="threshold_met",
            total_labels=200,
        )
        d = trigger.to_dict()
        assert d["should_retrain"] is True
        assert d["tenant_id"] == "t1"
        assert d["new_labels"] == 50
        assert d["reason"] == "threshold_met"
        assert d["total_labels"] == 200

    def test_multi_tenant_isolation(self):
        """Labels for one tenant don't affect another."""
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=100)
        scheduler.record_labels("t2", count=5)
        assert scheduler.get_status("t1")["new_labels"] == 100
        assert scheduler.get_status("t2")["new_labels"] == 5
        assert scheduler.get_status("t3")["new_labels"] == 0

# ═══════════════════════════════════════════════════════════════════════
# Q2-QG: Quality Gate Tests
# ═══════════════════════════════════════════════════════════════════════

class TestQualityGate:
    """Test model quality validation."""

    def test_all_pass(self):
        """Model meeting all thresholds passes."""
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
            current_precision=0.90,
            current_recall=0.82,
        )
        assert result.passed
        assert result.reason == "all_checks_passed"

    def test_precision_regression(self):
        """Precision regression beyond tolerance fails."""
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.85,  # Big drop from 0.92
            new_recall=0.85,
            new_fpr=0.03,
            current_precision=0.92,
            current_recall=0.82,
        )
        assert not result.passed
        assert "precision_regression" in result.reason

    def test_precision_within_tolerance(self):
        """Small precision decrease within tolerance passes."""
        gate = QualityGate()
        cfg = get_ml_config().auto_retrain
        result = gate.evaluate(
            new_precision=0.90 - cfg.precision_regression_tolerance + 0.001,
            new_recall=0.85,
            new_fpr=0.03,
            current_precision=0.90,
            current_recall=0.82,
        )
        assert result.passed

    def test_recall_regression(self):
        """Recall regression beyond tolerance fails."""
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.70,  # Big drop from 0.85
            new_fpr=0.03,
            current_precision=0.90,
            current_recall=0.85,
        )
        assert not result.passed
        assert "recall_regression" in result.reason

    def test_fpr_ceiling(self):
        """FPR exceeding ceiling fails."""
        gate = QualityGate()
        cfg = get_ml_config().auto_retrain
        result = gate.evaluate(
            new_precision=0.95,
            new_recall=0.90,
            new_fpr=cfg.fpr_max + 0.01,
            current_precision=0.90,
            current_recall=0.85,
        )
        assert not result.passed
        assert "fpr_ceiling" in result.reason

    def test_nan_predictions_fail(self):
        """Predictions with NaN fail."""
        gate = QualityGate()
        predictions = np.array([0.5, 0.6, float("nan"), 0.8])
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
            predictions=predictions,
        )
        assert not result.passed
        assert "NaN" in result.reason

    def test_inf_predictions_fail(self):
        """Predictions with Inf fail."""
        gate = QualityGate()
        predictions = np.array([0.5, 0.6, float("inf"), 0.8])
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
            predictions=predictions,
        )
        assert not result.passed

    def test_trivial_predictions_fail(self):
        """All-same predictions fail."""
        gate = QualityGate()
        predictions = np.array([0.5, 0.5, 0.5, 0.5])
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
            predictions=predictions,
        )
        assert not result.passed
        assert "trivial" in result.reason

    def test_valid_predictions_pass(self):
        """Valid diverse predictions pass."""
        gate = QualityGate()
        predictions = np.array([0.1, 0.5, 0.8, 0.3])
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
            predictions=predictions,
        )
        assert result.passed

    def test_first_model_no_current(self):
        """First model (no current baseline) uses default thresholds."""
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.5,  # Would fail vs existing, but passes vs 0.0
            new_recall=0.5,
            new_fpr=0.05,
            current_precision=0.0,
            current_recall=0.0,
        )
        assert result.passed

    def test_quality_result_to_dict(self):
        """QualityResult.to_dict() returns expected structure."""
        result = QualityResult(
            passed=True,
            checks={"precision": {"passed": True}},
            reason="all_checks_passed",
        )
        d = result.to_dict()
        assert d["passed"] is True
        assert "checks" in d
        assert d["reason"] == "all_checks_passed"

    def test_multiple_failures(self):
        """Multiple failures are all reported."""
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.1,
            new_recall=0.1,
            new_fpr=0.5,
            current_precision=0.9,
            current_recall=0.9,
        )
        assert not result.passed
        # Should mention both precision and recall regression
        assert "precision_regression" in result.reason
        assert "recall_regression" in result.reason
        assert "fpr_ceiling" in result.reason

    def test_checks_detail(self):
        """Each check includes detailed breakdown."""
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
            current_precision=0.90,
            current_recall=0.82,
        )
        assert "precision" in result.checks
        assert "recall" in result.checks
        assert "fpr" in result.checks
        assert result.checks["precision"]["passed"] is True

# ═══════════════════════════════════════════════════════════════════════
# Q2-PIPELINE: Retrain Pipeline Tests
# ═══════════════════════════════════════════════════════════════════════

class TestRetrainPipeline:
    """Test the full retrain orchestration."""

    def _make_pipeline(self):
        """Helper to create a RetrainPipeline with temp storage."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)
        scheduler = RetrainScheduler()
        pipeline = RetrainPipeline(registry, loader, scheduler)
        return pipeline, scheduler, loader

    def test_retrain_success(self):
        """Full retrain cycle succeeds with synthetic data."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain

        scheduler.record_labels("t1", count=cfg.min_new_labels)
        result = pipeline.retrain("t1")

        assert result.success
        assert result.version is not None
        assert result.quality_result is not None
        assert result.quality_result["passed"] is True
        assert result.training_time_seconds > 0
        assert result.reason == "retrain_successful"

    def test_retrain_updates_scheduler(self):
        """Successful retrain resets scheduler label count."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain

        scheduler.record_labels("t1", count=cfg.min_new_labels)
        pipeline.retrain("t1")

        status = scheduler.get_status("t1")
        assert status["new_labels"] == 0
        assert status["is_retraining"] is False

    def test_retrain_updates_loader_metadata(self):
        """Successful retrain updates tenant metadata in ModelLoader."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain

        scheduler.record_labels("t1", count=cfg.min_new_labels)
        result = pipeline.retrain("t1")

        assert result.success
        # Fusion weights should now reflect tenant data
        w = loader.get_fusion_weights("t1")
        assert w.tenant_samples > 0

    def test_retrain_result_to_dict(self):
        """RetrainResult.to_dict() returns expected structure."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        result = pipeline.retrain("t1")

        d = result.to_dict()
        assert "success" in d
        assert "tenant_id" in d
        assert "version" in d
        assert "quality_result" in d

    def test_retrain_with_provided_data(self):
        """Retrain with pre-loaded data succeeds."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)

        rng = np.random.RandomState(42)
        X = rng.randn(2000, 30) * 0.3
        y = np.zeros(2000, dtype=np.int64)
        y[-200:] = rng.randint(1, 8, size=200)

        result = pipeline.retrain("t1", X=X, y=y)
        assert result.success

    def test_retrain_preserves_labels_on_failure(self):
        """Failed retrain preserves labels for retry."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)

        # Patch training to fail
        with patch.object(
            pipeline._training_pipeline,
            "train_all",
            side_effect=RuntimeError("training error"),
        ):
            result = pipeline.retrain("t1")

        assert not result.success
        assert "exception" in result.reason
        status = scheduler.get_status("t1")
        assert status["new_labels"] == cfg.min_new_labels  # Preserved

    def test_process_all_pending(self):
        """process_all_pending() retrains all eligible tenants."""
        pipeline, scheduler, loader = self._make_pipeline()
        cfg = get_ml_config().auto_retrain

        scheduler.record_labels("t1", count=cfg.min_new_labels)
        scheduler.record_labels("t2", count=cfg.min_new_labels)
        scheduler.record_labels("t3", count=5)  # Below threshold

        results = pipeline.process_all_pending()
        successful = [r.tenant_id for r in results if r.success]
        assert "t1" in successful
        assert "t2" in successful
        # t3 should not be retrained
        assert "t3" not in [r.tenant_id for r in results]

# ═══════════════════════════════════════════════════════════════════════
# Q2-WORKER: Background Worker Tests
# ═══════════════════════════════════════════════════════════════════════

class TestRetrainWorker:
    """Test the background retrain worker."""

    def test_worker_stats(self):
        """Worker reports correct stats."""
        pipeline = MagicMock(spec=RetrainPipeline)
        scheduler = RetrainScheduler()
        worker = RetrainWorker(pipeline, scheduler)

        stats = worker.stats
        assert stats["running"] is False
        assert stats["retrains_completed"] == 0
        assert stats["retrains_failed"] == 0

    def test_worker_stop(self):
        """Worker stop() sets running flag to False."""
        pipeline = MagicMock(spec=RetrainPipeline)
        scheduler = RetrainScheduler()
        worker = RetrainWorker(pipeline, scheduler)
        worker._running = True
        worker.stop()
        assert not worker.is_running

    @pytest.mark.asyncio
    async def test_worker_run_and_stop(self):
        """Worker runs and stops cleanly."""
        pipeline = MagicMock(spec=RetrainPipeline)
        scheduler = RetrainScheduler()
        scheduler.enabled = False  # Prevent actual retrains

        worker = RetrainWorker(pipeline, scheduler)

        # Override check interval for fast testing
        worker._cfg = MagicMock()
        worker._cfg.check_interval_seconds = 0.01
        worker._cfg.enabled = False

        task = asyncio.create_task(worker.run())
        await asyncio.sleep(0.05)
        worker.stop()

        # Wait for task to complete
        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1.0)

        assert not worker.is_running

# ═══════════════════════════════════════════════════════════════════════
# Q2-INTEGRATION: End-to-End Integration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestQ2Integration:
    """End-to-end Q2 auto-retrain integration tests."""

    def test_full_lifecycle(self):
        """Full Q2 lifecycle: labels → trigger → retrain → deploy."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)
        scheduler = RetrainScheduler()
        pipeline = RetrainPipeline(registry, loader, scheduler)

        # Step 1: Record labels over time
        cfg = get_ml_config().auto_retrain
        for _ in range(cfg.min_new_labels):
            scheduler.record_labels("tenant_a", count=1)

        # Step 2: Check triggers
        triggers = scheduler.check_all()
        assert len(triggers) == 1
        assert triggers[0].tenant_id == "tenant_a"
        assert triggers[0].should_retrain

        # Step 3: Retrain
        result = pipeline.retrain_from_trigger(triggers[0])
        assert result.success
        assert result.version is not None

        # Step 4: Verify model is deployed
        versions = loader.loaded_versions()
        assert "tenant_a" in versions

        # Step 5: Verify scheduler state is reset
        status = scheduler.get_status("tenant_a")
        assert status["new_labels"] == 0
        assert status["last_retrain"] is not None

    def test_retrain_then_global_fusion(self):
        """After retrain, tenant model blends with global model."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)
        scheduler = RetrainScheduler()
        pipeline = RetrainPipeline(registry, loader, scheduler)

        # Train global model first
        manager.train_and_register()

        # Generate proper multi-class training data so tenant achieves
        # reasonable precision (default synthetic data is single-class)
        gen = GlobalSyntheticGenerator(random_state=99)
        X, y, names = gen.generate(n_samples=5000)

        # Retrain tenant with proper data
        cfg = get_ml_config().auto_retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        result = pipeline.retrain("t1", X=X, y=y, feature_names=names)
        assert result.success

        # Override precision to exceed min_tenant_precision (0.70) so fusion
        # actually blends.  The retrain recorded the real precision which may
        # be low with reduced test data — that's fine; this test validates
        # the fusion wiring, not model quality.
        loader.update_tenant_metadata("t1", precision=0.90)

        # Fusion weights should reflect tenant data
        w = loader.get_fusion_weights("t1")
        assert w.tenant_samples > 0
        assert w.tenant_weight > 0  # Tenant model contributes

    def test_multiple_retrains_accumulate(self):
        """Multiple retrains increase tenant training samples."""
        tmp = tempfile.mkdtemp()
        registry = ModelRegistry(base_dir=tmp)
        manager = GlobalModelManager(registry)
        loader = ModelLoader(registry=registry, global_manager=manager)
        scheduler = RetrainScheduler()
        pipeline = RetrainPipeline(registry, loader, scheduler)

        cfg = get_ml_config().auto_retrain

        # First retrain
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        r1 = pipeline.retrain("t1")
        assert r1.success
        loader.get_fusion_weights("t1")

        # Force reset rate limit for testing
        scheduler._last_retrain_time["t1"] = 0

        # Second retrain (more labels)
        scheduler.record_labels("t1", count=cfg.min_new_labels)
        r2 = pipeline.retrain("t1")
        assert r2.success
        # Tenant samples should have been updated
        w2 = loader.get_fusion_weights("t1")
        assert w2.tenant_samples > 0

# ═══════════════════════════════════════════════════════════════════════
# Q2 Hardening Tests ( audit)
# ═══════════════════════════════════════════════════════════════════════

class TestSchedulerThreadSafety:
    """BUG-02: check() must hold the lock to prevent data races."""

    def test_check_under_concurrent_record_labels(self):
        """check() and record_labels() should not race."""
        import threading

        scheduler = RetrainScheduler()

        errors = []

        def record_loop():
            try:
                for _ in range(100):
                    scheduler.record_labels("t1", count=1)
            except Exception as e:
                errors.append(e)

        def check_loop():
            try:
                for _ in range(100):
                    scheduler.check("t1")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=record_loop),
            threading.Thread(target=check_loop),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Race condition errors: {errors}"

class TestSchedulerLabelCap:
    """SEC-07: record_labels must cap per-call count."""

    def test_huge_label_count_capped(self):
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=10**18)
        status = scheduler.get_status("t1")
        assert status["new_labels"] <= scheduler._MAX_LABEL_BATCH
        assert status["total_labels"] <= scheduler._MAX_LABEL_BATCH

    def test_has_max_label_batch_constant(self):
        scheduler = RetrainScheduler()
        assert hasattr(scheduler, "_MAX_LABEL_BATCH")
        assert scheduler._MAX_LABEL_BATCH > 0

class TestSchedulerTenantEviction:
    """SEC-04: scheduler must evict dormant tenants at capacity."""

    def test_has_max_tracked_tenants(self):
        scheduler = RetrainScheduler()
        assert hasattr(scheduler, "_MAX_TRACKED_TENANTS")
        assert scheduler._MAX_TRACKED_TENANTS > 0

    def test_evicts_when_at_capacity(self):
        scheduler = RetrainScheduler()
        old_max = scheduler._MAX_TRACKED_TENANTS
        scheduler._MAX_TRACKED_TENANTS = 5
        try:
            for i in range(10):
                scheduler.record_labels(f"tenant_{i}", count=1)
            # Should not exceed cap + small margin
            assert len(scheduler._new_label_counts) <= 6
        finally:
            scheduler._MAX_TRACKED_TENANTS = old_max

class TestSchedulerGetStatusLock:
    """get_status() should hold the lock for consistent reads."""

    def test_get_status_returns_dict(self):
        scheduler = RetrainScheduler()
        scheduler.record_labels("t1", count=5)
        status = scheduler.get_status("t1")
        assert status["new_labels"] == 5
        assert status["total_labels"] == 5
        assert status["enabled"] is True

class TestQualityGateInputValidation:
    """BUG-06: metric values must be clamped to [0, 1]."""

    def test_negative_precision_clamped(self):
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=-0.5,
            new_recall=0.8,
            new_fpr=0.05,
        )
        # Should not crash; precision clamped to 0.0
        assert isinstance(result, QualityResult)
        assert result.checks["precision"]["new"] == 0.0

    def test_fpr_above_one_clamped(self):
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.9,
            new_recall=0.8,
            new_fpr=2.0,
        )
        # FPR clamped to 1.0
        assert result.checks["fpr"]["new"] == 1.0

    def test_normal_values_unaffected(self):
        gate = QualityGate()
        result = gate.evaluate(
            new_precision=0.92,
            new_recall=0.85,
            new_fpr=0.03,
        )
        assert result.passed
        assert result.checks["precision"]["new"] == 0.92

class TestWorkerEventLoop:
    """BUG-03: worker must use get_running_loop(), not get_event_loop()."""

    def test_worker_source_uses_running_loop(self):
        import inspect

        from ml.retrain.worker import RetrainWorker

        src = inspect.getsource(RetrainWorker)
        assert "get_running_loop" in src
        assert "get_event_loop" not in src
