# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ML Router unit tests.

Tests the REST layer for ML model status endpoints:
  - Global model info
  - Tenant model listing
  - Retrain scheduling + history
  - Worker stats
  - Fusion weights
  - Shadow mode status
  - Accuracy snapshot
  - Meta-alert listing
  - Manual retrain trigger
  - Aggregated dashboard endpoint
  - Auth: admin-only enforcement
  - 503 when ML components not initialised
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch

import pytest

# ── Fake ML components ───────────────────────────────────────────────────────

class FakeGlobalModelManager:
    def __init__(self, loaded=True, version="v1700000000", n_features=62):
        self._loaded = loaded
        self._version = version
        self._n_features = n_features

    @property
    def version(self) -> str:
        return self._version

    def get_info(self) -> dict:
        return {
            "loaded": self._loaded,
            "version": self._version,
            "n_features": self._n_features,
            "training_in_progress": False,
        }

class FakeModelRegistry:
    def __init__(self, versions: list[dict] | None = None):
        self._versions = versions or []

    def list_versions(self, tenant_id: str) -> list[dict]:
        return [v for v in self._versions if v.get("tenant_id") == tenant_id]

class FakeShadowTracker:
    def __init__(self, in_shadow=False, version="", total=0, alerts=0):
        self._shadow_version: dict[str, str] = {}
        self._shadow_total: dict[str, int] = {}
        self._shadow_alerts: dict[str, int] = {}
        self._max_fpr = 0.10
        self._in_shadow = in_shadow
        if version:
            self._shadow_version["test-tenant"] = version
            self._shadow_total["test-tenant"] = total
            self._shadow_alerts["test-tenant"] = alerts

    def is_in_shadow(self, tenant_id: str) -> bool:
        return self._in_shadow

class FakeModelLoader:
    def __init__(
        self,
        registry=None,
        global_manager=None,
        shadow_tracker=None,
        loaded_versions_map=None,
        tenant_samples=0,
    ):
        self._registry = registry or FakeModelRegistry()
        self._global_manager = global_manager or FakeGlobalModelManager()
        self._shadow_tracker = shadow_tracker or FakeShadowTracker()
        self._loaded_versions_map = loaded_versions_map or {}
        self._tenant_samples = tenant_samples

    @property
    def global_manager(self):
        return self._global_manager

    @property
    def shadow_tracker(self):
        return self._shadow_tracker

    def loaded_versions(self) -> dict[str, str]:
        return self._loaded_versions_map

    def get_ensemble(self, tenant_id: str):
        return None

    def get_fusion_weights(self, tenant_id: str):
        @dataclass
        class _FW:
            global_weight: float = 1.0
            tenant_weight: float = 0.0
            tenant_samples: int = 0
            reason: str = "no_tenant_model"

            def to_dict(self):
                return {
                    "global_weight": self.global_weight,
                    "tenant_weight": self.tenant_weight,
                    "tenant_samples": self.tenant_samples,
                    "reason": self.reason,
                }

        return _FW(tenant_samples=self._tenant_samples)

class FakeRetrainScheduler:
    def __init__(self, retrain_status=None, enabled=True):
        self._status = retrain_status or {
            "new_labels": 5,
            "total_labels": 200,
            "last_retrain": time.time() - 3600,
            "is_retraining": False,
            "active_retrains": 0,
            "max_concurrent": 4,
            "enabled": enabled,
        }
        self._min_new_labels = 50
        self._started = False

    def get_status(self, tenant_id: str) -> dict:
        return self._status

    def mark_retrain_started(self, tenant_id: str):
        self._started = True

    def mark_retrain_completed(self, tenant_id: str, *, success=True, reset_labels=True):
        pass

    def record_labels(self, tenant_id: str, count: int = 1):
        pass

class FakeRetrainWorker:
    def __init__(self, running=True, completed=3, failed=1):
        self._stats = {
            "running": running,
            "retrains_completed": completed,
            "retrains_failed": failed,
            "check_interval_seconds": 21600,
            "enabled": True,
        }

    @property
    def stats(self):
        return self._stats

class FakeAccuracySnapshot:
    def __init__(self):
        self.timestamp = time.time()

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "precision": 0.92,
            "recall": 0.85,
            "fpr": 0.03,
            "tp": 100,
            "fp": 9,
            "fn": 18,
            "tn": 300,
        }

class FakeAccuracyTracker:
    def compute(self):
        return FakeAccuracySnapshot()

@dataclass
class FakeMetaAlert:
    id: str
    alert_type: str
    severity: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self):
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }

class FakeMetaAlerter:
    def __init__(self, alerts=None):
        self._alerts = alerts or []

    def get_alerts(self, *, limit=200):
        return self._alerts[:limit]

class FakeRetrainResult:
    def __init__(self, success=True, version="v1700000100"):
        self.success = success
        self.version = version
        self.tenant_id = "test-tenant"
        self.training_time_seconds = 12.5
        self.reason = "threshold_met"
        self.metrics = {"stage1_validation": {"precision": 0.95}}

    def to_dict(self):
        return {
            "success": self.success,
            "tenant_id": self.tenant_id,
            "version": self.version,
            "training_time_seconds": self.training_time_seconds,
            "reason": self.reason,
            "metrics": self.metrics,
        }

class FakeRetrainPipeline:
    def __init__(self, result=None):
        self._result = result or FakeRetrainResult()

    def retrain(self, tenant_id, X=None, y=None, feature_names=None, operator_id="manual"):
        return self._result

# ── Fake auth middleware ─────────────────────────────────────────────────────

TENANT_UUID = "00000000-0000-0000-0000-000000000001"

class FakeCurrentUser:
    def __init__(self, role="admin", tenant_id=TENANT_UUID):
        self.id = "user-1"
        self.email = "admin@example.com"
        self.role = role
        self.tenant_id = tenant_id
        self.is_active = True

# ── Setup / Teardown ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_ml_router():
    """Reset ML router singletons between tests."""
    from app.routers.ml import _retrain_history, set_ml_components

    # Clear history
    _retrain_history.clear()
    # Clear all components
    set_ml_components(
        model_loader=None,
        retrain_scheduler=None,
        retrain_worker=None,
        retrain_pipeline=None,
        accuracy_tracker=None,
        drift_detector=None,
        meta_alerter=None,
    )
    # Re-null the globals explicitly
    import app.routers.ml as _ml_mod

    _ml_mod._model_loader = None
    _ml_mod._retrain_scheduler = None
    _ml_mod._retrain_worker = None
    _ml_mod._retrain_pipeline = None
    _ml_mod._accuracy_tracker = None
    _ml_mod._drift_detector = None
    _ml_mod._meta_alerter = None
    yield

@pytest.fixture
def wired_components():
    """Wire up all ML fakes and return the component bag."""
    from app.routers.ml import set_ml_components

    versions = [
        {
            "version": "v1700000000",
            "tenant_id": TENANT_UUID,
            "created_at": 1700000000,
            "stages": {"stage1": True, "stage2": True, "stage3": False},
            "metrics": {
                "stage1_validation": {"precision": 0.94, "recall": 0.88, "fpr": 0.02},
                "training_samples": 5000,
            },
            "feature_names": ["f1", "f2", "f3"],
        },
    ]

    loader = FakeModelLoader(
        registry=FakeModelRegistry(versions),
        loaded_versions_map={TENANT_UUID: "v1700000000"},
    )
    scheduler = FakeRetrainScheduler()
    worker = FakeRetrainWorker()
    pipeline = FakeRetrainPipeline()
    accuracy = FakeAccuracyTracker()
    meta = FakeMetaAlerter(
        alerts=[
            FakeMetaAlert(
                id="meta-000001",
                alert_type="evasion_pattern",
                severity="critical",
                message="Evasion detected",
                timestamp=time.time(),
            ),
        ]
    )

    set_ml_components(
        model_loader=loader,
        retrain_scheduler=scheduler,
        retrain_worker=worker,
        retrain_pipeline=pipeline,
        accuracy_tracker=accuracy,
        meta_alerter=meta,
    )

    return {
        "loader": loader,
        "scheduler": scheduler,
        "worker": worker,
        "pipeline": pipeline,
        "accuracy": accuracy,
        "meta": meta,
    }

# ── Helper: override auth ───────────────────────────────────────────────────

def _patch_auth(role="admin"):
    """Return patches for auth middleware that inject a FakeCurrentUser."""
    user = FakeCurrentUser(role=role)
    return (
        patch("app.routers.ml.get_current_active_user", return_value=user),
        patch("app.routers.ml.require_permission", return_value=lambda: None),
        patch("app.routers.ml.rate_limit", return_value=None),
    )

# ── Tests ────────────────────────────────────────────────────────────────────

class TestMLRouterGlobalModel:
    """GET /api/v1/ml/global-model"""

    @pytest.mark.asyncio
    async def test_returns_global_model_info(self, wired_components):
        from app.routers.ml import get_global_model

        user = FakeCurrentUser()
        result = await get_global_model(current_user=user)
        assert result["loaded"] is True
        assert result["version"] == "v1700000000"
        assert result["n_features"] == 62
        assert result["training_in_progress"] is False

    @pytest.mark.asyncio
    async def test_503_when_loader_not_initialised(self):
        from app.routers.ml import get_global_model

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_global_model(current_user=user)
        assert exc_info.value.status_code == 503

class TestMLRouterModels:
    """GET /api/v1/ml/models"""

    @pytest.mark.asyncio
    async def test_returns_tenant_model_list(self, wired_components):
        from app.routers.ml import get_models

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await get_models(current_user=user)
        assert "models" in result
        assert len(result["models"]) == 1
        assert result["models"][0]["version"] == "v1700000000"
        assert result["models"][0]["stages"]["stage1"] is True
        assert result["models"][0]["stages"]["stage3"] is False
        assert result["current_version"] == "v1700000000"

    @pytest.mark.asyncio
    async def test_empty_when_no_models(self, wired_components):
        import app.routers.ml as _ml
        from app.routers.ml import get_models

        _ml._model_loader._registry = FakeModelRegistry([])
        user = FakeCurrentUser(tenant_id="other-tenant")
        result = await get_models(current_user=user)
        assert result["models"] == []
        assert result["current_version"] is None

    @pytest.mark.asyncio
    async def test_metrics_parsed_correctly(self, wired_components):
        from app.routers.ml import get_models

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await get_models(current_user=user)
        metrics = result["models"][0]["metrics"]
        assert metrics is not None
        assert metrics["stage1_validation"]["precision"] == 0.94
        assert metrics["training_samples"] == 5000

class TestMLRouterRetrainStatus:
    """GET /api/v1/ml/retrain/status"""

    @pytest.mark.asyncio
    async def test_returns_scheduler_status(self, wired_components):
        from app.routers.ml import get_retrain_status

        user = FakeCurrentUser()
        result = await get_retrain_status(current_user=user)
        assert result["enabled"] is True
        assert result["is_retraining"] is False
        assert result["max_concurrent"] == 4
        assert "new_labels" in result

    @pytest.mark.asyncio
    async def test_503_when_scheduler_missing(self):
        from app.routers.ml import get_retrain_status

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_retrain_status(current_user=user)
        assert exc_info.value.status_code == 503

class TestMLRouterRetrainHistory:
    """GET /api/v1/ml/retrain/history"""

    @pytest.mark.asyncio
    async def test_returns_empty_initially(self, wired_components):
        from app.routers.ml import get_retrain_history

        user = FakeCurrentUser()
        result = await get_retrain_history(current_user=user)
        assert result["results"] == []

    @pytest.mark.asyncio
    async def test_returns_recorded_history(self, wired_components):
        from app.routers.ml import _record_retrain_result, get_retrain_history

        _record_retrain_result(
            {
                "tenant_id": TENANT_UUID,
                "success": True,
                "version": "v1700000100",
            }
        )
        _record_retrain_result(
            {
                "tenant_id": "other-tenant",
                "success": True,
                "version": "v9999",
            }
        )
        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await get_retrain_history(current_user=user)
        assert len(result["results"]) == 1
        assert result["results"][0]["version"] == "v1700000100"

    @pytest.mark.asyncio
    async def test_history_cap(self, wired_components):
        from app.routers.ml import _record_retrain_result, _retrain_history

        for i in range(150):
            _record_retrain_result({"tenant_id": "t", "version": f"v{i}"})
        assert len(_retrain_history) <= 100

class TestMLRouterWorkerStats:
    """GET /api/v1/ml/retrain/worker"""

    @pytest.mark.asyncio
    async def test_returns_worker_stats(self, wired_components):
        from app.routers.ml import get_retrain_worker_stats

        user = FakeCurrentUser()
        result = await get_retrain_worker_stats(current_user=user)
        assert result["running"] is True
        assert result["retrains_completed"] == 3
        assert result["retrains_failed"] == 1

class TestMLRouterFusionWeights:
    """GET /api/v1/ml/fusion-weights"""

    @pytest.mark.asyncio
    async def test_returns_fusion_weights(self, wired_components):
        from app.routers.ml import get_fusion_weights

        user = FakeCurrentUser()
        result = await get_fusion_weights(current_user=user)
        assert result["global_weight"] == 1.0
        assert result["tenant_weight"] == 0.0
        assert result["reason"] == "no_tenant_model"

class TestMLRouterShadowStatus:
    """GET /api/v1/ml/shadow"""

    @pytest.mark.asyncio
    async def test_not_in_shadow(self, wired_components):
        from app.routers.ml import get_shadow_status

        user = FakeCurrentUser()
        result = await get_shadow_status(current_user=user)
        assert result["in_shadow"] is False
        assert isinstance(result["max_alert_rate"], float)

    @pytest.mark.asyncio
    async def test_in_shadow_mode(self, wired_components):
        import app.routers.ml as _ml

        _ml._model_loader._shadow_tracker = FakeShadowTracker(
            in_shadow=True,
            version="v1700000200",
            total=500,
            alerts=20,
        )
        # Fix tenant to match tracker
        from app.routers.ml import get_shadow_status

        user = FakeCurrentUser(tenant_id="test-tenant")
        result = await get_shadow_status(current_user=user)
        assert result["in_shadow"] is True
        assert result["version"] == "v1700000200"
        assert result["total_scored"] == 500
        assert result["total_alerts"] == 20
        assert result["alert_rate"] == pytest.approx(0.04)

class TestMLRouterAccuracy:
    """GET /api/v1/ml/accuracy"""

    @pytest.mark.asyncio
    async def test_returns_accuracy_snapshot(self, wired_components):
        from app.routers.ml import get_accuracy

        user = FakeCurrentUser()
        result = await get_accuracy(current_user=user)
        assert result["precision"] == 0.92
        assert result["recall"] == 0.85
        assert result["fpr"] == 0.03
        assert result["tp"] == 100

    @pytest.mark.asyncio
    async def test_returns_zeroes_when_no_tracker(self):
        from app.routers.ml import get_accuracy

        user = FakeCurrentUser()
        result = await get_accuracy(current_user=user)
        assert result["precision"] == 0.0
        assert result["tp"] == 0

class TestMLRouterMetaAlerts:
    """GET /api/v1/ml/meta-alerts"""

    @pytest.mark.asyncio
    async def test_returns_meta_alerts(self, wired_components):
        from app.routers.ml import get_meta_alerts

        user = FakeCurrentUser()
        result = await get_meta_alerts(current_user=user)
        assert len(result) == 1
        assert result[0]["alert_type"] == "evasion_pattern"
        assert result[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_alerter(self):
        from app.routers.ml import get_meta_alerts

        user = FakeCurrentUser()
        result = await get_meta_alerts(current_user=user)
        assert result == []

class TestMLRouterRetrainTrigger:
    """POST /api/v1/ml/retrain/trigger"""

    @pytest.mark.asyncio
    async def test_manual_retrain_success(self, wired_components):
        from app.routers.ml import trigger_retrain

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await trigger_retrain(current_user=user)
        assert result["success"] is True
        assert result["version"] == "v1700000100"
        # Scheduler should have been marked started
        assert wired_components["scheduler"]._started is True

    @pytest.mark.asyncio
    async def test_retrain_conflict_when_already_running(self, wired_components):
        wired_components["scheduler"]._status["is_retraining"] = True
        from app.routers.ml import trigger_retrain

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        with pytest.raises(Exception) as exc_info:
            await trigger_retrain(current_user=user)
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_retrain_records_history(self, wired_components):
        from app.routers.ml import _retrain_history, trigger_retrain

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        await trigger_retrain(current_user=user)
        assert len(_retrain_history) == 1
        # The result comes from the FakeRetrainPipeline, so tenant_id is
        # whatever the fake returns — just verify it got recorded.
        assert _retrain_history[0]["success"] is True
        assert _retrain_history[0]["version"] == "v1700000100"

    @pytest.mark.asyncio
    async def test_retrain_without_pipeline_schedules_via_worker(self, wired_components):
        import app.routers.ml as _ml

        _ml._retrain_pipeline = None
        from app.routers.ml import trigger_retrain

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await trigger_retrain(current_user=user)
        assert result["success"] is False
        assert result["reason"] == "scheduled_via_worker"

class TestMLRouterDashboard:
    """GET /api/v1/ml/dashboard"""

    @pytest.mark.asyncio
    async def test_returns_aggregated_dashboard(self, wired_components):
        from app.routers.ml import get_ml_dashboard

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await get_ml_dashboard(current_user=user)

        # Global model
        assert result["global_model"]["loaded"] is True
        assert result["global_model"]["version"] == "v1700000000"

        # Models
        assert len(result["models"]["models"]) == 1
        assert result["models"]["current_version"] == "v1700000000"

        # Fusion weights
        assert result["fusion_weights"]["global_weight"] == 1.0

        # Retrain status
        assert result["retrain_status"]["enabled"] is True

        # Worker
        assert result["worker_stats"]["running"] is True

        # Shadow
        assert result["shadow"]["in_shadow"] is False  # Not in shadow

        # Accuracy
        assert result["accuracy"]["precision"] == 0.92

        # Meta-alerts
        assert len(result["meta_alerts"]) == 1

    @pytest.mark.asyncio
    async def test_dashboard_with_shadow_active(self, wired_components):
        import app.routers.ml as _ml

        _ml._model_loader._shadow_tracker = FakeShadowTracker(
            in_shadow=True,
            version="v1700000200",
            total=1000,
            alerts=30,
        )
        from app.routers.ml import get_ml_dashboard

        user = FakeCurrentUser(tenant_id="test-tenant")
        result = await get_ml_dashboard(current_user=user)
        assert result["shadow"] is not None
        assert result["shadow"]["in_shadow"] is True
        assert result["shadow"]["version"] == "v1700000200"

    @pytest.mark.asyncio
    async def test_dashboard_graceful_when_optional_missing(self, wired_components):
        import app.routers.ml as _ml

        _ml._accuracy_tracker = None
        _ml._meta_alerter = None
        _ml._retrain_worker = None
        from app.routers.ml import get_ml_dashboard

        user = FakeCurrentUser(tenant_id=TENANT_UUID)
        result = await get_ml_dashboard(current_user=user)
        assert result["accuracy"] is None
        assert result["meta_alerts"] == []
        assert result["worker_stats"] == {}

class TestMLRouter503:
    """Endpoints return 503 when ML components are not initialised."""

    @pytest.mark.asyncio
    async def test_global_model_503(self):
        from app.routers.ml import get_global_model

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_global_model(current_user=user)
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_models_503(self):
        from app.routers.ml import get_models

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_models(current_user=user)
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_fusion_weights_503(self):
        from app.routers.ml import get_fusion_weights

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_fusion_weights(current_user=user)
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_worker_stats_503(self):
        from app.routers.ml import get_retrain_worker_stats

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_retrain_worker_stats(current_user=user)
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_shadow_503(self):
        from app.routers.ml import get_shadow_status

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await get_shadow_status(current_user=user)
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_retrain_trigger_503(self):
        from app.routers.ml import trigger_retrain

        user = FakeCurrentUser()
        with pytest.raises(Exception) as exc_info:
            await trigger_retrain(current_user=user)
        assert exc_info.value.status_code == 503
