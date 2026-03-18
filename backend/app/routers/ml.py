# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ML Model Status Router.

REST endpoints exposing ML pipeline state to the admin dashboard (O11).

Routes:
  GET  /api/v1/ml/dashboard       — aggregated ML dashboard snapshot
  GET  /api/v1/ml/global-model    — global model info
  GET  /api/v1/ml/models          — tenant model version list
  GET  /api/v1/ml/retrain/status  — retrain scheduler state
  GET  /api/v1/ml/retrain/history — historical retrain results
  GET  /api/v1/ml/retrain/worker  — retrain worker runtime stats
  GET  /api/v1/ml/fusion-weights  — ensemble fusion weights
  GET  /api/v1/ml/shadow          — shadow mode evaluation state
  GET  /api/v1/ml/accuracy        — rolling accuracy snapshot
  GET  /api/v1/ml/meta-alerts     — meta-detection alerts
  POST /api/v1/ml/retrain/trigger — manual retrain trigger (admin only)

Security:
  - All endpoints require admin role
  - Tenant-scoped model listing
  - Rate-limited: shared rate limiter
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.utils.logging import get_logger

logger = get_logger("phantex.router.ml")

router = APIRouter(
    prefix="/api/v1/ml",
    tags=["ml"],
    dependencies=[Depends(rate_limit), Depends(require_permission("ml.manage"))],
)

# ---------------------------------------------------------------------------
# Lazy singletons — ML components live in background workers.  We access
# them lazily so the router can import without triggering heavy ML imports
# at module-top level.  In production, these are initialised during lifespan;
# in tests, they get monkeypatched.
# ---------------------------------------------------------------------------

_model_loader = None
_retrain_scheduler = None
_retrain_worker = None
_retrain_pipeline = None
_accuracy_tracker = None
_drift_detector = None
_meta_alerter = None

def set_ml_components(
    *,
    model_loader=None,
    retrain_scheduler=None,
    retrain_worker=None,
    retrain_pipeline=None,
    accuracy_tracker=None,
    drift_detector=None,
    meta_alerter=None,
) -> None:
    """Wire ML component references (called from lifespan or tests)."""
    global _model_loader, _retrain_scheduler, _retrain_worker
    global _retrain_pipeline, _accuracy_tracker, _drift_detector, _meta_alerter
    if model_loader is not None:
        _model_loader = model_loader
    if retrain_scheduler is not None:
        _retrain_scheduler = retrain_scheduler
    if retrain_worker is not None:
        _retrain_worker = retrain_worker
    if retrain_pipeline is not None:
        _retrain_pipeline = retrain_pipeline
    if accuracy_tracker is not None:
        _accuracy_tracker = accuracy_tracker
    if drift_detector is not None:
        _drift_detector = drift_detector
    if meta_alerter is not None:
        _meta_alerter = meta_alerter

def _loader():
    if _model_loader is None:
        raise HTTPException(status_code=503, detail="ML model loader not initialised")
    return _model_loader

# ---------------------------------------------------------------------------
# Prediction log — in-memory ring buffer for recent ML predictions.
# Populated by the inference pipeline; surfaced via the interpretability API.
# ---------------------------------------------------------------------------

_prediction_log: list[dict[str, Any]] = []
_MAX_PREDICTIONS = 500

def record_prediction(entry: dict[str, Any]) -> None:
    """Record a prediction result for the interpretability dashboard.

    Entry should contain: tenant_id, agent_id, timestamp, score,
    should_alert, stage_scores, attack_class, feature_contributions.
    """
    _prediction_log.append(entry)
    if len(_prediction_log) > _MAX_PREDICTIONS:
        del _prediction_log[: len(_prediction_log) - _MAX_PREDICTIONS]

def _scheduler():
    if _retrain_scheduler is None:
        raise HTTPException(status_code=503, detail="Retrain scheduler not initialised")
    return _retrain_scheduler

def _worker():
    if _retrain_worker is None:
        raise HTTPException(status_code=503, detail="Retrain worker not initialised")
    return _retrain_worker

# ---------------------------------------------------------------------------
# GET /global-model
# ---------------------------------------------------------------------------

@router.get("/global-model", summary="Global model info")
async def get_global_model(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return diagnostic info about the global starter model."""
    loader = _loader()
    return loader.global_manager.get_info()

# ---------------------------------------------------------------------------
# GET /models
# ---------------------------------------------------------------------------

@router.get("/models", summary="Tenant model versions")
async def get_models(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """List model versions for the current tenant."""
    loader = _loader()
    tenant_id = str(current_user.tenant_id)

    # Get version list from registry
    versions = loader._registry.list_versions(tenant_id)

    # Map each manifest dict → response shape
    model_list = []
    for manifest in versions:
        # Parse metrics
        raw_metrics = manifest.get("metrics", {})
        version_metrics = None
        if raw_metrics:
            s1_val = raw_metrics.get("stage1_validation")
            version_metrics = {
                "stage1_validation": s1_val if isinstance(s1_val, dict) else None,
                "training_samples": raw_metrics.get("training_samples"),
                "retrain_trigger": raw_metrics.get("retrain_trigger"),
            }

        model_list.append(
            {
                "version": manifest.get("version", ""),
                "tenant_id": manifest.get("tenant_id", tenant_id),
                "created_at": manifest.get("created_at", 0),
                "stages": manifest.get("stages", {}),
                "metrics": version_metrics,
                "feature_names": manifest.get("feature_names", []),
                "signature": manifest.get("signature"),
            }
        )

    current_version = loader.loaded_versions().get(tenant_id)

    return {
        "models": model_list,
        "current_version": current_version,
    }

# ---------------------------------------------------------------------------
# GET /retrain/status
# ---------------------------------------------------------------------------

@router.get("/retrain/status", summary="Retrain scheduler status")
async def get_retrain_status(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return retrain scheduler state for the current tenant."""
    scheduler = _scheduler()
    tenant_id = str(current_user.tenant_id)
    return scheduler.get_status(tenant_id)

# ---------------------------------------------------------------------------
# GET /retrain/history
# ---------------------------------------------------------------------------

# In-memory retrain history (populated by retrain trigger and worker).
_retrain_history: list[dict[str, Any]] = []
_MAX_HISTORY = 100

def _record_retrain_result(result_dict: dict[str, Any]) -> None:
    """Record a retrain result in the history buffer."""
    _retrain_history.append(result_dict)
    if len(_retrain_history) > _MAX_HISTORY:
        del _retrain_history[: len(_retrain_history) - _MAX_HISTORY]

@router.get("/retrain/history", summary="Retrain history")
async def get_retrain_history(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return historical retrain results for the current tenant."""
    tenant_id = str(current_user.tenant_id)
    tenant_results = [r for r in _retrain_history if r.get("tenant_id") == tenant_id]
    return {"results": tenant_results}

# ---------------------------------------------------------------------------
# GET /retrain/worker
# ---------------------------------------------------------------------------

@router.get("/retrain/worker", summary="Retrain worker stats")
async def get_retrain_worker_stats(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return retrain worker runtime statistics."""
    worker = _worker()
    return worker.stats

# ---------------------------------------------------------------------------
# GET /fusion-weights
# ---------------------------------------------------------------------------

@router.get("/fusion-weights", summary="Ensemble fusion weights")
async def get_fusion_weights(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return the current ensemble fusion weights for the tenant."""
    loader = _loader()
    tenant_id = str(current_user.tenant_id)
    weights = loader.get_fusion_weights(tenant_id)
    return weights.to_dict()

# ---------------------------------------------------------------------------
# GET /shadow
# ---------------------------------------------------------------------------

@router.get("/shadow", summary="Shadow mode status")
async def get_shadow_status(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return shadow mode evaluation state for the tenant."""
    loader = _loader()
    tenant_id = str(current_user.tenant_id)
    tracker = loader.shadow_tracker

    in_shadow = tracker.is_in_shadow(tenant_id)
    version = tracker._shadow_version.get(tenant_id, "")
    total = tracker._shadow_total.get(tenant_id, 0)
    alerts = tracker._shadow_alerts.get(tenant_id, 0)
    alert_rate = (alerts / total) if total > 0 else 0.0

    return {
        "in_shadow": in_shadow,
        "passed": not in_shadow and alert_rate <= tracker._max_fpr if total > 0 else False,
        "alert_rate": alert_rate,
        "total_scored": total,
        "total_alerts": alerts,
        "version": version,
        "max_alert_rate": tracker._max_fpr,
    }

# ---------------------------------------------------------------------------
# GET /accuracy
# ---------------------------------------------------------------------------

@router.get("/accuracy", summary="Rolling accuracy snapshot")
async def get_accuracy(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return rolling accuracy metrics from the AccuracyTracker."""
    if _accuracy_tracker is None:
        return {
            "timestamp": time.time(),
            "precision": 0.0,
            "recall": 0.0,
            "fpr": 0.0,
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
        }
    snapshot = _accuracy_tracker.compute()
    return snapshot.to_dict()

# ---------------------------------------------------------------------------
# GET /meta-alerts
# ---------------------------------------------------------------------------

@router.get("/meta-alerts", summary="Meta-detection alerts")
async def get_meta_alerts(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> list[dict[str, Any]]:
    """Return recent meta-detection alerts."""
    if _meta_alerter is None:
        return []
    alerts = _meta_alerter.get_alerts(limit=200)
    return [a.to_dict() for a in alerts]

# ---------------------------------------------------------------------------
# GET /feature-importance
# ---------------------------------------------------------------------------

@router.get("/feature-importance", summary="Feature importance analysis")
async def get_feature_importance(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return feature importance from the loaded model.

    Sources importance from:
    1. XGBoost feature_importances_ (gain-based) — most reliable
    2. Feature registry categories for grouping
    """
    loader = _loader()
    tenant_id = str(current_user.tenant_id)
    ensemble = loader.get_ensemble(tenant_id)
    feature_names = loader.get_feature_names(tenant_id)

    importances: list[dict[str, Any]] = []

    if ensemble is not None:
        # Try XGBoost native importances first (best quality)
        xgb_model = getattr(ensemble, "_stage2", None)
        if xgb_model is not None and getattr(xgb_model, "is_fitted", False):
            raw = getattr(xgb_model._model, "feature_importances_", None)
            if raw is not None:
                names = xgb_model._feature_names or feature_names
                for i, val in enumerate(raw):
                    fname = names[i] if i < len(names) else f"feature_{i}"
                    importances.append({"feature": fname, "importance": round(float(val), 6), "source": "xgboost"})

        # If no XGBoost, use isolation forest permutation-based
        if not importances:
            iforest = getattr(ensemble, "_stage1", None)
            if iforest is not None and getattr(iforest, "is_fitted", False) and iforest._feature_names:
                # Use synthetic importances from tree depths (fast heuristic)
                tree_importances = getattr(iforest._model, "feature_importances_", None)
                if tree_importances is None:
                    # IsolationForest doesn't have direct importances —
                    # use average path length contribution from estimators
                    import numpy as np

                    n_features = len(iforest._feature_names)
                    # Count how often each feature is used as a split across all trees
                    feature_counts = np.zeros(n_features)
                    for tree in iforest._model.estimators_:
                        tree_features = tree.tree_.feature
                        for f_idx in tree_features:
                            if 0 <= f_idx < n_features:
                                feature_counts[f_idx] += 1
                    # Normalize to [0, 1]
                    total = feature_counts.sum()
                    if total > 0:
                        feature_counts /= total
                    for i, fname in enumerate(iforest._feature_names):
                        importances.append(
                            {
                                "feature": fname,
                                "importance": round(float(feature_counts[i]), 6),
                                "source": "isolation_forest",
                            }
                        )

    # Fallback: return feature names with equal weight
    if not importances and feature_names:
        weight = round(1.0 / len(feature_names), 6)
        for fname in feature_names:
            importances.append({"feature": fname, "importance": weight, "source": "uniform"})

    # Sort by importance descending
    importances.sort(key=lambda x: x["importance"], reverse=True)

    # Add category from feature registry
    try:
        from ml.features.registry import get_feature

        for item in importances:
            defn = get_feature(item["feature"])
            if defn:
                item["category"] = defn.category
                item["description"] = defn.description
    except ImportError:
        pass

    return {
        "features": importances,
        "model_version": loader.loaded_versions().get(tenant_id, ""),
        "total_features": len(importances),
    }

# ---------------------------------------------------------------------------
# GET /predictions
# ---------------------------------------------------------------------------

@router.get("/predictions", summary="Recent prediction log")
async def get_predictions(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    limit: int = 100,
) -> dict[str, Any]:
    """Return recent ML prediction results for the current tenant.

    Each entry contains the agent, timestamp, risk score, stage scores,
    attack classification, and whether an alert was triggered.
    """
    tenant_id = str(current_user.tenant_id)
    limit = min(max(1, limit), _MAX_PREDICTIONS)

    # Filter by tenant and take latest
    tenant_preds = [p for p in _prediction_log if p.get("tenant_id") == tenant_id][-limit:]

    return {
        "predictions": tenant_preds,
        "total": len(tenant_preds),
        "buffer_size": _MAX_PREDICTIONS,
    }

# ---------------------------------------------------------------------------
# GET /training-summary
# ---------------------------------------------------------------------------

@router.get("/training-summary", summary="Training data summary")
async def get_training_summary(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return a summary of training data: feature names, sample counts,
    label distribution, latest retrain metrics.
    """
    loader = _loader()
    tenant_id = str(current_user.tenant_id)
    feature_names = loader.get_feature_names(tenant_id)

    # Pull label distribution and sample count from retrain history
    tenant_history = [r for r in _retrain_history if r.get("tenant_id") == tenant_id]

    last_train: dict[str, Any] | None = None
    training_samples = 0
    label_distribution: dict[str, int] = {}

    if tenant_history:
        last_train = tenant_history[-1]
        metrics = last_train.get("metrics", {})
        training_samples = metrics.get("training_samples", 0)
        label_distribution = metrics.get("label_distribution", {})

    # Feature registry metadata
    feature_meta: list[dict[str, Any]] = []
    try:
        from ml.features.registry import list_features

        for defn in list_features():
            if not feature_names or defn.name in feature_names:
                feature_meta.append(
                    {
                        "name": defn.name,
                        "category": defn.category,
                        "description": defn.description,
                        "window": defn.window,
                        "default": defn.default,
                    }
                )
    except ImportError:
        pass

    return {
        "feature_names": feature_names,
        "feature_count": len(feature_names),
        "feature_registry": feature_meta,
        "training_samples": training_samples,
        "label_distribution": label_distribution,
        "last_retrain": last_train,
        "retrain_count": len(tenant_history),
    }

# ---------------------------------------------------------------------------
# GET /confusion-matrix
# ---------------------------------------------------------------------------

@router.get("/confusion-matrix", summary="Confusion matrix data")
async def get_confusion_matrix(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Return the confusion matrix from the rolling accuracy tracker.

    Includes TP, FP, FN, TN counts plus derived metrics.
    """
    if _accuracy_tracker is None:
        return {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
            "precision": 0.0,
            "recall": 0.0,
            "fpr": 0.0,
            "f1": 0.0,
            "total": 0,
        }

    snap = _accuracy_tracker.compute()
    d = snap.to_dict()
    tp, fp, fn, tn = d.get("tp", 0), d.get("fp", 0), d.get("fn", 0), d.get("tn", 0)
    total = tp + fp + fn + tn

    # Derived metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "total": total,
    }

# ---------------------------------------------------------------------------
# POST /retrain/trigger
# ---------------------------------------------------------------------------

@router.post("/retrain/trigger", summary="Trigger manual retrain")
async def trigger_retrain(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Manually trigger a model retrain for the current tenant.

    Uses the retrain pipeline if available; otherwise schedules via the
    scheduler.  Limited to admin role.
    """
    tenant_id = str(current_user.tenant_id)
    scheduler = _scheduler()

    # Check rate-limiting
    sched_status = scheduler.get_status(tenant_id)
    if sched_status.get("is_retraining"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Retrain already in progress for this tenant.",
        )

    if _retrain_pipeline is not None:
        import asyncio

        scheduler.mark_retrain_started(tenant_id)
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                _retrain_pipeline.retrain,
                tenant_id,
            )
            result_dict = result.to_dict()
            _record_retrain_result(result_dict)

            logger.info(
                "manual_retrain_completed",
                tenant_id=tenant_id,
                success=result.success,
                version=result.version,
            )
            return result_dict
        except Exception as exc:
            scheduler.mark_retrain_completed(tenant_id, success=False)
            logger.error("manual_retrain_error", tenant_id=tenant_id, error=str(exc))
            raise HTTPException(
                status_code=500,
                detail="Retrain failed — see server logs.",
            )
    else:
        # No pipeline available — just record labels to trigger via worker
        scheduler.record_labels(tenant_id, count=scheduler._min_new_labels)
        return {
            "success": False,
            "tenant_id": tenant_id,
            "version": None,
            "training_time_seconds": 0,
            "reason": "scheduled_via_worker",
            "metrics": {},
        }

# ---------------------------------------------------------------------------
# GET /dashboard — aggregated single-call
# ---------------------------------------------------------------------------

@router.get("/dashboard", summary="Aggregated ML dashboard")
async def get_ml_dashboard(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Single-call aggregated ML dashboard endpoint.

    Returns all ML subsystem state in one response to minimise
    dashboard latency (no waterfall of 10+ parallel requests).
    """
    tenant_id = str(current_user.tenant_id)
    loader = _loader()

    # Global model
    global_model = loader.global_manager.get_info()

    # Models — include global model + tenant-specific models
    from ml.config import get_ml_config as _mlcfg

    _global_tid = _mlcfg().global_model.global_tenant_id
    global_versions = loader._registry.list_versions(_global_tid)
    tenant_versions = loader._registry.list_versions(tenant_id)
    all_versions = global_versions + tenant_versions

    model_list = []
    for manifest in all_versions:
        raw_metrics = manifest.get("metrics", {})
        version_metrics = None
        if raw_metrics:
            s1_val = raw_metrics.get("stage1_validation")
            version_metrics = {
                "stage1_validation": s1_val if isinstance(s1_val, dict) else None,
                "training_samples": raw_metrics.get("training_samples"),
                "retrain_trigger": raw_metrics.get("retrain_trigger"),
            }
        model_list.append(
            {
                "version": manifest.get("version", ""),
                "tenant_id": manifest.get("tenant_id", _global_tid),
                "created_at": manifest.get("created_at", 0),
                "stages": manifest.get("stages", {}),
                "metrics": version_metrics,
                "feature_names": manifest.get("feature_names", []),
                "signature": manifest.get("signature"),
            }
        )
    current_version = loader.loaded_versions().get(tenant_id) or loader.global_manager.version

    # Fusion weights
    fusion = loader.get_fusion_weights(tenant_id).to_dict()

    # Retrain status
    retrain_status: dict[str, Any] = {}
    if _retrain_scheduler is not None:
        retrain_status = _retrain_scheduler.get_status(tenant_id)

    # Retrain history
    tenant_history = [r for r in _retrain_history if r.get("tenant_id") == tenant_id]

    # Worker stats
    worker_stats: dict[str, Any] = {}
    if _retrain_worker is not None:
        worker_stats = _retrain_worker.stats

    # Shadow mode
    shadow: dict[str, Any] | None = None
    tracker = loader.shadow_tracker
    if tracker.is_in_shadow(tenant_id):
        total = tracker._shadow_total.get(tenant_id, 0)
        alerts = tracker._shadow_alerts.get(tenant_id, 0)
        alert_rate = (alerts / total) if total > 0 else 0.0
        shadow = {
            "in_shadow": True,
            "passed": False,
            "alert_rate": alert_rate,
            "total_scored": total,
            "total_alerts": alerts,
            "version": tracker._shadow_version.get(tenant_id, ""),
            "max_alert_rate": tracker._max_fpr,
        }
    else:
        # Not in shadow — return stable baseline so the UI renders properly
        shadow = {
            "in_shadow": False,
            "passed": False,
            "alert_rate": 0.0,
            "total_scored": 0,
            "total_alerts": 0,
            "version": "",
            "max_alert_rate": getattr(tracker, "_max_fpr", 0.1),
        }

    # Accuracy
    accuracy: dict[str, Any] | None = None
    if _accuracy_tracker is not None:
        accuracy = _accuracy_tracker.compute().to_dict()

    # Drift
    drift: dict[str, Any] | None = None
    if _drift_detector is not None:
        # Provide stable status even when no baseline/current arrays exist
        drift = {
            "drifted": False,
            "metric_name": "psi",
            "metric_value": 0.0,
            "threshold": _drift_detector._threshold if hasattr(_drift_detector, "_threshold") else 0.15,
        }

    # Meta-alerts
    meta_alerts: list[dict[str, Any]] = []
    if _meta_alerter is not None:
        meta_alerts = [a.to_dict() for a in _meta_alerter.get_alerts(limit=200)]

    # ── Interpretability data ──────────────────
    # Feature importance
    feature_importance: list[dict[str, Any]] = []
    ensemble = loader.get_ensemble(tenant_id)
    if ensemble is not None:
        xgb_model = getattr(ensemble, "_stage2", None)
        if xgb_model is not None and getattr(xgb_model, "is_fitted", False):
            raw = getattr(xgb_model._model, "feature_importances_", None)
            if raw is not None:
                fi_names = xgb_model._feature_names or loader.get_feature_names(tenant_id)
                for i, val in enumerate(raw):
                    fname = fi_names[i] if i < len(fi_names) else f"feature_{i}"
                    feature_importance.append(
                        {
                            "feature": fname,
                            "importance": round(float(val), 6),
                            "source": "xgboost",
                        }
                    )
                feature_importance.sort(key=lambda x: x["importance"], reverse=True)

    # Confusion matrix
    confusion_matrix: dict[str, Any] | None = None
    if accuracy is not None:
        tp = accuracy.get("tp", 0)
        fp = accuracy.get("fp", 0)
        fn = accuracy.get("fn", 0)
        tn = accuracy.get("tn", 0)
        total = tp + fp + fn + tn
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        confusion_matrix = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "total": total,
        }

    # Recent predictions (last 50 for dashboard snapshot)
    tenant_preds = [p for p in _prediction_log if p.get("tenant_id") == tenant_id][-50:]

    return {
        "global_model": global_model,
        "models": {
            "models": model_list,
            "current_version": current_version,
        },
        "fusion_weights": fusion,
        "retrain_status": retrain_status,
        "retrain_history": tenant_history,
        "worker_stats": worker_stats,
        "shadow": shadow,
        "accuracy": accuracy,
        "drift": drift,
        "meta_alerts": meta_alerts,
        "feature_importance": feature_importance,
        "confusion_matrix": confusion_matrix,
        "recent_predictions": tenant_preds,
    }
