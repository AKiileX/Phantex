# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q2: Retrain Pipeline.

Orchestrates the full automatic retrain workflow:
  1. Load data from ClickHouse (or synthetic for dev)
  2. Train via existing TrainingPipeline
  3. Validate against QualityGate
  4. If passed: save to registry and trigger hot-swap via ModelLoader
  5. If failed: keep current model, log reason
  6. Update scheduler state

This pipeline is designed to be invoked by the RetrainScheduler
and runs synchronously (blocking). For async use, wrap in a
background thread/task.

Security:
  - New model is validated before deployment
  - Current model keeps serving during training
  - Atomic swap via registry + ModelLoader
  - Full audit trail from training pipeline (J5)
  - Rate-limited by scheduler
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
import structlog

from ml.registry.model_registry import ModelRegistry
from ml.retrain.quality_gate import QualityGate
from ml.retrain.scheduler import RetrainScheduler
from ml.serving.model_loader import ModelLoader
from ml.training.trainer import TrainingPipeline

logger = structlog.get_logger("phantex.ml.retrain.pipeline")

class RetrainResult:
    """Result of a retrain operation."""

    __slots__ = (
        "success",
        "tenant_id",
        "version",
        "quality_result",
        "training_time_seconds",
        "reason",
        "metrics",
    )

    def __init__(
        self,
        success: bool,
        tenant_id: str,
        version: str | None = None,
        quality_result: dict[str, Any] | None = None,
        training_time_seconds: float = 0.0,
        reason: str = "",
        metrics: dict[str, Any] | None = None,
    ) -> None:
        self.success = success
        self.tenant_id = tenant_id
        self.version = version
        self.quality_result = quality_result
        self.training_time_seconds = training_time_seconds
        self.reason = reason
        self.metrics = metrics or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "tenant_id": self.tenant_id,
            "version": self.version,
            "quality_result": self.quality_result,
            "training_time_seconds": round(self.training_time_seconds, 2),
            "reason": self.reason,
            "metrics": self.metrics,
        }

class RetrainPipeline:
    """Full automatic retrain workflow for a single tenant.

    Usage:
        pipeline = RetrainPipeline(registry, model_loader, scheduler)
        result = pipeline.retrain(tenant_id)
        if result.success:
            print(f"New model deployed: {result.version}")
    """

    def __init__(
        self,
        registry: ModelRegistry,
        model_loader: ModelLoader,
        scheduler: RetrainScheduler,
        clickhouse_client=None,
    ) -> None:
        self._registry = registry
        self._loader = model_loader
        self._scheduler = scheduler
        self._quality_gate = QualityGate()
        self._training_pipeline = TrainingPipeline(clickhouse_client)

    def retrain(
        self,
        tenant_id: str,
        X: np.ndarray | None = None,
        y: np.ndarray | None = None,
        feature_names: list[str] | None = None,
        operator_id: str = "auto-retrain",
    ) -> RetrainResult:
        """Execute a full retrain cycle for a tenant.

        Steps:
          1. Mark retrain as started in scheduler
          2. Train new model via TrainingPipeline
          3. Validate via QualityGate
          4. If passed: save to registry + update ModelLoader
          5. Update scheduler state

        Args:
            tenant_id: Tenant to retrain.
            X: Optional pre-loaded feature matrix (for testing).
            y: Optional pre-loaded labels.
            feature_names: Optional feature name list.
            operator_id: Identifier for audit trail.

        Returns:
            RetrainResult with success/failure and details.
        """
        start = time.time()

        self._scheduler.mark_retrain_started(tenant_id)
        logger.info("retrain_pipeline_started", tenant_id=tenant_id)

        try:
            # ── Step 1: Train new model ──────────────────────────────
            train_results = self._training_pipeline.train_all(
                X=X,
                y=y,
                feature_names=feature_names,
                tenant_id=tenant_id,
                operator_id=operator_id,
            )

            # Extract trained models
            stage1 = train_results.get("stage1", {}).get("model")
            stage2 = train_results.get("stage2", {}).get("model")
            stage3 = train_results.get("stage3", {}).get("model")
            trained_features = train_results.get("feature_names", [])

            if stage1 is None:
                elapsed = time.time() - start
                self._scheduler.mark_retrain_completed(
                    tenant_id,
                    success=False,
                    reset_labels=False,
                )
                return RetrainResult(
                    success=False,
                    tenant_id=tenant_id,
                    training_time_seconds=elapsed,
                    reason="training_produced_no_models",
                )

            # ── Step 2: Quality gate validation ──────────────────────
            s1_val = train_results.get("stage1", {}).get("validation")
            new_precision = s1_val.precision if s1_val else 0.0
            new_recall = s1_val.recall if s1_val else 0.0
            new_fpr = s1_val.fpr if s1_val else 1.0

            # Get current model metrics for comparison
            current_precision = 0.0
            current_recall = 0.0
            current_version = self._loader.loaded_versions().get(tenant_id)
            if current_version:
                # Try to get current metrics from registry
                try:
                    mv = self._registry.load_version(tenant_id, current_version)
                    if mv and mv.metrics:
                        s1_metrics = mv.metrics.get("stage1_validation", {})
                        if isinstance(s1_metrics, dict):
                            current_precision = s1_metrics.get("precision", 0.0)
                            current_recall = s1_metrics.get("recall", 0.0)
                except Exception:
                    pass  # Use defaults

            quality = self._quality_gate.evaluate(
                new_precision=new_precision,
                new_recall=new_recall,
                new_fpr=new_fpr,
                current_precision=current_precision,
                current_recall=current_recall,
            )

            if not quality.passed:
                elapsed = time.time() - start
                self._scheduler.mark_retrain_completed(
                    tenant_id,
                    success=False,
                    reset_labels=False,
                )
                logger.warning(
                    "retrain_quality_gate_failed",
                    tenant_id=tenant_id,
                    reason=quality.reason,
                )
                return RetrainResult(
                    success=False,
                    tenant_id=tenant_id,
                    quality_result=quality.to_dict(),
                    training_time_seconds=elapsed,
                    reason=f"quality_gate_failed: {quality.reason}",
                )

            # ── Step 3: Save to registry ─────────────────────────────
            metrics = {
                "stage1_validation": {
                    "precision": new_precision,
                    "recall": new_recall,
                    "fpr": new_fpr,
                },
                "training_samples": train_results.get("n_samples", 0),
                "retrain_trigger": "auto",
            }
            if s1_val and hasattr(s1_val, "f1"):
                metrics["stage1_validation"]["f1"] = s1_val.f1

            mv = self._registry.save_model(
                tenant_id=tenant_id,
                stage1=stage1,
                stage2=stage2,
                stage3=stage3,
                feature_names=trained_features,
                metrics=metrics,
            )

            # ── Step 4: Trigger hot-swap in ModelLoader ──────────────
            self._loader.force_reload(tenant_id)

            # Q1: Update tenant metadata for fusion weight computation
            self._loader.update_tenant_metadata(
                tenant_id,
                samples=train_results.get("n_samples", 0),
                precision=new_precision,
            )

            # ── Step 5: Update scheduler ─────────────────────────────
            self._scheduler.mark_retrain_completed(tenant_id, success=True)

            elapsed = time.time() - start
            logger.info(
                "retrain_pipeline_completed",
                tenant_id=tenant_id,
                version=mv.version,
                precision=round(new_precision, 4),
                recall=round(new_recall, 4),
                elapsed_seconds=round(elapsed, 1),
            )

            return RetrainResult(
                success=True,
                tenant_id=tenant_id,
                version=mv.version,
                quality_result=quality.to_dict(),
                training_time_seconds=elapsed,
                reason="retrain_successful",
                metrics=metrics,
            )

        except Exception as exc:
            elapsed = time.time() - start
            self._scheduler.mark_retrain_completed(
                tenant_id,
                success=False,
                reset_labels=False,
            )
            logger.exception(
                "retrain_pipeline_error",
                tenant_id=tenant_id,
                error=str(exc),
            )
            return RetrainResult(
                success=False,
                tenant_id=tenant_id,
                training_time_seconds=elapsed,
                reason=f"exception: {exc!s}",
            )

    def retrain_from_trigger(self, trigger: Any) -> RetrainResult:
        """Convenience: retrain from a RetrainTrigger object.

        Args:
            trigger: RetrainTrigger from RetrainScheduler.check()
        """
        return self.retrain(trigger.tenant_id)

    def process_all_pending(self) -> list[RetrainResult]:
        """Check all tenants and retrain those meeting threshold.

        Returns list of RetrainResult for each tenant that was retrained.
        """
        triggers = self._scheduler.check_all()
        results = []
        for trigger in triggers:
            result = self.retrain(trigger.tenant_id)
            results.append(result)
        return results
