# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Unified Training Pipeline (J2 + J5 Integration).

Orchestrates the full training workflow:
  1. Load data from ClickHouse (or synthetic for dev)
  2. Create labels from alert dispositions
  3. *Sanitize training data (J5b — poison/outlier removal)*
  4. Train Stage 1 (Isolation Forest) — unsupervised
  5. Train Stage 2 (XGBoost) — supervised (if labels exist)
  6. Train Stage 3 (Autoencoder) — semi-supervised
  7. *Augment with adversarial examples and retrain AE (J5a)*
  8. Validate each model
  9. *Generate signed training manifest (J5e)*
  10. *Log all actions to audit trail (J5b)*
  11. Save to model registry
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
import structlog

from ml.config import get_ml_config
from ml.integrity.audit import AuditAction, TrainingAuditLog
from ml.integrity.data_sanitizer import DataSanitizer
from ml.models.autoencoder import AutoencoderModel
from ml.models.isolation_forest import IsolationForestModel
from ml.models.xgboost_model import XGBoostModel
from ml.provenance.manifest import (
    DataProvenance,
    ManifestBuilder,
    ValidationMetrics,
)
from ml.training.data_loader import TrainingDataLoader
from ml.training.labeler import Labeler
from ml.training.validator import ModelValidator

logger = structlog.get_logger("phantex.ml.training.trainer")

class TrainingPipeline:
    """Full training pipeline for all 3 model stages."""

    def __init__(self, clickhouse_client=None) -> None:
        self._loader = TrainingDataLoader(clickhouse_client)
        self._labeler = Labeler()
        self._validator = ModelValidator()
        self._sanitizer = DataSanitizer()
        self._manifest_builder = ManifestBuilder(pipeline_version="j5-integrated")

    @property
    def audit_log(self) -> TrainingAuditLog:
        """Access the audit log for this training run."""
        return self._audit_log

    def train_all(
        self,
        X: np.ndarray | None = None,
        y: np.ndarray | None = None,
        feature_names: list[str] | None = None,
        alert_labels: list[dict[str, Any]] | None = None,
        tenant_id: str = "default",
        operator_id: str = "system",
    ) -> dict[str, Any]:
        """Train all 3 stages and return results.

        If X is None, generates synthetic training data for dev/testing.

        Returns:
            Dict with 'stage1', 'stage2', 'stage3' results + metadata.
        """
        cfg = get_ml_config().training
        start = time.time()
        self._audit_log = TrainingAuditLog()

        self._audit_log.append(
            AuditAction.TRAINING_STARTED,
            actor=operator_id,
            tenant_id=tenant_id,
            details={"config": {"validation_split": cfg.validation_split, "min_samples": cfg.min_samples}},
        )

        # ── Load or generate data ────────────────────────────────────
        if X is None:
            # Try real data from ClickHouse first
            X_ch, fn_ch, _ = self._loader.load_features_sync(tenant_id)
            if X_ch.shape[0] > 0:
                X = X_ch
                feature_names = fn_ch
                logger.info(
                    "using_clickhouse_training_data",
                    samples=X.shape[0],
                    features=len(feature_names),
                    tenant_id=tenant_id,
                )
            else:
                # Fallback: synthetic data for dev/testing
                X, y, feature_names = self._loader.generate_synthetic_data(
                    n_samples=10_000,
                    n_features=30,
                )
                logger.info("using_synthetic_training_data", samples=X.shape[0])
        else:
            if feature_names is None:
                feature_names = [f"feature_{i}" for i in range(X.shape[1])]

        self._audit_log.append(
            AuditAction.DATA_LOADED,
            actor=operator_id,
            tenant_id=tenant_id,
            details={"samples": X.shape[0], "features": X.shape[1]},
        )

        # ── Create labels ────────────────────────────────────────────
        if y is None:
            y_labels, label_mask = self._labeler.create_labels(X, alert_labels)
        else:
            y_labels = y
            label_mask = np.ones(len(y), dtype=bool)

        # ── J5b: Sanitize training data ──────────────────────────────
        X_clean, y_clean, san_report, keep_mask = self._sanitizer.sanitize(X, y_labels)
        if san_report.removed_samples > 0:
            logger.info(
                "training_data_sanitized",
                removed=san_report.removed_samples,
                retained=san_report.retained_samples,
                outliers=san_report.outlier_removals,
                spectral=san_report.spectral_removals,
            )
            # BUG-01 fix: use keep_mask from sanitizer for correct alignment
            # (sanitizer can remove rows from arbitrary positions, not just tail)
            label_mask_clean = label_mask[keep_mask]
        else:
            X_clean, y_clean = X, y_labels
            label_mask_clean = label_mask

        self._audit_log.append(
            AuditAction.SANITIZATION_COMPLETE,
            actor="system",
            tenant_id=tenant_id,
            details=san_report.to_dict(),
        )

        # ── Train/validate split ─────────────────────────────────────
        n = X_clean.shape[0]
        split = int(n * (1 - cfg.validation_split))
        X_train, X_val = X_clean[:split], X_clean[split:]
        y_train, y_val = y_clean[:split], y_clean[split:]
        mask_train = label_mask_clean[:split]

        results: dict[str, Any] = {
            "n_samples": n,
            "n_features": X_clean.shape[1],
            "feature_names": feature_names,
            "sanitization": san_report.to_dict(),
        }

        # ── Stage 1: Isolation Forest (unsupervised — uses ALL data) ─
        logger.info("training_stage1_isolation_forest")
        stage1 = IsolationForestModel()
        s1_meta = stage1.fit(X_train, feature_names=feature_names)
        s1_scores = stage1.predict_score(X_val)
        s1_preds = (s1_scores > 0.5).astype(int)
        s1_val = self._validator.validate(y_val, s1_preds)
        results["stage1"] = {
            "model": stage1,
            "training_meta": s1_meta,
            "validation": s1_val,
        }

        # ── Stage 2: XGBoost (supervised — needs labeled data) ───────
        labeled_train_mask = mask_train
        labeled_count = labeled_train_mask.sum()

        stage2: XGBoostModel | None = None
        X_labeled = X_train[labeled_train_mask] if labeled_count > 0 else X_train[:0]
        y_labeled = y_train[labeled_train_mask] if labeled_count > 0 else y_train[:0]
        n_unique_classes = len(np.unique(y_labeled)) if labeled_count > 0 else 0

        if labeled_count >= cfg.min_samples and n_unique_classes >= 2:
            logger.info("training_stage2_xgboost", labeled_samples=int(labeled_count))

            stage2 = XGBoostModel()
            s2_meta = stage2.fit(
                X_labeled,
                y_labeled,
                feature_names=feature_names,
            )
            s2_probs = stage2.predict_proba(X_val)
            s2_preds = (s2_probs[:, 0] < 0.5).astype(int)  # Non-benign
            s2_val = self._validator.validate(y_val, s2_preds)
            results["stage2"] = {
                "model": stage2,
                "training_meta": s2_meta,
                "validation": s2_val,
            }
        else:
            reason = "insufficient_labels" if labeled_count < cfg.min_samples else "single_class"
            logger.info(
                "skipping_stage2",
                reason=reason,
                labeled=int(labeled_count),
                unique_classes=n_unique_classes,
                min_required=cfg.min_samples,
            )
            results["stage2"] = {"model": None, "reason": reason}

        # ── Stage 3: Autoencoder (train on benign data only) ─────────
        benign_mask = y_train == 0
        n_benign = benign_mask.sum()

        stage3: AutoencoderModel | None = None
        if n_benign >= cfg.min_samples:
            logger.info("training_stage3_autoencoder", benign_samples=int(n_benign))
            X_benign = X_train[benign_mask]
            stage3 = AutoencoderModel(input_dim=X_clean.shape[1])
            s3_meta = stage3.fit(X_benign, feature_names=feature_names)
            s3_scores = stage3.predict_score(X_val)
            s3_preds = (s3_scores > 0.5).astype(int)
            s3_val = self._validator.validate(y_val, s3_preds)
            results["stage3"] = {
                "model": stage3,
                "training_meta": s3_meta,
                "validation": s3_val,
            }
        else:
            logger.info(
                "skipping_stage3_insufficient_data",
                benign=int(n_benign),
                min_required=cfg.min_samples,
            )
            results["stage3"] = {"model": None, "reason": "insufficient_data"}

        # ── J5a: Adversarial augment + retrain AE (if stage3 exists) ─
        if stage3 is not None and stage3.is_fitted:
            try:
                from ml.adversarial.adversarial_trainer import augment_training_data

                X_aug, _ = augment_training_data(
                    model=stage3._model,  # nn.Module
                    X_train=X_benign.astype(np.float32),
                    epsilon=0.1,
                    adversarial_ratio=0.3,
                )
                # Retrain with augmented data
                stage3_aug = AutoencoderModel(input_dim=X_clean.shape[1])
                stage3_aug.fit(X_aug, feature_names=feature_names)
                # BUG-02 fix: replace original model with hardened version
                results["stage3"]["model"] = stage3_aug
                results["stage3"]["adversarial_augmented"] = True
                results["stage3"]["augmented_samples"] = len(X_aug)
                logger.info(
                    "stage3_adversarial_augmentation",
                    original_samples=int(n_benign),
                    augmented_samples=len(X_aug),
                )
            except Exception as exc:
                logger.warning("adversarial_augmentation_failed", error=str(exc))
                results["stage3"]["adversarial_augmented"] = False

        # ── J5e: Generate signed training manifest ───────────────────
        s1_val_result = results.get("stage1", {}).get("validation")
        manifest = self._manifest_builder.build(
            model_id=f"{tenant_id}:{int(start)}",
            data=DataProvenance(
                total_samples=n,
                positive_labels=int((y_clean > 0).sum()),
                negative_labels=int((y_clean == 0).sum()),
                sanitization_report=san_report.to_dict(),
            ),
            validation=ValidationMetrics(
                clean_precision=s1_val_result.precision if s1_val_result else 0.0,
                clean_recall=s1_val_result.recall if s1_val_result else 0.0,
                clean_fpr=s1_val_result.fpr if s1_val_result else 0.0,
            ),
        )
        manifest = self._manifest_builder.sign(manifest)
        results["manifest"] = manifest.to_dict()

        self._audit_log.append(
            AuditAction.TRAINING_COMPLETED,
            actor=operator_id,
            tenant_id=tenant_id,
            details={
                "training_time_seconds": round(time.time() - start, 1),
                "manifest_hash": manifest.content_hash()[:16],
            },
        )
        results["audit_chain_valid"] = self._audit_log.verify_chain()

        elapsed = time.time() - start
        results["training_time_seconds"] = elapsed
        logger.info("training_complete", elapsed_seconds=f"{elapsed:.1f}")

        return results
