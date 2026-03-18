# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q1: Global Model Manager.

Manages the global (tier-0) starter model lifecycle:
  - Loading the pre-trained global model from the registry
  - On-demand training if no global model exists
  - Thread-safe caching with atomic swap
  - Feature name validation

The global model is a singleton per process — all tenants share
the same global ensemble as their baseline protection floor.

Security:
  - Global model artifacts are HMAC-verified before loading (INT-07)
  - Thread-safe access via threading.Lock
  - Lazy initialization (no work at import time)
"""

from __future__ import annotations

import threading
from typing import Any

import structlog

from ml.config import get_ml_config
from ml.models.ensemble import EnsembleScorer
from ml.registry.model_registry import ModelRegistry

logger = structlog.get_logger("phantex.ml.global_model.manager")

class GlobalModelManager:
    """Singleton manager for the global starter model.

    Usage:
        manager = GlobalModelManager(registry)
        ensemble = manager.get_ensemble()  # Lazy loads or trains
        feature_names = manager.feature_names

    Thread Safety:
        All mutations are guarded by a threading.Lock. The get_ensemble()
        method is safe to call from multiple threads concurrently.
    """

    def __init__(self, registry: ModelRegistry) -> None:
        self._registry = registry
        self._cfg = get_ml_config().global_model
        self._lock = threading.Lock()

        self._ensemble: EnsembleScorer | None = None
        self._feature_names: list[str] = []
        self._version: str | None = None
        self._loaded = False
        self._training_in_progress = False

    @property
    def is_loaded(self) -> bool:
        """Whether a global model is currently loaded."""
        return self._loaded

    @property
    def feature_names(self) -> list[str]:
        """Feature names the global model was trained on."""
        return list(self._feature_names)

    @property
    def version(self) -> str | None:
        """Current global model version string."""
        return self._version

    def get_ensemble(self) -> EnsembleScorer | None:
        """Get the global ensemble scorer (lazy load).

        On first call:
          1. Tries to load from registry (pre-trained artifacts)
          2. If not found, trains a new global model on-demand
          3. Saves the newly trained model to the registry

        Subsequent calls return the cached ensemble.

        Returns:
            EnsembleScorer or None if training failed.
        """
        if self._loaded:
            return self._ensemble

        with self._lock:
            # Double-check after acquiring lock
            if self._loaded:
                return self._ensemble

            # Try loading from registry first
            if self._try_load_from_registry():
                return self._ensemble

            # No pre-trained model — train on demand
            logger.info("global_model_not_found_training_on_demand")
            if self._train_and_register():
                return self._ensemble

            logger.error("global_model_unavailable")
            return None

    def reload(self) -> bool:
        """Force reload the global model from the registry.

        Returns True if a model was loaded, False otherwise.
        """
        with self._lock:
            return self._try_load_from_registry()

    def train_and_register(self) -> bool:
        """Explicitly train a new global model and save to registry.

        Returns True if training succeeded.
        """
        with self._lock:
            return self._train_and_register()

    def _try_load_from_registry(self) -> bool:
        """Attempt to load the global model from the model registry.

        Returns True if successful.
        """
        try:
            mv = self._registry.load_latest(self._cfg.global_tenant_id)
            if mv is None:
                logger.debug("no_global_model_in_registry")
                return False

            models = self._registry.load_models(mv)

            ensemble = EnsembleScorer(
                stage1=models.get("stage1"),
                stage2=models.get("stage2"),
                stage3=models.get("stage3"),
            )

            self._ensemble = ensemble
            self._feature_names = mv.feature_names
            self._version = mv.version
            self._loaded = True

            logger.info(
                "global_model_loaded",
                version=mv.version,
                stages={
                    "stage1": models.get("stage1") is not None,
                    "stage2": models.get("stage2") is not None,
                    "stage3": models.get("stage3") is not None,
                },
            )
            return True

        except Exception:
            logger.exception("global_model_load_failed")
            return False

    def _train_and_register(self) -> bool:
        """Train global model and save to registry.

        Returns True if successful.
        """
        if self._training_in_progress:
            logger.warning("global_model_training_already_in_progress")
            return False

        self._training_in_progress = True
        try:
            from ml.global_model.trainer import GlobalModelTrainer

            trainer = GlobalModelTrainer()
            results = trainer.train()

            stage1 = results.get("stage1", {}).get("model")
            stage2 = results.get("stage2", {}).get("model")
            stage3 = results.get("stage3", {}).get("model")
            feature_names = results.get("feature_names", [])

            if stage1 is None:
                logger.error("global_model_training_failed_no_stage1")
                return False

            # Save to registry
            metrics = {
                "stage1_validation": results.get("stage1", {}).get("validation"),
                "stage2_validation": results.get("stage2", {}).get("validation"),
                "stage3_validation": results.get("stage3", {}).get("validation"),
                "data_fingerprint": results.get("data_fingerprint"),
                "training_time_seconds": results.get("training_time_seconds"),
            }
            # Serialize validation objects
            for key in ["stage1_validation", "stage2_validation", "stage3_validation"]:
                val = metrics.get(key)
                if val is not None and hasattr(val, "__dict__"):
                    metrics[key] = {
                        "precision": getattr(val, "precision", 0),
                        "recall": getattr(val, "recall", 0),
                        "fpr": getattr(val, "fpr", 0),
                    }

            mv = self._registry.save_model(
                tenant_id=self._cfg.global_tenant_id,
                stage1=stage1,
                stage2=stage2,
                stage3=stage3,
                feature_names=feature_names,
                metrics=metrics,
            )

            # Activate
            ensemble = EnsembleScorer(
                stage1=stage1,
                stage2=stage2,
                stage3=stage3,
            )
            self._ensemble = ensemble
            self._feature_names = feature_names
            self._version = mv.version
            self._loaded = True

            logger.info(
                "global_model_trained_and_registered",
                version=mv.version,
                training_time=results.get("training_time_seconds"),
            )
            return True

        except Exception:
            logger.exception("global_model_training_failed")
            return False
        finally:
            self._training_in_progress = False

    def get_info(self) -> dict[str, Any]:
        """Return diagnostic info about the global model state."""
        with self._lock:
            return {
                "loaded": self._loaded,
                "version": self._version,
                "n_features": len(self._feature_names),
                "training_in_progress": self._training_in_progress,
            }
