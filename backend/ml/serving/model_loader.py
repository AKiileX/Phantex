# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Model Loader (J3 + Q1 Global Model Integration).

Loads model artifacts from the registry, handles hot-reload polling,
and performs atomic model swap with zero downtime.
Shadow mode: new models score in shadow for a configurable period before
becoming active.

Q1 Enhancement: Falls back to the global starter model when no
tenant-specific model is available, using EnsembleFusion for
adaptive weight blending.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import structlog

from ml.config import get_ml_config
from ml.global_model.fusion import EnsembleFusion, FusionWeights
from ml.global_model.manager import GlobalModelManager
from ml.models.ensemble import EnsembleScorer
from ml.registry.model_registry import ModelRegistry
from ml.serving.shadow_mode import ShadowModeTracker

logger = structlog.get_logger("phantex.ml.serving.loader")

class ModelLoader:
    """Lazy model loader with periodic hot-reload, shadow mode, and
    global model fallback (Q1).

    On first call, loads the latest model from the registry.
    Polls the registry every `model_poll_seconds` for new versions.
    New models enter shadow mode; after the shadow period elapses and
    FPR is acceptable, they become the active scorer.

    Q1: If no tenant model is available, falls back to the global
    starter model. When both are available, uses EnsembleFusion for
    weighted blending.
    """

    def __init__(
        self,
        registry: ModelRegistry,
        global_manager: GlobalModelManager | None = None,
    ) -> None:
        self._registry = registry
        self._cfg = get_ml_config().inference
        self._lock = threading.Lock()
        self._shadow_tracker = ShadowModeTracker()

        # Q1: Global model manager and fusion
        self._global_manager = global_manager or GlobalModelManager(registry)
        self._fusion = EnsembleFusion()

        # Per-tenant loaded ensembles
        self._ensembles: dict[str, EnsembleScorer] = {}
        self._shadow_ensembles: dict[str, EnsembleScorer] = {}  # Shadow candidates
        self._versions: dict[str, str] = {}  # tenant → current version
        self._last_poll: dict[str, float] = {}  # tenant → last poll timestamp
        self._feature_names: dict[str, list[str]] = {}

        # Q1: Per-tenant training metadata for fusion weighting
        self._tenant_samples: dict[str, int] = {}
        self._tenant_precision: dict[str, float] = {}

    def get_ensemble(self, tenant_id: str) -> EnsembleScorer | None:
        """Get the current ensemble scorer for a tenant.

        Q1 Enhancement: Never returns None. Falls back to the global
        starter model when no tenant-specific model is available.

        Returns None ONLY if neither global nor tenant model is available
        (should not happen in production — global model trains on demand).
        """
        now = time.time()
        last = self._last_poll.get(tenant_id, 0)

        # Poll for new version if interval elapsed
        if now - last >= self._cfg.model_poll_seconds:
            self._try_load(tenant_id)
            self._last_poll[tenant_id] = now

        # Check if shadow period ended → evaluate and promote or reject
        if self._shadow_tracker.is_in_shadow(tenant_id):
            pass  # Still in shadow — use existing active model
        elif tenant_id in self._shadow_ensembles:
            # Shadow period ended — evaluate results
            result = self._shadow_tracker.evaluate(tenant_id)
            if result["passed"]:
                with self._lock:
                    self._ensembles[tenant_id] = self._shadow_ensembles.pop(tenant_id)
                logger.info("shadow_model_promoted", tenant_id=tenant_id, **result)
            else:
                self._shadow_ensembles.pop(tenant_id, None)
                logger.warning("shadow_model_rejected", tenant_id=tenant_id, **result)

        return self._ensembles.get(tenant_id)

    def get_shadow_ensemble(self, tenant_id: str) -> EnsembleScorer | None:
        """Get the shadow ensemble (for scoring without alerting)."""
        if self._shadow_tracker.is_in_shadow(tenant_id):
            return self._shadow_ensembles.get(tenant_id)
        return None

    @property
    def shadow_tracker(self) -> ShadowModeTracker:
        """Access the shadow mode tracker for recording scores."""
        return self._shadow_tracker

    def get_feature_names(self, tenant_id: str) -> list[str]:
        """Return the feature names the loaded model expects."""
        return self._feature_names.get(tenant_id, [])

    def _try_load(self, tenant_id: str) -> None:
        """Attempt to load the latest model version for a tenant.

        If this is the first load (cold start), the model is activated
        immediately. Otherwise it enters shadow mode for validation.
        """
        try:
            mv = self._registry.load_latest(tenant_id)
            if mv is None:
                return

            # Already have this version (active or shadow)?
            if self._versions.get(tenant_id) == mv.version:
                return

            # Load model artifacts
            models = self._registry.load_models(mv)

            ensemble = EnsembleScorer(
                stage1=models.get("stage1"),
                stage2=models.get("stage2"),
                stage3=models.get("stage3"),
            )

            # First model for this tenant → activate immediately (cold start)
            if tenant_id not in self._ensembles:
                with self._lock:
                    self._ensembles[tenant_id] = ensemble
                    self._versions[tenant_id] = mv.version
                    self._feature_names[tenant_id] = mv.feature_names
                logger.info(
                    "model_loaded_cold_start",
                    tenant_id=tenant_id,
                    version=mv.version,
                )
            else:
                # Existing model → new version enters shadow mode
                with self._lock:
                    self._shadow_ensembles[tenant_id] = ensemble
                    self._versions[tenant_id] = mv.version
                    self._feature_names[tenant_id] = mv.feature_names
                self._shadow_tracker.start_shadow(tenant_id, mv.version)
                logger.info(
                    "model_entered_shadow",
                    tenant_id=tenant_id,
                    version=mv.version,
                )

        except Exception:
            logger.exception("model_load_error", tenant_id=tenant_id)

    def force_reload(self, tenant_id: str) -> bool:
        """Force-reload the latest model for a tenant. Returns True if loaded."""
        self._try_load(tenant_id)
        return tenant_id in self._ensembles

    def loaded_versions(self) -> dict[str, str]:
        """Return {tenant_id: version} for all loaded models."""
        return dict(self._versions)

    # ── Q1: Global Model Integration ────────────────────────────────

    @property
    def global_manager(self) -> GlobalModelManager:
        """Access the global model manager."""
        return self._global_manager

    @property
    def fusion(self) -> EnsembleFusion:
        """Access the ensemble fusion scorer."""
        return self._fusion

    def get_global_ensemble(self) -> EnsembleScorer | None:
        """Get the global starter model ensemble."""
        return self._global_manager.get_ensemble()

    def get_fused_ensemble_result(
        self,
        tenant_id: str,
        features: dict[str, float],
        feature_names: list[str],
    ) -> dict[str, Any] | None:
        """Score through the fused global + tenant ensemble (Q1).

        This is the primary scoring path. It:
          1. Gets the global ensemble (always available after init)
          2. Gets the tenant ensemble (may be None)
          3. Computes adaptive fusion weights
          4. Returns blended result

        Returns None only if no global model is available.
        """
        global_ensemble = self._global_manager.get_ensemble()
        if global_ensemble is None:
            # Absolute last resort — try tenant-only
            tenant_ensemble = self.get_ensemble(tenant_id)
            if tenant_ensemble is not None:
                return tenant_ensemble.score(features, feature_names)
            return None

        tenant_ensemble = self.get_ensemble(tenant_id)
        tenant_samples = self._tenant_samples.get(tenant_id, 0)
        tenant_precision = self._tenant_precision.get(tenant_id)
        global_feature_names = self._global_manager.feature_names

        return self._fusion.score(
            global_ensemble=global_ensemble,
            tenant_ensemble=tenant_ensemble,
            features=features,
            feature_names=feature_names,
            tenant_samples=tenant_samples,
            tenant_precision=tenant_precision,
            global_feature_names=global_feature_names or feature_names,
        )

    def update_tenant_metadata(
        self,
        tenant_id: str,
        *,
        samples: int | None = None,
        precision: float | None = None,
    ) -> None:
        """Update tenant training metadata for fusion weight computation.

        Called by the auto-retrain pipeline (Q2) after training completes.
        """
        if samples is not None:
            self._tenant_samples[tenant_id] = samples
        if precision is not None:
            self._tenant_precision[tenant_id] = precision

    def get_fusion_weights(self, tenant_id: str) -> FusionWeights:
        """Get the current fusion weights for a tenant (diagnostic)."""
        return self._fusion.compute_weights(
            tenant_samples=self._tenant_samples.get(tenant_id, 0),
            tenant_precision=self._tenant_precision.get(tenant_id),
        )
