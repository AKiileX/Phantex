# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Model Registry (J2).

Versioned storage and retrieval of trained ML model artifacts.
Phase 2: local filesystem storage. Phase 3+: S3 + Vault-signed artifacts.

Each model version is stored as a directory:
    models/{tenant_id}/{version}/
        ├── stage1.pkl
        ├── stage2.pkl
        ├── stage3.pkl
        ├── manifest.json
        └── feature_names.json
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import structlog

from ml.config import get_ml_config

logger = structlog.get_logger("phantex.ml.registry")

class ModelVersion:
    """Metadata for a single model version."""

    def __init__(
        self,
        version: str,
        tenant_id: str,
        created_at: float,
        path: Path,
        metrics: dict[str, Any] | None = None,
        feature_names: list[str] | None = None,
    ) -> None:
        self.version = version
        self.tenant_id = tenant_id
        self.created_at = created_at
        self.path = path
        self.metrics = metrics or {}
        self.feature_names = feature_names or []

class ModelRegistry:
    """Versioned model storage and retrieval.

    Phase 2 implementation: local filesystem.
    Models are stored under {base_dir}/{tenant_id}/{version}/.
    """

    def __init__(self, base_dir: str | Path | None = None) -> None:
        cfg = get_ml_config().training
        self._base_dir = Path(base_dir) if base_dir else Path(cfg.model_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sanitize_path_component(value: str) -> str:
        """Sanitize a path component to prevent directory traversal."""
        import re

        # Strip leading/trailing whitespace and dots to kill traversal
        stripped = value.strip().strip(".")
        safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", stripped)
        # Collapse runs of underscores
        safe = re.sub(r"_+", "_", safe).strip("_")
        if not safe:
            raise ValueError(f"Invalid path component: {value!r}")
        return safe

    def save_model(
        self,
        tenant_id: str,
        stage1=None,
        stage2=None,
        stage3=None,
        feature_names: list[str] | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> ModelVersion:
        """Save a new model version to the registry.

        Returns the ModelVersion with path and metadata.
        """
        version = f"v{int(time.time())}"
        safe_tenant = self._sanitize_path_component(tenant_id)
        model_dir = self._base_dir / safe_tenant / version
        model_dir.mkdir(parents=True, exist_ok=True)

        # Save each stage if present
        if stage1 is not None:
            stage1.save(model_dir / "stage1.pkl")
        if stage2 is not None:
            stage2.save(model_dir / "stage2.pkl")
        if stage3 is not None:
            stage3.save(model_dir / "stage3.pkl")

        # Save feature names
        if feature_names:
            with open(model_dir / "feature_names.json", "w") as f:
                json.dump(feature_names, f)

        # Save manifest
        manifest = {
            "version": version,
            "tenant_id": tenant_id,
            "created_at": time.time(),
            "stages": {
                "stage1": stage1 is not None,
                "stage2": stage2 is not None,
                "stage3": stage3 is not None,
            },
            "metrics": metrics or {},
            "feature_names": feature_names or [],
        }
        with open(model_dir / "manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)

        mv = ModelVersion(
            version=version,
            tenant_id=tenant_id,
            created_at=manifest["created_at"],
            path=model_dir,
            metrics=metrics,
            feature_names=feature_names,
        )

        logger.info(
            "model_saved",
            version=version,
            tenant_id=tenant_id,
            path=str(model_dir),
        )
        return mv

    def load_latest(self, tenant_id: str) -> ModelVersion | None:
        """Load the most recent model version for a tenant."""
        safe_tenant = self._sanitize_path_component(tenant_id)
        tenant_dir = self._base_dir / safe_tenant
        if not tenant_dir.exists():
            return None

        versions = sorted(tenant_dir.iterdir(), key=lambda p: p.name, reverse=True)
        for version_dir in versions:
            manifest_path = version_dir / "manifest.json"
            if manifest_path.exists():
                return self._load_version(version_dir, manifest_path)
        return None

    def load_version(self, tenant_id: str, version: str) -> ModelVersion | None:
        """Load a specific model version."""
        safe_tenant = self._sanitize_path_component(tenant_id)
        safe_version = self._sanitize_path_component(version)
        version_dir = self._base_dir / safe_tenant / safe_version
        manifest_path = version_dir / "manifest.json"
        if not manifest_path.exists():
            return None
        return self._load_version(version_dir, manifest_path)

    def list_versions(self, tenant_id: str) -> list[dict[str, Any]]:
        """List all model versions for a tenant."""
        safe_tenant = self._sanitize_path_component(tenant_id)
        tenant_dir = self._base_dir / safe_tenant
        if not tenant_dir.exists():
            return []

        versions = []
        for version_dir in sorted(tenant_dir.iterdir(), reverse=True):
            manifest_path = version_dir / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(f)
                versions.append(manifest)
        return versions

    def load_models(self, model_version: ModelVersion) -> dict[str, Any]:
        """Load the actual model objects from a ModelVersion.

        INT-07: Verifies manifest signature before loading pickle artifacts.
        Returns dict with 'stage1', 'stage2', 'stage3' keys (None if not present).
        """
        # ── INT-07: Verify manifest before loading pickles ───────────
        manifest_path = model_version.path / "manifest.json"
        if manifest_path.exists():
            try:
                import hashlib
                import hmac as _hmac
                import os

                with open(manifest_path) as f:
                    manifest_data = json.load(f)

                stored_sig = manifest_data.get("signature", "")
                if stored_sig:
                    # Recompute content hash (same logic as TrainingManifest.content_hash)
                    verify_data = dict(manifest_data)
                    verify_data.pop("signature", None)
                    verify_data.pop("signed_by", None)
                    content_hash = hashlib.sha256(json.dumps(verify_data, sort_keys=True).encode()).hexdigest()
                    signing_key = os.environ.get("PHANTEX_SIGNING_KEY", "local-dev-key")
                    expected_sig = hashlib.sha256(f"{signing_key}:{content_hash}".encode()).hexdigest()
                    expected = f"hmac-sha256:{expected_sig}"

                    if not _hmac.compare_digest(stored_sig, expected):
                        logger.error(
                            "manifest_verification_failed",
                            version=model_version.version,
                            tenant_id=model_version.tenant_id,
                        )
                        return {"stage1": None, "stage2": None, "stage3": None}
                    logger.info(
                        "manifest_verified",
                        version=model_version.version,
                        tenant_id=model_version.tenant_id,
                    )
            except Exception as exc:
                # Manifest verification is best-effort during Phase 2;
                # log warning but allow load to proceed for models created
                # before manifest signing was added.
                logger.warning(
                    "manifest_verification_skipped",
                    version=model_version.version,
                    error=str(exc),
                )

        result: dict[str, Any] = {"stage1": None, "stage2": None, "stage3": None}

        s1_path = model_version.path / "stage1.pkl"
        if s1_path.exists():
            from ml.models.isolation_forest import IsolationForestModel

            result["stage1"] = IsolationForestModel.load(s1_path)

        s2_path = model_version.path / "stage2.pkl"
        if s2_path.exists():
            from ml.models.xgboost_model import XGBoostModel

            result["stage2"] = XGBoostModel.load(s2_path)

        s3_path = model_version.path / "stage3.pkl"
        if s3_path.exists():
            from ml.models.autoencoder import AutoencoderModel

            result["stage3"] = AutoencoderModel.load(s3_path)

        return result

    @staticmethod
    def _load_version(version_dir: Path, manifest_path: Path) -> ModelVersion:
        with open(manifest_path) as f:
            manifest = json.load(f)
        return ModelVersion(
            version=manifest["version"],
            tenant_id=manifest["tenant_id"],
            created_at=manifest.get("created_at", 0),
            path=version_dir,
            metrics=manifest.get("metrics"),
            feature_names=manifest.get("feature_names", []),
        )
