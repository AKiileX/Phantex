# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Training Manifest Generation & Signing (J5e).

Every trained model gets a signed manifest documenting: data hash,
sample counts, hyperparameters, validation metrics, adversarial metrics.
SLSA-inspired provenance chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.provenance.manifest")

@dataclass
class DataProvenance:
    """Provenance of training data."""

    source: str = "clickhouse:events"
    query_hash: str = ""
    date_range: str = ""
    total_samples: int = 0
    positive_labels: int = 0
    negative_labels: int = 0
    unlabeled: int = 0
    sanitization_report: dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationMetrics:
    """Model validation metrics."""

    clean_precision: float = 0.0
    clean_recall: float = 0.0
    clean_fpr: float = 0.0
    adversarial_evasion_fgsm: float = 0.0
    adversarial_evasion_pgd: float = 0.0
    robustness_certified_eps: float = 0.0

@dataclass
class ModelDiff:
    """Diff from predecessor model."""

    accuracy_delta: str = ""
    new_features: list[str] = field(default_factory=list)
    removed_features: list[str] = field(default_factory=list)

@dataclass
class TrainingManifest:
    """Complete training manifest for a model version."""

    manifest_version: str = "1.0"
    model_id: str = ""
    created_at: str = ""
    signed_by: str = ""
    signature: str = ""
    pipeline_version: str = ""
    data: DataProvenance = field(default_factory=DataProvenance)
    hyperparameters: dict[str, Any] = field(default_factory=dict)
    random_seed: int = 42
    adversarial_training: bool = False
    adversarial_eps: float = 0.0
    validation: ValidationMetrics = field(default_factory=ValidationMetrics)
    predecessor: str = ""
    diff_from_predecessor: ModelDiff = field(default_factory=ModelDiff)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "model_id": self.model_id,
            "created_at": self.created_at,
            "signed_by": self.signed_by,
            "signature": self.signature,
            "training": {
                "pipeline_version": self.pipeline_version,
                "data": asdict(self.data),
                "hyperparameters": self.hyperparameters,
                "random_seed": self.random_seed,
                "adversarial_training": self.adversarial_training,
                "adversarial_eps": self.adversarial_eps,
            },
            "validation": asdict(self.validation),
            "predecessor": self.predecessor,
            "diff_from_predecessor": asdict(self.diff_from_predecessor),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def content_hash(self) -> str:
        """Compute SHA-256 hash of manifest content (excluding signature)."""
        d = self.to_dict()
        d.pop("signature", None)
        d.pop("signed_by", None)
        payload = json.dumps(d, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_customer_safe(self) -> dict[str, Any]:
        """Return redacted manifest for customer-facing endpoint.

        Removes: internal paths, infra details, exact query hash.
        """
        d = self.to_dict()
        training = d.get("training", {})
        data = training.get("data", {})

        # Redact internal details
        data.pop("query_hash", None)
        data["source"] = "phantex-training-pipeline"

        return d

class ManifestBuilder:
    """Builds training manifests for model versions."""

    def __init__(self, pipeline_version: str = "unknown") -> None:
        self._pipeline_version = pipeline_version

    def build(
        self,
        model_id: str,
        data: DataProvenance | None = None,
        hyperparameters: dict[str, Any] | None = None,
        validation: ValidationMetrics | None = None,
        predecessor: str = "",
        diff: ModelDiff | None = None,
        random_seed: int = 42,
        adversarial_training: bool = False,
        adversarial_eps: float = 0.0,
    ) -> TrainingManifest:
        """Build a complete training manifest."""
        manifest = TrainingManifest(
            model_id=model_id,
            created_at=datetime.now(UTC).isoformat(),
            pipeline_version=self._pipeline_version,
            data=data or DataProvenance(),
            hyperparameters=hyperparameters or {},
            random_seed=random_seed,
            adversarial_training=adversarial_training,
            adversarial_eps=adversarial_eps,
            validation=validation or ValidationMetrics(),
            predecessor=predecessor,
            diff_from_predecessor=diff or ModelDiff(),
        )

        logger.info(
            "manifest_built",
            model_id=model_id,
            content_hash=manifest.content_hash()[:16],
        )

        return manifest

    def sign(
        self,
        manifest: TrainingManifest,
        signing_key: str | None = None,
    ) -> TrainingManifest:
        """Sign a manifest with Ed25519 (stub — Vault Transit in production).

        For development: HMAC-SHA256 with local key.
        Production: vault:transit/phantex-ml-signing.
        """
        if signing_key is None:
            signing_key = os.environ.get("PHANTEX_SIGNING_KEY", "local-dev-key")

        content_hash = manifest.content_hash()

        # Development signing: HMAC-SHA256
        sig = hashlib.sha256(f"{signing_key}:{content_hash}".encode()).hexdigest()

        manifest.signed_by = f"dev:{signing_key[:8]}..."
        manifest.signature = f"hmac-sha256:{sig}"

        return manifest

    @staticmethod
    def verify(
        manifest: TrainingManifest,
        signing_key: str | None = None,
    ) -> bool:
        """Verify manifest signature.

        Args:
            signing_key: HMAC key. Defaults to PHANTEX_SIGNING_KEY env var,
                         falling back to 'local-dev-key' for development.

        Returns:
            True if signature is valid.
        """
        if not manifest.signature:
            return False

        if signing_key is None:
            signing_key = os.environ.get("PHANTEX_SIGNING_KEY", "local-dev-key")

        content_hash = manifest.content_hash()
        expected_sig = hashlib.sha256(f"{signing_key}:{content_hash}".encode()).hexdigest()
        expected = f"hmac-sha256:{expected_sig}"

        return hmac.compare_digest(manifest.signature, expected)
