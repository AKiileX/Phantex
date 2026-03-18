# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Phantex ML Training Provenance & Reproducibility (J5e)."""

from ml.provenance.diff import ModelVersionDiff, compute_diff, format_diff_summary
from ml.provenance.manifest import DataProvenance, ManifestBuilder, TrainingManifest, ValidationMetrics
from ml.provenance.reproducer import (
    ReproducibilityResult,
    compute_data_hash,
    compute_model_hash,
    verify_reproducibility,
)

__all__ = [
    "ManifestBuilder",
    "TrainingManifest",
    "DataProvenance",
    "ValidationMetrics",
    "compute_data_hash",
    "compute_model_hash",
    "verify_reproducibility",
    "ReproducibilityResult",
    "compute_diff",
    "format_diff_summary",
    "ModelVersionDiff",
]
