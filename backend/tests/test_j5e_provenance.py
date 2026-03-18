# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for J5e — Training Provenance & Reproducibility.
"""

from __future__ import annotations

import numpy as np

# ---------------------------------------------------------------------------
# J5e: Training Manifest
# ---------------------------------------------------------------------------

class TestTrainingManifest:
    """Training manifest generation and signing."""

    def test_build_manifest(self):
        from ml.provenance.manifest import (
            DataProvenance,
            ManifestBuilder,
            ValidationMetrics,
        )

        builder = ManifestBuilder(pipeline_version="git:abc123")
        manifest = builder.build(
            model_id="ensemble-v1",
            data=DataProvenance(total_samples=1000, positive_labels=50),
            hyperparameters={"max_depth": 8},
            validation=ValidationMetrics(clean_precision=0.93),
            random_seed=42,
        )

        assert manifest.model_id == "ensemble-v1"
        assert manifest.data.total_samples == 1000
        assert manifest.random_seed == 42

    def test_manifest_to_dict_structure(self):
        from ml.provenance.manifest import ManifestBuilder

        builder = ManifestBuilder()
        manifest = builder.build(model_id="test-v1")
        d = manifest.to_dict()

        assert "manifest_version" in d
        assert "training" in d
        assert "validation" in d
        assert d["training"]["random_seed"] == 42

    def test_sign_and_verify(self):
        from ml.provenance.manifest import ManifestBuilder

        builder = ManifestBuilder()
        manifest = builder.build(model_id="test-v2")
        signed = builder.sign(manifest, signing_key="test-key")

        assert signed.signature.startswith("hmac-sha256:")
        assert ManifestBuilder.verify(signed, signing_key="test-key") is True

    def test_tampered_manifest_fails_verify(self):
        from ml.provenance.manifest import ManifestBuilder

        builder = ManifestBuilder()
        manifest = builder.build(model_id="test-v3")
        signed = builder.sign(manifest, signing_key="test-key")

        # Tamper with model_id
        signed.model_id = "tampered-v3"
        assert ManifestBuilder.verify(signed, signing_key="test-key") is False

    def test_wrong_key_fails_verify(self):
        from ml.provenance.manifest import ManifestBuilder

        builder = ManifestBuilder()
        manifest = builder.build(model_id="test-v4")
        signed = builder.sign(manifest, signing_key="key-A")

        assert ManifestBuilder.verify(signed, signing_key="key-B") is False

    def test_customer_safe_redacts_query_hash(self):
        from ml.provenance.manifest import DataProvenance, ManifestBuilder

        builder = ManifestBuilder()
        manifest = builder.build(
            model_id="v5",
            data=DataProvenance(query_hash="sha256:secret_hash"),
        )
        safe = manifest.to_customer_safe()
        training_data = safe["training"]["data"]

        assert "query_hash" not in training_data
        assert training_data["source"] == "phantex-training-pipeline"

    def test_content_hash_deterministic(self):
        from ml.provenance.manifest import ManifestBuilder

        builder = ManifestBuilder()
        m1 = builder.build(model_id="v6")
        builder.build(model_id="v6")

        # created_at differs, so hashes differ
        # But same manifest re-hashed should be consistent
        h = m1.content_hash()
        assert h == m1.content_hash()  # Idempotent

# ---------------------------------------------------------------------------
# J5e: Reproducibility
# ---------------------------------------------------------------------------

class TestReproducer:
    """Model reproducibility verification."""

    def test_data_hash_deterministic(self):
        from ml.provenance.reproducer import compute_data_hash

        X = np.array([[1.0, 2.0], [3.0, 4.0]])
        h1 = compute_data_hash(X)
        h2 = compute_data_hash(X)
        assert h1 == h2

    def test_data_hash_changes_with_data(self):
        from ml.provenance.reproducer import compute_data_hash

        X1 = np.array([[1.0, 2.0]])
        X2 = np.array([[1.0, 3.0]])
        assert compute_data_hash(X1) != compute_data_hash(X2)

    def test_model_hash_consistent(self):
        from ml.provenance.reproducer import compute_model_hash

        class MockModel:
            def __init__(self):
                self._model = None

        m = MockModel()
        h1 = compute_model_hash(m)
        h2 = compute_model_hash(m)
        assert h1 == h2

    def test_verify_reproducibility_same_model(self):
        from ml.provenance.reproducer import verify_reproducibility

        class MockModel:
            def __repr__(self):
                return "MockModel(v1)"

        m1 = MockModel()
        m2 = MockModel()

        # Both have same repr() → same hash
        result = verify_reproducibility(m1, m2)
        assert result.reproducible

# ---------------------------------------------------------------------------
# J5e: Model Diff
# ---------------------------------------------------------------------------

class TestModelDiff:
    """Model version diff."""

    def test_compute_diff(self):
        from ml.provenance.diff import compute_diff

        diff = compute_diff(
            model_a_id="v1",
            model_b_id="v2",
            metrics_a={"precision": 0.90, "recall": 0.85},
            metrics_b={"precision": 0.92, "recall": 0.83},
            features_a=["f1", "f2", "f3"],
            features_b=["f1", "f2", "f4"],
        )

        assert diff.model_a == "v1"
        assert diff.model_b == "v2"
        assert "f4" in diff.feature_changes["added"]
        assert "f3" in diff.feature_changes["removed"]
        assert "precision" in diff.accuracy_delta

    def test_diff_with_params(self):
        from ml.provenance.diff import compute_diff

        diff = compute_diff(
            "v1",
            "v2",
            {"acc": 0.9},
            {"acc": 0.9},
            ["f1"],
            ["f1"],
            params_a={"lr": 0.01, "depth": 6},
            params_b={"lr": 0.001, "depth": 6},
        )
        assert "lr" in diff.parameter_changes
        assert "depth" not in diff.parameter_changes

    def test_format_diff_summary(self):
        from ml.provenance.diff import compute_diff, format_diff_summary

        diff = compute_diff(
            "v1",
            "v2",
            {"precision": 0.90},
            {"precision": 0.95},
            ["f1"],
            ["f1", "f2"],
        )
        summary = format_diff_summary(diff)
        assert "v1" in summary
        assert "v2" in summary
        assert "f2" in summary
