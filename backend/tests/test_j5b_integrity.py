# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for J5b — Training Data Integrity & Poisoning Defense.
"""

from __future__ import annotations

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# J5b: Label Governance
# ---------------------------------------------------------------------------

class TestLabelGovernance:
    """Dual-approval label governance workflow."""

    def test_analyst_confirm_sets_positive_label(self):
        from ml.integrity.label_governance import LabelGovernance, TrainingLabel

        gov = LabelGovernance()
        gov.analyst_confirm("alert-1", "analyst-A")
        labels = gov.get_training_labels()
        assert labels["alert-1"] == TrainingLabel.POSITIVE

    def test_analyst_dismiss_sets_pending_review(self):
        from ml.integrity.label_governance import LabelGovernance

        gov = LabelGovernance()
        gov.analyst_dismiss("alert-2", "analyst-A", reason="false positive")
        reviews = gov.get_pending_reviews()
        assert len(reviews) == 1
        assert reviews[0].alert_id == "alert-2"

    def test_admin_approve_dismissal_sets_negative(self):
        from ml.integrity.label_governance import LabelGovernance, TrainingLabel

        gov = LabelGovernance()
        gov.analyst_dismiss("alert-3", "analyst-A", "false positive")
        gov.admin_approve_dismissal("alert-3", "admin-B")
        labels = gov.get_training_labels()
        assert labels["alert-3"] == TrainingLabel.NEGATIVE

    def test_admin_reject_dismissal_keeps_positive(self):
        from ml.integrity.label_governance import LabelGovernance, TrainingLabel

        gov = LabelGovernance()
        gov.analyst_dismiss("alert-4", "analyst-A", "misidentified")
        gov.admin_reject_dismissal("alert-4", "admin-B", "actually malicious")
        labels = gov.get_training_labels()
        assert labels["alert-4"] == TrainingLabel.POSITIVE

    def test_separation_of_duties_enforced(self):
        from ml.integrity.label_governance import LabelGovernance

        gov = LabelGovernance()
        gov.analyst_dismiss("alert-5", "user-X", "test dismissal")
        with pytest.raises(ValueError, match="separation of duties"):
            gov.admin_approve_dismissal("alert-5", "user-X")

    def test_label_stats(self):
        from ml.integrity.label_governance import LabelGovernance

        gov = LabelGovernance()
        gov.analyst_confirm("a1", "analyst-A")
        gov.analyst_confirm("a2", "analyst-A")
        gov.analyst_dismiss("a3", "analyst-A", "false alarm")
        gov.admin_approve_dismissal("a3", "admin-B")

        stats = gov.get_label_stats()
        assert stats["confirmed"] == 2
        assert stats["dismissed"] == 1

# ---------------------------------------------------------------------------
# J5b: Data Sanitizer
# ---------------------------------------------------------------------------

class TestDataSanitizer:
    """Training data sanitization pipeline."""

    def test_outlier_removal(self):
        from ml.integrity.data_sanitizer import DataSanitizer

        rng = np.random.RandomState(42)
        X = rng.randn(100, 10).astype(np.float32)

        # Inject 3 extreme outliers
        X[0] = 20.0  # All features extreme
        X[1] = -20.0
        X[2] = 15.0

        sanitizer = DataSanitizer(outlier_sigma=4.0, outlier_min_features=3)
        X_clean, _, report, keep_mask = sanitizer.sanitize(X)

        assert report.outlier_removals >= 3
        assert report.retained_samples < 100
        assert keep_mask.sum() == report.retained_samples

    def test_volume_anomaly_removal(self):
        from ml.integrity.data_sanitizer import DataSanitizer

        X = np.random.randn(50, 5).astype(np.float32)
        agent_ids = ["a"] * 40 + ["b"] * 10
        event_counts = np.array([1] * 40 + [100] * 10)

        sanitizer = DataSanitizer()
        X_clean, _, report, _ = sanitizer.sanitize(X, agent_ids=agent_ids, event_counts=event_counts)
        assert report.volume_anomaly_removals > 0

    def test_label_override_removal(self):
        from ml.integrity.data_sanitizer import DataSanitizer

        X = np.random.randn(30, 5).astype(np.float32)
        overrides = {0, 1, 2}

        sanitizer = DataSanitizer()
        X_clean, _, report, _ = sanitizer.sanitize(X, label_overrides=overrides)
        assert report.label_override_removals == 3

    def test_preserves_labels(self):
        from ml.integrity.data_sanitizer import DataSanitizer

        X = np.random.randn(20, 5).astype(np.float32)
        y = np.array([0] * 10 + [1] * 10)

        sanitizer = DataSanitizer()
        X_clean, y_clean, report, _ = sanitizer.sanitize(X, y=y)
        assert len(X_clean) == len(y_clean)

    def test_sanitization_report_fields(self):
        from ml.integrity.data_sanitizer import DataSanitizer, SanitizationReport

        X = np.random.randn(50, 5).astype(np.float32)
        sanitizer = DataSanitizer()
        _, _, report, _ = sanitizer.sanitize(X)

        assert isinstance(report, SanitizationReport)
        assert report.total_samples == 50
        assert report.retained_samples + report.removed_samples == 50

# ---------------------------------------------------------------------------
# J5b: Spectral Analysis
# ---------------------------------------------------------------------------

class TestSpectralAnalysis:
    """Spectral backdoor detection."""

    def test_no_backdoor_in_clean_data(self):
        from ml.integrity.spectral_analysis import detect_backdoor_cluster

        rng = np.random.RandomState(42)
        X = rng.randn(500, 10)
        y = rng.randint(0, 2, 500)

        result = detect_backdoor_cluster(X, y)
        assert not result.suspected_backdoor

    def test_detects_planted_backdoor_cluster(self):
        from ml.integrity.spectral_analysis import detect_backdoor_cluster

        rng = np.random.RandomState(42)
        X = rng.randn(1000, 10)
        y = rng.randint(0, 2, 1000)

        # Plant a small cluster (5 samples) with extreme features and uniform label
        n_poison = 5
        X[-n_poison:] = 50.0  # Very far from centroid
        y[-n_poison:] = 1  # All same label

        result = detect_backdoor_cluster(
            X,
            y,
            outlier_threshold=3.0,
            min_cluster_pct=0.001,
            max_cluster_pct=0.01,
        )
        assert result.suspected_backdoor
        assert len(result.flagged_indices) >= n_poison

    def test_too_few_samples_returns_safe(self):
        from ml.integrity.spectral_analysis import detect_backdoor_cluster

        X = np.random.randn(50, 5)
        y = np.random.randint(0, 2, 50)
        result = detect_backdoor_cluster(X, y)
        assert not result.suspected_backdoor

    def test_remove_spectral_outliers(self):
        from ml.integrity.spectral_analysis import remove_spectral_outliers

        rng = np.random.RandomState(42)
        X = rng.randn(500, 5)
        y = rng.randint(0, 2, 500)

        X_clean, y_clean, result = remove_spectral_outliers(X, y)
        assert len(X_clean) <= len(X)
        assert len(y_clean) == len(X_clean)

# ---------------------------------------------------------------------------
# J5b: Training Audit
# ---------------------------------------------------------------------------

class TestTrainingAudit:
    """Immutable training data audit trail."""

    def test_append_and_query(self):
        from ml.integrity.audit import AuditAction, TrainingAuditLog

        log = TrainingAuditLog()
        log.append(AuditAction.TRAINING_STARTED, "system", "tenant-1")
        log.append(AuditAction.TRAINING_COMPLETED, "system", "tenant-1")

        assert log.length == 2
        entries = log.get_entries(tenant_id="tenant-1")
        assert len(entries) == 2

    def test_hash_chain_integrity(self):
        from ml.integrity.audit import AuditAction, TrainingAuditLog

        log = TrainingAuditLog()
        log.append(AuditAction.LABEL_CONFIRMED, "analyst-A", "t1")
        log.append(AuditAction.LABEL_DISMISSED, "analyst-B", "t1")
        log.append(AuditAction.LABEL_APPROVED, "admin-C", "t1")

        assert log.verify_chain() is True

    def test_tampered_chain_fails(self):
        from ml.integrity.audit import AuditAction, TrainingAuditLog

        log = TrainingAuditLog()
        log.append(AuditAction.LABEL_CONFIRMED, "a", "t1")
        log.append(AuditAction.LABEL_DISMISSED, "b", "t1")

        # Tamper with the first entry
        log._entries[0].entry_hash = "tampered"
        assert log.verify_chain() is False

    def test_convenience_methods(self):
        from ml.integrity.audit import AuditAction, TrainingAuditLog

        log = TrainingAuditLog()
        log.log_label_action(AuditAction.LABEL_CONFIRMED, "analyst", "t1", "alert-1")
        log.log_sanitization("system", "t1", {"removed": 5})
        log.log_sample_removal("system", "t1", AuditAction.SAMPLE_REMOVED_OUTLIER, 10)

        assert log.length == 3

    def test_filter_by_action(self):
        from ml.integrity.audit import AuditAction, TrainingAuditLog

        log = TrainingAuditLog()
        log.append(AuditAction.LABEL_CONFIRMED, "a", "t1")
        log.append(AuditAction.TRAINING_STARTED, "s", "t1")
        log.append(AuditAction.LABEL_CONFIRMED, "b", "t1")

        entries = log.get_entries(action=AuditAction.LABEL_CONFIRMED)
        assert len(entries) == 2
