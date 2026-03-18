# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for J5d — Meta-Detection (Monitoring Own Models).
"""

from __future__ import annotations

import time

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# J5d: Drift Detector
# ---------------------------------------------------------------------------

class TestDriftDetector:
    """Feature and prediction distribution drift detection."""

    def test_no_drift_same_distribution(self):
        from ml.meta.drift_detector import DriftDetector

        rng = np.random.RandomState(42)
        baseline = rng.uniform(0, 1, 500)
        # Use the *same* baseline as current — truly identical distribution
        current = baseline.copy()

        detector = DriftDetector(kl_threshold=0.1)
        result = detector.check_prediction_drift(baseline, current)
        assert not result.drifted

    def test_drift_detected_different_distribution(self):
        from ml.meta.drift_detector import DriftDetector

        baseline = np.random.uniform(0.4, 0.6, 200)
        current = np.random.uniform(0.0, 0.2, 200)

        detector = DriftDetector(kl_threshold=0.1)
        result = detector.check_prediction_drift(baseline, current)
        assert result.drifted
        assert result.metric_value > 0.1

    def test_feature_drift_ks_test(self):
        from ml.meta.drift_detector import DriftDetector

        rng = np.random.RandomState(42)
        baseline = rng.randn(200, 3)
        current = rng.randn(200, 3) + 5  # Shifted features

        detector = DriftDetector()
        results = detector.check_feature_drift(baseline, current, ["f1", "f2", "f3"])
        assert len(results) == 3
        assert all(r.drifted for r in results)

    def test_check_all_summary(self):
        from ml.meta.drift_detector import DriftDetector

        rng = np.random.RandomState(42)
        baseline_scores = rng.uniform(0, 1, 200)
        current_scores = rng.uniform(0, 1, 200)

        detector = DriftDetector()
        summary = detector.check_all(baseline_scores, current_scores)
        assert "any_drift" in summary
        assert "prediction_drift" in summary

    def test_insufficient_data(self):
        from ml.meta.drift_detector import DriftDetector

        detector = DriftDetector()
        result = detector.check_prediction_drift(np.array([0.5]), np.array([0.5]))
        assert not result.drifted

# ---------------------------------------------------------------------------
# J5d: Accuracy Tracker
# ---------------------------------------------------------------------------

class TestAccuracyTracker:
    """Rolling accuracy tracker."""

    def test_perfect_accuracy(self):
        from ml.meta.accuracy_tracker import AccuracyTracker

        tracker = AccuracyTracker()
        for _ in range(20):
            tracker.record(True, True)  # TP
        for _ in range(20):
            tracker.record(False, False)  # TN

        snap = tracker.compute()
        assert snap.precision == 1.0
        assert snap.recall == 1.0
        assert snap.fpr == 0.0

    def test_degradation_detected(self):
        from ml.meta.accuracy_tracker import AccuracyTracker

        tracker = AccuracyTracker(precision_threshold=0.8)
        for _ in range(5):
            tracker.record(True, True)  # TP
        for _ in range(20):
            tracker.record(True, False)  # FP

        result = tracker.check_degradation()
        assert result["degraded"] is True
        assert any(i["metric"] == "precision" for i in result["issues"])

    def test_no_degradation_initially(self):
        from ml.meta.accuracy_tracker import AccuracyTracker

        tracker = AccuracyTracker()
        result = tracker.check_degradation()
        assert result["degraded"] is False

# ---------------------------------------------------------------------------
# J5d: Evasion Detector
# ---------------------------------------------------------------------------

class TestEvasionDetector:
    """Near-threshold clustering evasion detection."""

    def test_no_evasion_normal_distribution(self):
        from ml.meta.evasion_detector import EvasionDetector

        detector = EvasionDetector(threshold=0.70)
        rng = np.random.RandomState(42)
        scores = rng.uniform(0, 1, 100).tolist()
        detector.record_scores(scores)

        alert = detector.check()
        assert not alert.detected

    def test_evasion_detected_spike_below_threshold(self):
        from ml.meta.evasion_detector import EvasionDetector

        detector = EvasionDetector(threshold=0.70, ratio_trigger=3.0)

        # Normal scores
        rng = np.random.RandomState(42)
        normal = rng.uniform(0, 1, 50).tolist()
        detector.record_scores(normal)

        # Spike just below threshold (0.65-0.70)
        evasion = [0.68] * 50
        detector.record_scores(evasion)

        alert = detector.check()
        assert alert.detected
        assert alert.near_threshold_count >= 50

    def test_adjusted_threshold(self):
        from ml.meta.evasion_detector import EvasionDetector

        detector = EvasionDetector(
            threshold=0.70,
            max_threshold_adjustment=0.05,
        )
        # Trigger evasion detection
        detector.record_scores([0.68] * 100)
        adjusted = detector.get_adjusted_threshold()
        assert adjusted == pytest.approx(0.65, abs=0.001)

# ---------------------------------------------------------------------------
# J5d: Extraction Detector
# ---------------------------------------------------------------------------

class TestExtractionDetector:
    """API query rate anomaly detection."""

    def test_normal_usage_not_flagged(self):
        from ml.meta.extraction_detector import ExtractionDetector

        detector = ExtractionDetector(min_queries_for_baseline=20)
        for i in range(10):
            detector.record_query("user-1", f"entity-{i}")

        alert = detector.check_user("user-1")
        assert not alert.detected

    def test_extraction_detected_high_volume(self):
        from ml.meta.extraction_detector import ExtractionDetector

        detector = ExtractionDetector(
            rate_multiplier=2.0,
            min_queries_for_baseline=20,
        )
        # Establish baseline
        detector._avg_rate["user-1"] = 10.0
        # Flood with queries
        for i in range(50):
            detector.record_query("user-1", f"entity-{i}")

        alert = detector.check_user("user-1")
        assert alert.detected
        assert "throttle" in alert.recommended_action

    def test_should_throttle(self):
        from ml.meta.extraction_detector import ExtractionDetector

        detector = ExtractionDetector(min_queries_for_baseline=5)
        assert not detector.should_throttle("user-new")

# ---------------------------------------------------------------------------
# J5d: Poisoning Monitor
# ---------------------------------------------------------------------------

class TestPoisoningMonitor:
    """Training label distribution monitoring."""

    def test_normal_rate_no_alert(self):
        from ml.meta.poisoning_monitor import PoisoningMonitor

        monitor = PoisoningMonitor(min_events=10)
        for _ in range(19):
            monitor.record_label(False)  # confirmation
        monitor.record_label(True)  # 1 dismissal

        alert = monitor.check()
        assert not alert.detected

    def test_high_dismissal_rate_alert(self):
        from ml.meta.poisoning_monitor import PoisoningMonitor

        monitor = PoisoningMonitor(ratio_threshold=2.0, min_events=10)
        monitor.set_baseline_rate(0.05)

        for _ in range(15):
            monitor.record_label(True)  # dismissals
        for _ in range(5):
            monitor.record_label(False)  # confirmations

        alert = monitor.check()
        assert alert.detected
        assert alert.ratio >= 2.0

# ---------------------------------------------------------------------------
# J5d: Staleness Checker
# ---------------------------------------------------------------------------

class TestStalenessChecker:
    """Model age monitoring."""

    def test_fresh_model_not_stale(self):
        from ml.meta.staleness_checker import StalenessChecker

        checker = StalenessChecker(max_age_days=14)
        checker.register_model("v1")
        result = checker.check("v1")
        assert not result.stale

    def test_old_model_is_stale(self):
        from ml.meta.staleness_checker import StalenessChecker

        checker = StalenessChecker(max_age_days=14)
        old_time = time.time() - (15 * 86400)  # 15 days ago
        checker.register_model("v1", trained_at=old_time)

        result = checker.check("v1")
        assert result.stale
        assert result.age_days > 14

    def test_unregistered_model(self):
        from ml.meta.staleness_checker import StalenessChecker

        checker = StalenessChecker()
        result = checker.check("nonexistent")
        assert result.stale  # No training time = infinitely stale

# ---------------------------------------------------------------------------
# J5d: Meta-Alerter
# ---------------------------------------------------------------------------

class TestMetaAlerter:
    """Meta-alert routing."""

    def test_fire_and_query(self):
        from ml.meta.alerter import MetaAlerter, MetaAlertSeverity, MetaAlertType

        alerter = MetaAlerter()
        alert = alerter.fire(
            MetaAlertType.ACCURACY_DRIFT,
            "Precision dropped to 0.72",
            {"precision": 0.72},
        )
        assert alert.severity == MetaAlertSeverity.WARNING
        assert "ops_team" in alert.channels
        assert alerter.alert_count == 1

    def test_critical_alerts(self):
        from ml.meta.alerter import MetaAlerter, MetaAlertSeverity, MetaAlertType

        alerter = MetaAlerter()
        alert = alerter.fire(
            MetaAlertType.EVASION_PATTERN,
            "Evasion detected",
        )
        assert alert.severity == MetaAlertSeverity.CRITICAL
        assert "customer_admin" in alert.channels

    def test_filter_by_type(self):
        from ml.meta.alerter import MetaAlerter, MetaAlertType

        alerter = MetaAlerter()
        alerter.fire(MetaAlertType.MODEL_STALE, "stale")
        alerter.fire(MetaAlertType.EVASION_PATTERN, "evasion")
        alerter.fire(MetaAlertType.MODEL_STALE, "stale again")

        stale_alerts = alerter.get_alerts(alert_type=MetaAlertType.MODEL_STALE)
        assert len(stale_alerts) == 2

    def test_clear(self):
        from ml.meta.alerter import MetaAlerter, MetaAlertType

        alerter = MetaAlerter()
        alerter.fire(MetaAlertType.MODEL_STALE, "test")
        alerter.clear()
        assert alerter.alert_count == 0
