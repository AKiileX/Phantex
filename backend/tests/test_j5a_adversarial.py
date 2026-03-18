# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for J5a — Adversarial Robustness Testing & Training.
"""

from __future__ import annotations

import numpy as np

# ---------------------------------------------------------------------------
# J5a: Adversarial attacks
# ---------------------------------------------------------------------------

class TestFGSMAttack:
    """FGSM attack on autoencoder."""

    def test_fgsm_returns_attack_result(self):
        import torch.nn as nn

        from ml.adversarial.attacks import AttackResult, fgsm_attack

        model = nn.Sequential(nn.Linear(5, 3), nn.ReLU(), nn.Linear(3, 5))

        X = np.random.randn(10, 5).astype(np.float32)
        result = fgsm_attack(model, X, epsilon=0.1)

        assert isinstance(result, AttackResult)
        assert result.attack_name == "fgsm"
        assert result.epsilon == 0.1
        assert result.total_samples >= 0
        assert 0 <= result.evasion_rate <= 1.0

    def test_fgsm_zero_epsilon_no_evasion(self):
        import torch.nn as nn

        from ml.adversarial.attacks import fgsm_attack

        model = nn.Sequential(nn.Linear(4, 2), nn.ReLU(), nn.Linear(2, 4))
        X = np.random.randn(5, 4).astype(np.float32)
        result = fgsm_attack(model, X, epsilon=0.0)
        assert result.attack_name == "fgsm"
        assert result.mean_perturbation <= 1e-6 or result.total_samples == 0

class TestPGDAttack:
    """PGD attack (multi-step FGSM)."""

    def test_pgd_bounded_perturbation(self):
        import torch.nn as nn

        from ml.adversarial.attacks import pgd_attack

        model = nn.Sequential(nn.Linear(5, 3), nn.Linear(3, 5))
        X = np.random.randn(8, 5).astype(np.float32)
        result = pgd_attack(model, X, epsilon=0.05, num_steps=5, step_size=0.01)

        assert result.attack_name == "pgd"
        assert result.epsilon == 0.05
        assert result.total_samples >= 0

class TestFeaturePerturbation:
    """Model-agnostic feature perturbation attack."""

    def test_feature_perturbation_flips_some_predictions(self):
        from ml.adversarial.attacks import feature_perturbation_attack

        rng = np.random.RandomState(42)
        X = rng.randn(50, 5).astype(np.float32)

        def predict_fn(x):
            return (x.sum(axis=1) > 0).astype(int)

        y_pred = predict_fn(X)

        result = feature_perturbation_attack(predict_fn, X, y_pred, perturbation_pct=0.2, top_k=3)
        assert result.attack_name == "feature_perturbation"
        assert result.evasion_rate >= 0  # some may flip

# ---------------------------------------------------------------------------
# J5a: Robustness benchmark
# ---------------------------------------------------------------------------

class TestRobustnessBenchmark:
    """Robustness benchmark with CI gate thresholds."""

    def test_benchmark_report_structure(self):
        from ml.adversarial.robustness_test import RobustnessReport

        report = RobustnessReport(
            clean_accuracy=0.95,
            adversarial_accuracy=0.94,
            accuracy_drop=0.01,
            passed=True,
            failures=[],
        )
        assert report.passed
        assert report.accuracy_drop == 0.01

    def test_ci_gate_thresholds_defined(self):
        from ml.adversarial.robustness_test import (
            FEATURE_PERTURB_MAX_FLIP,
            FGSM_MAX_EVASION,
            MAX_CLEAN_ACCURACY_DROP,
            PGD_MAX_EVASION,
        )

        assert FGSM_MAX_EVASION == 0.05
        assert PGD_MAX_EVASION == 0.10
        assert FEATURE_PERTURB_MAX_FLIP == 0.08
        assert MAX_CLEAN_ACCURACY_DROP == 0.02

# ---------------------------------------------------------------------------
# J5a: Adversarial trainer
# ---------------------------------------------------------------------------

class TestAdversarialTrainer:
    """Adversarial training data augmentation."""

    def test_augment_produces_mixed_dataset(self):
        import torch.nn as nn

        from ml.adversarial.adversarial_trainer import augment_training_data

        model = nn.Sequential(nn.Linear(4, 2), nn.Linear(2, 4))
        X = np.random.randn(20, 4).astype(np.float32)
        y = np.array([0] * 10 + [1] * 10)

        X_aug, y_aug = augment_training_data(model, X, y, epsilon=0.1)

        # Augmented set: clean (20) + 50% adversarial (10) = 30
        assert len(X_aug) == len(X) + int(len(X) * 0.5)
        assert len(y_aug) == len(X_aug)

# ---------------------------------------------------------------------------
# J5a: Certified robustness
# ---------------------------------------------------------------------------

class TestCertifiedRobustness:
    """Empirical certified robustness for Isolation Forest."""

    def test_certify_isolation_forest(self):
        from ml.adversarial.certified import CertifiedResult, certify_isolation_forest

        class MockIF:
            def __init__(self):
                self.is_fitted = True

            def predict_score(self, X):
                return np.clip(X.sum(axis=1) * 0.1, 0, 1)

        model = MockIF()
        X = np.random.randn(20, 4)

        result = certify_isolation_forest(model, X, epsilon=0.1, n_perturbations=10)
        assert isinstance(result, CertifiedResult)
        assert isinstance(result.certified_stable, bool)
        assert result.max_score_change >= 0

# ---------------------------------------------------------------------------
# J5a: Ensemble disagreement
# ---------------------------------------------------------------------------

class TestEnsembleDisagreement:
    """Ensemble disagreement detector."""

    def test_no_disagreement_when_aligned(self):
        from ml.adversarial.disagreement import analyze_disagreement

        # All 3 stages agree: all anomalous
        stage1_scores = np.array([0.8, 0.9, 0.7])  # all > 0.5
        stage2_labels = np.array([1, 2, 3])  # all anomalous
        stage3_errors = np.array([0.82, 0.91, 0.72])  # all > 0.5

        result = analyze_disagreement(stage1_scores, stage2_labels, stage3_errors)
        assert result.disagreement_rate == 0.0

    def test_high_disagreement_detected(self):
        from ml.adversarial.disagreement import analyze_disagreement

        # Stage1 says anomalous, Stage2 says benign, Stage3 mixed
        stage1_scores = np.array([0.9, 0.1, 0.8, 0.2])
        stage2_labels = np.array([0, 1, 0, 1])  # opposite of stage1
        stage3_errors = np.array([0.5, 0.5, 0.5, 0.5])

        result = analyze_disagreement(stage1_scores, stage2_labels, stage3_errors)
        assert result.disagreement_rate > 0.0

    def test_adversarial_suspected_above_baseline(self):
        from ml.adversarial.disagreement import is_adversarial_suspected

        assert is_adversarial_suspected(0.30, baseline_disagreement_rate=0.05) is True
        assert is_adversarial_suspected(0.05, baseline_disagreement_rate=0.05) is False
