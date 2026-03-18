# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Phantex ML Adversarial Robustness (J5a)."""

from ml.adversarial.adversarial_trainer import augment_training_data, generate_adversarial_samples
from ml.adversarial.attacks import AttackResult, feature_perturbation_attack, fgsm_attack, pgd_attack
from ml.adversarial.certified import CertifiedResult, certify_isolation_forest
from ml.adversarial.disagreement import DisagreementResult, analyze_disagreement, is_adversarial_suspected
from ml.adversarial.robustness_test import RobustnessReport, run_robustness_benchmark

__all__ = [
    "fgsm_attack",
    "pgd_attack",
    "feature_perturbation_attack",
    "AttackResult",
    "run_robustness_benchmark",
    "RobustnessReport",
    "augment_training_data",
    "generate_adversarial_samples",
    "certify_isolation_forest",
    "CertifiedResult",
    "analyze_disagreement",
    "is_adversarial_suspected",
    "DisagreementResult",
]
