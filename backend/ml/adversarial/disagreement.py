# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Ensemble Disagreement Detector (J5a).

Monitors when ML pipeline stages disagree on a prediction, which can indicate:
1. Adversarial input specifically crafted to evade one stage
2. Novel/unseen behavior that splits model opinions
3. Model degradation in one stage

Rule: if ANY stage flags as high-confidence anomaly, never suppress the alert.
High disagreement rate (≥3× normal) triggers meta-detection alert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.adversarial.disagreement")

@dataclass
class DisagreementResult:
    """Analysis of ensemble stage disagreements."""

    total_samples: int
    disagreement_count: int
    disagreement_rate: float
    high_confidence_overrides: int
    stage_agreement_matrix: dict[str, dict[str, float]]
    details: dict[str, Any] = field(default_factory=dict)

def analyze_disagreement(
    stage1_scores: NDArray[np.floating],
    stage2_labels: NDArray[np.integer],
    stage3_errors: NDArray[np.floating],
    stage1_threshold: float = 0.5,
    stage2_anomaly_labels: set[int] | None = None,
    stage3_threshold: float = 0.5,
) -> DisagreementResult:
    """Analyze disagreement between ensemble stages.

    Args:
        stage1_scores: Isolation Forest anomaly scores (higher = more anomalous).
        stage2_labels: XGBoost predicted class labels (0 = benign, 1-7 = attack).
        stage3_errors: Autoencoder reconstruction errors (higher = more anomalous).
        stage1_threshold: IF anomaly threshold.
        stage2_anomaly_labels: Set of labels considered anomalous. Default: {1..7}.
        stage3_threshold: AE reconstruction error threshold.

    Returns:
        DisagreementResult with analysis.
    """
    if stage2_anomaly_labels is None:
        stage2_anomaly_labels = set(range(1, 8))

    n = len(stage1_scores)
    assert len(stage2_labels) == n and len(stage3_errors) == n

    s1_flag = stage1_scores > stage1_threshold
    s2_flag = np.array([lbl in stage2_anomaly_labels for lbl in stage2_labels])
    s3_flag = stage3_errors > stage3_threshold

    # Disagreement: at least one stage disagrees with the majority
    votes = s1_flag.astype(int) + s2_flag.astype(int) + s3_flag.astype(int)
    # Unanimous agreement = 0 (all benign) or 3 (all anomalous)
    disagreement = (votes == 1) | (votes == 2)
    disagreement_count = int(disagreement.sum())

    # High-confidence override: any single stage with very high confidence
    # says anomaly, but majority says benign → still alert (safety first)
    high_confidence_s1 = stage1_scores > (stage1_threshold * 1.5)
    high_confidence_s3 = stage3_errors > (stage3_threshold * 1.5)
    override = (
        (high_confidence_s1 & ~s2_flag & ~s3_flag)
        | (s2_flag & ~s1_flag & ~s3_flag)
        | (high_confidence_s3 & ~s1_flag & ~s2_flag)
    )
    override_count = int(override.sum())

    # Pairwise agreement rates
    def _agree_rate(a: NDArray, b: NDArray) -> float:
        return float((a == b).mean()) if n > 0 else 0.0

    agreement_matrix = {
        "s1_s2": {"agree": _agree_rate(s1_flag, s2_flag)},
        "s1_s3": {"agree": _agree_rate(s1_flag, s3_flag)},
        "s2_s3": {"agree": _agree_rate(s2_flag, s3_flag)},
    }

    disagreement_rate = disagreement_count / max(n, 1)

    logger.info(
        "disagreement_analysis",
        total=n,
        disagreements=disagreement_count,
        rate=disagreement_rate,
        overrides=override_count,
    )

    return DisagreementResult(
        total_samples=n,
        disagreement_count=disagreement_count,
        disagreement_rate=disagreement_rate,
        high_confidence_overrides=override_count,
        stage_agreement_matrix=agreement_matrix,
        details={
            "s1_anomaly_count": int(s1_flag.sum()),
            "s2_anomaly_count": int(s2_flag.sum()),
            "s3_anomaly_count": int(s3_flag.sum()),
            "unanimous_benign": int((votes == 0).sum()),
            "unanimous_anomaly": int((votes == 3).sum()),
        },
    )

def is_adversarial_suspected(
    current_disagreement_rate: float,
    baseline_disagreement_rate: float,
    multiplier_threshold: float = 3.0,
) -> bool:
    """Check if current disagreement rate suggests adversarial activity.

    If disagreement rate is ≥ multiplier_threshold × baseline → suspected.

    Args:
        current_disagreement_rate: Current window disagreement rate.
        baseline_disagreement_rate: Historical average disagreement rate.
        multiplier_threshold: How many times baseline before suspicion (default: 3×).

    Returns:
        True if adversarial activity suspected.
    """
    if baseline_disagreement_rate <= 0:
        return current_disagreement_rate > 0.1  # Fallback: >10% = suspicious

    return current_disagreement_rate >= (baseline_disagreement_rate * multiplier_threshold)
