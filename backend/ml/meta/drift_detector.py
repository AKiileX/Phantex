# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Feature & Prediction Distribution Drift Detector (J5d).

Monitors KL divergence of prediction score distributions and
Kolmogorov-Smirnov tests on individual feature distributions
versus the training baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.meta.drift_detector")

try:
    from scipy import stats as sp_stats
except ImportError:
    sp_stats = None  # type: ignore[assignment]

@dataclass
class DriftResult:
    """Result of a drift check."""

    drifted: bool
    metric_name: str
    metric_value: float
    threshold: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "drifted": self.drifted,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            **self.details,
        }

class DriftDetector:
    """Detect feature and prediction distribution drift."""

    def __init__(
        self,
        kl_threshold: float = 0.1,
        ks_pvalue_threshold: float = 0.01,
    ) -> None:
        """
        Args:
            kl_threshold: KL divergence above which prediction drift is flagged.
            ks_pvalue_threshold: KS test p-value below which feature drift is flagged.
        """
        self._kl_threshold = kl_threshold
        self._ks_pvalue = ks_pvalue_threshold

    def check_prediction_drift(
        self,
        baseline_scores: NDArray[np.floating],
        current_scores: NDArray[np.floating],
        n_bins: int = 50,
    ) -> DriftResult:
        """Check prediction score distribution drift via KL divergence.

        Args:
            baseline_scores: Score distribution from training/validation.
            current_scores: Recent production scores.
            n_bins: Histogram bins for discretisation.

        Returns:
            DriftResult indicating whether drift is detected.
        """
        if len(baseline_scores) < 10 or len(current_scores) < 10:
            return DriftResult(
                drifted=False,
                metric_name="kl_divergence",
                metric_value=0.0,
                threshold=self._kl_threshold,
                details={"reason": "insufficient_data"},
            )

        # Create histograms with same bins
        bins = np.linspace(0, 1, n_bins + 1)
        p, _ = np.histogram(baseline_scores, bins=bins, density=True)
        q, _ = np.histogram(current_scores, bins=bins, density=True)

        # Add small epsilon to avoid log(0)
        eps = 1e-10
        p = p + eps
        q = q + eps

        # Normalize to proper distributions
        p = p / p.sum()
        q = q / q.sum()

        # KL divergence: D_KL(Q || P)
        kl_div = float(np.sum(q * np.log(q / p)))

        return DriftResult(
            drifted=kl_div > self._kl_threshold,
            metric_name="kl_divergence",
            metric_value=kl_div,
            threshold=self._kl_threshold,
            details={"n_baseline": len(baseline_scores), "n_current": len(current_scores)},
        )

    def check_feature_drift(
        self,
        baseline: NDArray[np.floating],
        current: NDArray[np.floating],
        feature_names: list[str],
    ) -> list[DriftResult]:
        """Check per-feature distribution drift via Kolmogorov-Smirnov test.

        Args:
            baseline: Baseline feature matrix (n_samples, n_features).
            current: Current feature matrix.
            feature_names: Feature names (same order as columns).

        Returns:
            List of DriftResult per feature.
        """
        if sp_stats is None:
            logger.warning("scipy_not_available_for_ks_test")
            return []

        results = []
        n_features = min(baseline.shape[1], current.shape[1], len(feature_names))

        for i in range(n_features):
            stat, pvalue = sp_stats.ks_2samp(baseline[:, i], current[:, i])
            drifted = pvalue < self._ks_pvalue

            results.append(
                DriftResult(
                    drifted=drifted,
                    metric_name=f"ks_test_{feature_names[i]}",
                    metric_value=float(stat),
                    threshold=self._ks_pvalue,
                    details={
                        "feature": feature_names[i],
                        "ks_statistic": float(stat),
                        "p_value": float(pvalue),
                    },
                )
            )

        return results

    def check_all(
        self,
        baseline_scores: NDArray[np.floating],
        current_scores: NDArray[np.floating],
        baseline_features: NDArray[np.floating] | None = None,
        current_features: NDArray[np.floating] | None = None,
        feature_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run all drift checks and return summary.

        Returns:
            Dict with prediction_drift, feature_drifts, any_drift flag.
        """
        pred_drift = self.check_prediction_drift(baseline_scores, current_scores)

        feature_drifts: list[DriftResult] = []
        if baseline_features is not None and current_features is not None and feature_names:
            feature_drifts = self.check_feature_drift(baseline_features, current_features, feature_names)

        drifted_features = [d for d in feature_drifts if d.drifted]

        return {
            "prediction_drift": pred_drift.to_dict(),
            "feature_drifts": [d.to_dict() for d in drifted_features],
            "total_features_checked": len(feature_drifts),
            "drifted_feature_count": len(drifted_features),
            "any_drift": pred_drift.drifted or len(drifted_features) > 0,
        }
