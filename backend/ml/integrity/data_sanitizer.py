# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Training Data Sanitizer (J5b).

Pre-training pipeline that detects and removes potentially poisoned samples.
Runs before every training job.

Checks:
1. Feature outliers (>4σ from tenant mean on 3+ features)
2. Event volume anomaly (>10× normal for agent)
3. Label override audit (dismissed-then-overridden labels)
4. Spectral analysis (anomalous small clusters with uniform labels)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.integrity.data_sanitizer")

@dataclass
class SanitizationReport:
    """Report of training data sanitization."""

    total_samples: int
    removed_samples: int
    retained_samples: int
    outlier_removals: int
    volume_anomaly_removals: int
    label_override_removals: int
    spectral_removals: int
    removal_rate: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "removed_samples": self.removed_samples,
            "retained_samples": self.retained_samples,
            "outlier_removals": self.outlier_removals,
            "volume_anomaly_removals": self.volume_anomaly_removals,
            "label_override_removals": self.label_override_removals,
            "spectral_removals": self.spectral_removals,
            "removal_rate": self.removal_rate,
            **self.details,
        }

class DataSanitizer:
    """Training data sanitization pipeline."""

    def __init__(
        self,
        outlier_sigma: float = 4.0,
        outlier_min_features: int = 3,
        volume_multiplier: float = 10.0,
        spectral_min_cluster_pct: float = 0.01,
        downweight_factor: float = 0.1,
    ) -> None:
        """
        Args:
            outlier_sigma: σ threshold for feature outlier detection.
            outlier_min_features: Min features exceeding σ to flag sample.
            volume_multiplier: Volume multiplier for agent anomaly.
            spectral_min_cluster_pct: Min cluster size % for spectral check.
            downweight_factor: Weight for flagged but not removed samples.
        """
        self._outlier_sigma = outlier_sigma
        self._outlier_min_features = outlier_min_features
        self._volume_multiplier = volume_multiplier
        self._spectral_min_pct = spectral_min_cluster_pct
        self._downweight = downweight_factor

    def sanitize(
        self,
        X: NDArray[np.floating],
        y: NDArray | None = None,
        agent_ids: list[str] | None = None,
        event_counts: NDArray | None = None,
        label_overrides: set[int] | None = None,
    ) -> tuple[NDArray[np.floating], NDArray | None, SanitizationReport, NDArray[np.bool_]]:
        """Run full sanitization pipeline on training data.

        Args:
            X: Feature matrix (n_samples, n_features).
            y: Labels (optional).
            agent_ids: Agent ID per sample (for volume check).
            event_counts: Per-agent event counts (for volume anomaly).
            label_overrides: Indices of samples with overridden labels.

        Returns:
            (X_clean, y_clean, report, keep_mask) — cleaned data, report,
            and boolean mask of retained sample indices.
        """
        n_total = len(X)
        flagged = np.zeros(n_total, dtype=bool)

        # 1. Feature outliers
        outlier_flags = self._detect_outliers(X)
        n_outliers = int(outlier_flags.sum())
        flagged |= outlier_flags

        # 2. Volume anomaly
        n_volume = 0
        if agent_ids is not None and event_counts is not None:
            volume_flags = self._detect_volume_anomaly(agent_ids, event_counts)
            n_volume = int(volume_flags.sum())
            flagged |= volume_flags

        # 3. Label override audit
        n_override = 0
        if label_overrides:
            override_flags = np.zeros(n_total, dtype=bool)
            valid_indices = [i for i in label_overrides if 0 <= i < n_total]
            if valid_indices:
                override_flags[valid_indices] = True
            n_override = int(override_flags.sum())
            flagged |= override_flags

        # 4. Spectral analysis
        spectral_flags = self._spectral_analysis(X, y)
        n_spectral = int(spectral_flags.sum())
        flagged |= spectral_flags

        # Remove flagged samples
        keep_mask = ~flagged
        X_clean = X[keep_mask]
        y_clean = y[keep_mask] if y is not None else None

        n_removed = int(flagged.sum())

        report = SanitizationReport(
            total_samples=n_total,
            removed_samples=n_removed,
            retained_samples=n_total - n_removed,
            outlier_removals=n_outliers,
            volume_anomaly_removals=n_volume,
            label_override_removals=n_override,
            spectral_removals=n_spectral,
            removal_rate=n_removed / max(n_total, 1),
        )

        logger.info(
            "data_sanitization_complete",
            total=n_total,
            removed=n_removed,
            outliers=n_outliers,
            volume_anomalies=n_volume,
            label_overrides=n_override,
            spectral=n_spectral,
        )

        return X_clean, y_clean, report, keep_mask

    def _detect_outliers(self, X: NDArray[np.floating]) -> NDArray[np.bool_]:
        """Flag samples with >outlier_min_features features exceeding 4σ."""
        if len(X) < 10:
            return np.zeros(len(X), dtype=bool)

        mean = X.mean(axis=0)
        std = X.std(axis=0)
        std[std == 0] = 1.0

        z_scores = np.abs((X - mean) / std)
        extreme_features = (z_scores > self._outlier_sigma).sum(axis=1)

        return extreme_features >= self._outlier_min_features

    def _detect_volume_anomaly(
        self,
        agent_ids: list[str],
        event_counts: NDArray,
    ) -> NDArray[np.bool_]:
        """Flag samples from agents with event volume >10× normal."""
        unique_agents = set(agent_ids)
        mean_volume = float(event_counts.mean()) if len(event_counts) > 0 else 0.0

        anomalous_agents = set()
        for agent in unique_agents:
            agent_mask = np.array([a == agent for a in agent_ids])
            agent_count = event_counts[agent_mask].sum() if agent_mask.any() else 0
            if mean_volume > 0 and agent_count > mean_volume * self._volume_multiplier:
                anomalous_agents.add(agent)

        return np.array([a in anomalous_agents for a in agent_ids], dtype=bool)

    def _spectral_analysis(
        self,
        X: NDArray[np.floating],
        y: NDArray | None = None,
    ) -> NDArray[np.bool_]:
        """Detect anomalous small clusters with suspiciously uniform labels.

        Simple approach: k-means-like clustering via distance from centroid,
        flag tiny clusters where all labels are the same (potential backdoor).
        """
        n = len(X)
        if n < 100 or y is None:
            return np.zeros(n, dtype=bool)

        # Compute distance from global centroid
        centroid = X.mean(axis=0)
        distances = np.linalg.norm(X - centroid, axis=1)

        # Flag samples in far-flung clusters (>3σ distance) with uniform labels
        dist_mean = distances.mean()
        dist_std = distances.std()
        if dist_std == 0:
            return np.zeros(n, dtype=bool)

        far_mask = distances > (dist_mean + 3 * dist_std)
        far_count = int(far_mask.sum())

        if far_count < 2 or far_count / n > self._spectral_min_pct * 10:
            # Too few or too many — not a targeted backdoor
            return np.zeros(n, dtype=bool)

        # Check if far samples have suspiciously uniform labels
        far_labels = y[far_mask]
        unique_labels = np.unique(far_labels)
        if len(unique_labels) == 1:
            # All far samples have same label — suspicious
            logger.warning(
                "spectral_anomaly_detected",
                cluster_size=far_count,
                label=int(unique_labels[0]),
            )
            return far_mask

        return np.zeros(n, dtype=bool)
