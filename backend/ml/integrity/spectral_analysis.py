# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Spectral Signature Backdoor Detection (J5b).

Detect planted backdoor clusters in training data via spectral analysis.
A backdoor attack typically injects a small cluster (<1% of data) with:
- Uniform labels (all flagged or all benign)
- Features that differ subtly but coherently from the normal population

Detection approach:
1. Center the feature matrix
2. Compute top-k singular vectors (SVD)
3. Project data onto top singular vectors
4. Detect outlier clusters in the projection (small, tight, uniform-label)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

logger = structlog.get_logger("phantex.ml.integrity.spectral_analysis")

@dataclass
class SpectralResult:
    """Result of spectral backdoor analysis."""

    suspected_backdoor: bool
    cluster_sizes: list[int]
    cluster_label_purity: list[float]
    flagged_indices: list[int]
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suspected_backdoor": self.suspected_backdoor,
            "cluster_sizes": self.cluster_sizes,
            "cluster_label_purity": self.cluster_label_purity,
            "flagged_count": len(self.flagged_indices),
            **self.details,
        }

def detect_backdoor_cluster(
    X: NDArray[np.floating],
    y: NDArray,
    *,
    n_components: int = 3,
    outlier_threshold: float = 3.0,
    min_cluster_pct: float = 0.001,
    max_cluster_pct: float = 0.01,
    purity_threshold: float = 0.95,
) -> SpectralResult:
    """Detect backdoor clusters via spectral analysis.

    Args:
        X: Feature matrix (n_samples, n_features).
        y: Labels (0 or 1).
        n_components: Number of SVD components to analyse.
        outlier_threshold: Standard deviations for outlier detection
            in the projected space.
        min_cluster_pct: Minimum cluster size as fraction of total.
        max_cluster_pct: Maximum cluster size as fraction of total.
        purity_threshold: Minimum label purity for suspicion.

    Returns:
        SpectralResult with backdoor assessment.
    """
    n_samples = len(X)

    if n_samples < 200:
        return SpectralResult(
            suspected_backdoor=False,
            cluster_sizes=[],
            cluster_label_purity=[],
            flagged_indices=[],
            details={"reason": "too_few_samples"},
        )

    # 1. Center the feature matrix
    X_centered = X - X.mean(axis=0)

    # 2. Compute truncated SVD (top-k components)
    try:
        from scipy.linalg import svd as full_svd

        # Use randomized SVD for efficiency on large matrices
        if n_samples > 5000:
            from scipy.sparse.linalg import svds

            k = min(n_components, min(X_centered.shape) - 1)
            if k < 1:
                return SpectralResult(
                    suspected_backdoor=False,
                    cluster_sizes=[],
                    cluster_label_purity=[],
                    flagged_indices=[],
                    details={"reason": "insufficient_dimensions"},
                )
            _, s, Vt = svds(X_centered.astype(np.float64), k=k, which="LM")
            # svds returns in ascending order; flip to descending
            Vt = Vt[::-1]
        else:
            U, s, Vt = full_svd(X_centered, full_matrices=False)
            Vt = Vt[:n_components]
    except Exception as exc:
        logger.warning("spectral_svd_failed", error=str(exc))
        return SpectralResult(
            suspected_backdoor=False,
            cluster_sizes=[],
            cluster_label_purity=[],
            flagged_indices=[],
            details={"reason": "svd_failed", "error": str(exc)},
        )

    # 3. Project data onto top singular vectors
    projections = X_centered @ Vt.T  # (n_samples, n_components)

    # 4. Detect outlier clusters in the projected space
    all_flagged: set[int] = set()
    cluster_sizes: list[int] = []
    cluster_purities: list[float] = []

    for comp_idx in range(projections.shape[1]):
        proj = projections[:, comp_idx]
        mean_p = proj.mean()
        std_p = proj.std()

        if std_p == 0:
            continue

        # Find outliers in this component
        outlier_mask = np.abs(proj - mean_p) > outlier_threshold * std_p
        outlier_idx = np.where(outlier_mask)[0]
        n_outliers = len(outlier_idx)

        if n_outliers < 2:
            continue

        cluster_pct = n_outliers / n_samples

        # Check if cluster is in the backdoor size range
        if cluster_pct < min_cluster_pct or cluster_pct > max_cluster_pct:
            continue

        # Check label purity
        outlier_labels = y[outlier_idx]
        unique_labels, counts = np.unique(outlier_labels, return_counts=True)
        purity = counts.max() / len(outlier_labels)

        cluster_sizes.append(n_outliers)
        cluster_purities.append(float(purity))

        if purity >= purity_threshold:
            all_flagged.update(outlier_idx.tolist())
            logger.warning(
                "spectral_backdoor_suspected",
                component=comp_idx,
                cluster_size=n_outliers,
                purity=round(purity, 3),
                dominant_label=int(unique_labels[counts.argmax()]),
            )

    suspected = len(all_flagged) > 0

    return SpectralResult(
        suspected_backdoor=suspected,
        cluster_sizes=cluster_sizes,
        cluster_label_purity=cluster_purities,
        flagged_indices=sorted(all_flagged),
        details={
            "n_components_checked": projections.shape[1],
            "total_samples": n_samples,
        },
    )

def remove_spectral_outliers(
    X: NDArray[np.floating],
    y: NDArray,
    **kwargs: Any,
) -> tuple[NDArray[np.floating], NDArray, SpectralResult]:
    """Run spectral analysis and remove flagged samples.

    Returns:
        (X_clean, y_clean, result) — cleaned arrays and analysis result.
    """
    result = detect_backdoor_cluster(X, y, **kwargs)

    if not result.flagged_indices:
        return X, y, result

    keep_mask = np.ones(len(X), dtype=bool)
    keep_mask[result.flagged_indices] = False

    return X[keep_mask], y[keep_mask], result
