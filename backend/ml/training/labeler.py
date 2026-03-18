# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Semi-Supervised Labeler (J2 + J5b Integration).

Creates training labels from confirmed alert dispositions.
When LabelGovernance is provided, only uses labels that have
completed the dual-approval workflow (J5b).
"""

from __future__ import annotations

from typing import Any

import numpy as np
import structlog
from numpy.typing import NDArray

from ml.integrity.label_governance import LabelGovernance, TrainingLabel

logger = structlog.get_logger("phantex.ml.training.labeler")

# Maps alert disposition to training label interpretation
# (fallback when no governance engine is provided)
_DISPOSITION_MAP = {
    "confirmed": "positive",  # True positive — use as attack sample
    "false_positive": "negative",  # Confirmed FP — use as benign sample
    "pending_review": "unlabeled",  # Not yet reviewed — exclude from training
    "dismissed": "unlabeled",  # Dismissed without review — exclude
}

class Labeler:
    """Create training labels from alert dispositions and event data.

    When instantiated with a LabelGovernance engine, dispositions are
    cross-referenced against the governance store — only dual-approved
    labels are used. This prevents label-flipping poisoning attacks.
    """

    def __init__(self, governance: LabelGovernance | None = None) -> None:
        self._governance = governance

    def create_labels(
        self,
        feature_matrix: NDArray[np.floating],
        alert_labels: list[dict[str, Any]] | None = None,
    ) -> tuple[NDArray[np.integer], NDArray[np.bool_]]:
        """Assign labels to feature vectors.

        Args:
            feature_matrix: (n_samples, n_features) array.
            alert_labels: Optional list of dicts with 'sample_index', 'disposition',
                          'attack_class_index', and optionally 'alert_id' keys.

        Returns:
            (y, mask) where:
              y: (n_samples,) integer labels (0=benign, 1..N=attack classes)
              mask: (n_samples,) boolean — True where label is known
        """
        n_samples = feature_matrix.shape[0]
        y = np.zeros(n_samples, dtype=np.int64)
        mask = np.zeros(n_samples, dtype=bool)

        if not alert_labels:
            return y, mask

        # If governance is available, build the set of approved labels
        governed_labels: dict[str, TrainingLabel] | None = None
        if self._governance is not None:
            governed_labels = self._governance.get_training_labels()

        skipped_governance = 0
        for label in alert_labels:
            idx = label.get("sample_index")
            disposition = label.get("disposition", "")
            attack_class_index = label.get("attack_class_index", 0)
            alert_id = label.get("alert_id")

            if idx is None or idx < 0 or idx >= n_samples:
                continue

            # ── J5b governance gate ──────────────────────────────────
            if governed_labels is not None and alert_id:
                gov_label = governed_labels.get(alert_id)
                if gov_label is None:
                    # Not yet dual-approved — skip
                    skipped_governance += 1
                    continue
                # Use governance decision instead of raw disposition
                if gov_label == TrainingLabel.POSITIVE:
                    y[idx] = max(attack_class_index, 1)
                    mask[idx] = True
                elif gov_label == TrainingLabel.NEGATIVE:
                    y[idx] = 0
                    mask[idx] = True
                # TrainingLabel.EXCLUDED → skip
                continue

            # ── Fallback: raw disposition mapping (no governance) ────
            label_type = _DISPOSITION_MAP.get(disposition, "unlabeled")

            if label_type == "positive":
                y[idx] = max(attack_class_index, 1)  # Ensure non-zero for attacks
                mask[idx] = True
            elif label_type == "negative":
                y[idx] = 0  # benign
                mask[idx] = True
            # unlabeled: mask stays False

        labeled_count = mask.sum()
        logger.info(
            "labels_created",
            total_samples=n_samples,
            labeled=int(labeled_count),
            positive=int((y[mask] > 0).sum()) if labeled_count > 0 else 0,
            negative=int((y[mask] == 0).sum()) if labeled_count > 0 else 0,
            governance_enabled=governed_labels is not None,
            skipped_unapproved=skipped_governance,
        )

        return y, mask
