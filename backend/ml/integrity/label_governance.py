# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Label Governance (J5b).

Dual-approval workflow for training labels. Analyst dismisses an alert →
status becomes "pending_review" (not "false_positive"). Admin must approve
the dismissal before it becomes a negative training label.

This prevents label-flipping poisoning attacks where a compromised analyst
dismisses real alerts to degrade model accuracy.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger("phantex.ml.integrity.label_governance")

class LabelDecision(StrEnum):
    """Alert label decisions."""

    CONFIRMED = "confirmed"  # True positive → positive training label
    PENDING_REVIEW = "pending_review"  # Dismissed by analyst, awaiting admin
    DISMISSED = "dismissed"  # Admin-approved dismissal → negative label
    REJECTED = "rejected"  # Admin rejected dismissal → stays positive
    UNLABELED = "unlabeled"  # No action → NOT used for training

class TrainingLabel(StrEnum):
    """Labels used for model training."""

    POSITIVE = "positive"  # Confirmed attack
    NEGATIVE = "negative"  # Confirmed benign (admin-approved dismissal)
    EXCLUDED = "excluded"  # Not used (unlabeled, pending, or rejected)

@dataclass
class LabelReview:
    """Record of a label review decision."""

    alert_id: str
    analyst_id: str
    analyst_decision: LabelDecision
    analyst_reason: str
    analyst_timestamp: float
    admin_id: str | None = None
    admin_decision: LabelDecision | None = None
    admin_reason: str | None = None
    admin_timestamp: float | None = None
    training_label: TrainingLabel = TrainingLabel.EXCLUDED

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "analyst_id": self.analyst_id,
            "analyst_decision": self.analyst_decision.value,
            "analyst_reason": self.analyst_reason,
            "analyst_timestamp": self.analyst_timestamp,
            "admin_id": self.admin_id,
            "admin_decision": self.admin_decision.value if self.admin_decision else None,
            "admin_reason": self.admin_reason,
            "admin_timestamp": self.admin_timestamp,
            "training_label": self.training_label.value,
        }

class LabelGovernance:
    """Dual-approval label governance engine.

    Stores reviews in memory for Phase 2 (will back to Postgres in production).
    """

    def __init__(self) -> None:
        self._reviews: dict[str, LabelReview] = {}

    def analyst_confirm(
        self,
        alert_id: str,
        analyst_id: str,
        reason: str = "",
    ) -> LabelReview:
        """Analyst confirms alert as true positive → immediate positive label."""
        review = LabelReview(
            alert_id=alert_id,
            analyst_id=analyst_id,
            analyst_decision=LabelDecision.CONFIRMED,
            analyst_reason=reason,
            analyst_timestamp=time.time(),
            training_label=TrainingLabel.POSITIVE,
        )
        self._reviews[alert_id] = review
        logger.info("label_confirmed", alert_id=alert_id, analyst_id=analyst_id)
        return review

    def analyst_dismiss(
        self,
        alert_id: str,
        analyst_id: str,
        reason: str,
    ) -> LabelReview:
        """Analyst dismisses alert → pending admin review (NOT a negative label yet)."""
        if not reason:
            raise ValueError("Dismissal reason is required")

        review = LabelReview(
            alert_id=alert_id,
            analyst_id=analyst_id,
            analyst_decision=LabelDecision.PENDING_REVIEW,
            analyst_reason=reason,
            analyst_timestamp=time.time(),
            training_label=TrainingLabel.EXCLUDED,  # Not a label until admin approves
        )
        self._reviews[alert_id] = review
        logger.info(
            "label_pending_review",
            alert_id=alert_id,
            analyst_id=analyst_id,
            reason=reason,
        )
        return review

    def admin_approve_dismissal(
        self,
        alert_id: str,
        admin_id: str,
        reason: str = "",
    ) -> LabelReview:
        """Admin approves analyst's dismissal → becomes negative training label."""
        review = self._reviews.get(alert_id)
        if review is None:
            raise ValueError(f"No review found for alert {alert_id}")
        if review.analyst_decision != LabelDecision.PENDING_REVIEW:
            raise ValueError(f"Alert {alert_id} is not pending review")
        if admin_id == review.analyst_id:
            raise ValueError("Admin and analyst must be different users (separation of duties)")

        review.admin_id = admin_id
        review.admin_decision = LabelDecision.DISMISSED
        review.admin_reason = reason
        review.admin_timestamp = time.time()
        review.training_label = TrainingLabel.NEGATIVE

        logger.info(
            "label_dismissal_approved",
            alert_id=alert_id,
            admin_id=admin_id,
            analyst_id=review.analyst_id,
        )
        return review

    def admin_reject_dismissal(
        self,
        alert_id: str,
        admin_id: str,
        reason: str,
    ) -> LabelReview:
        """Admin rejects analyst's dismissal → alert stays as positive label."""
        review = self._reviews.get(alert_id)
        if review is None:
            raise ValueError(f"No review found for alert {alert_id}")
        if review.analyst_decision != LabelDecision.PENDING_REVIEW:
            raise ValueError(f"Alert {alert_id} is not pending review")

        review.admin_id = admin_id
        review.admin_decision = LabelDecision.REJECTED
        review.admin_reason = reason
        review.admin_timestamp = time.time()
        review.training_label = TrainingLabel.POSITIVE

        logger.info(
            "label_dismissal_rejected",
            alert_id=alert_id,
            admin_id=admin_id,
            analyst_id=review.analyst_id,
        )
        return review

    def get_training_labels(self) -> dict[str, TrainingLabel]:
        """Return all resolved training labels (excludes EXCLUDED)."""
        return {
            alert_id: review.training_label
            for alert_id, review in self._reviews.items()
            if review.training_label != TrainingLabel.EXCLUDED
        }

    def get_pending_reviews(self) -> list[LabelReview]:
        """Return reviews awaiting admin approval."""
        return [
            r
            for r in self._reviews.values()
            if r.analyst_decision == LabelDecision.PENDING_REVIEW and r.admin_decision is None
        ]

    def get_review(self, alert_id: str) -> LabelReview | None:
        return self._reviews.get(alert_id)

    def get_label_stats(self) -> dict[str, int]:
        """Return counts by label type."""
        stats: dict[str, int] = {
            "confirmed": 0,
            "pending": 0,
            "dismissed": 0,
            "rejected": 0,
            "unlabeled": 0,
        }
        for r in self._reviews.values():
            if r.training_label == TrainingLabel.POSITIVE and r.analyst_decision == LabelDecision.CONFIRMED:
                stats["confirmed"] += 1
            elif r.analyst_decision == LabelDecision.PENDING_REVIEW and r.admin_decision is None:
                stats["pending"] += 1
            elif r.admin_decision == LabelDecision.DISMISSED:
                stats["dismissed"] += 1
            elif r.admin_decision == LabelDecision.REJECTED:
                stats["rejected"] += 1
            else:
                stats["unlabeled"] += 1
        return stats
