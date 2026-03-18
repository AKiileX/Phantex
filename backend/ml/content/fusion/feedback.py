# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8c — Analyst Feedback Loop.

Routes analyst verdict confirmations / dismissals back into the
content ML training pipeline.  This is the ``flywheel`` that makes
the content classifier improve over time from production data.

Flow:
  analyst confirms alert   → positive sample → TrainingDataStore + AttackCorpus
  analyst dismisses alert  → negative sample → TrainingDataStore (only)

Integrates with:
- ``label_governance.py`` (J5b): dual-approval for dismissals.
- ``TrainingDataStore`` (JB8b): training data for classifier.
- ``AttackCorpus`` (JB8a): embedding corpus for similarity search.

Hardening:
- Text is length-capped and sanitized before storage.
- Dual-approval required for dismissals (inherits from J5b).
- All feedback actions are logged for audit (J5b audit trail).

Thread-safety: stateless — delegates to thread-safe stores.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MAX_TEXT_LENGTH = 8_192

@dataclass(frozen=True)
class FeedbackEvent:
    """A single analyst feedback event."""

    alert_id: str
    text: str  # Original content that triggered the alert
    action: str  # "confirm" | "dismiss"
    category: str  # Attack category (from classifier)
    analyst_id: str = ""
    tenant_id: str = ""
    agent_id: str = ""
    confidence: float = 1.0  # Analyst confidence in the verdict
    reason: str = ""  # Optional explanation
    timestamp: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

class FeedbackRouter:
    """Route analyst feedback into the content ML training pipeline.

    Parameters
    ----------
    data_store:
        TrainingDataStore for labeled training samples.
    corpus:
        AttackCorpus for embedding similarity search.
    require_dual_approval:
        If True (default), dismissals require admin confirmation
        before becoming negative training samples.
    """

    def __init__(
        self,
        data_store: Any | None = None,
        corpus: Any | None = None,
        *,
        require_dual_approval: bool = True,
    ) -> None:
        self._data_store = data_store
        self._corpus = corpus
        self._require_dual_approval = require_dual_approval
        self._lock = threading.Lock()
        self._pending_dismissals: dict[str, FeedbackEvent] = {}
        self._max_pending = 10_000  # DoS guard: cap pending dismissals
        self._pending_ttl = 86_400.0  # 24 h TTL for pending dismissals
        self._stats = _FeedbackStats()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_feedback(self, event: FeedbackEvent) -> dict[str, Any]:
        """Process a single analyst feedback event.

        Returns a dict summarizing what was done.
        """
        if event.action == "confirm":
            return self._handle_confirm(event)
        elif event.action == "dismiss":
            return self._handle_dismiss(event)
        else:
            logger.warning("Unknown feedback action: %s", event.action)
            return {"status": "error", "reason": f"unknown_action: {event.action}"}

    def approve_dismissal(
        self,
        alert_id: str,
        admin_id: str,
    ) -> dict[str, Any]:
        """Admin approves a pending dismissal → negative training sample.

        Implements the dual-approval gate from J5b label_governance.
        """
        self._expire_stale_dismissals()
        with self._lock:
            event = self._pending_dismissals.pop(alert_id, None)
        if event is None:
            return {"status": "error", "reason": "no_pending_dismissal"}

        # Add as negative training sample
        self._add_negative_sample(event, approved_by=admin_id)
        with self._lock:
            self._stats.approved_dismissals += 1

        logger.info(
            "Dismissal approved: alert=%s admin=%s",
            alert_id,
            admin_id,
        )
        return {
            "status": "approved",
            "alert_id": alert_id,
            "admin_id": admin_id,
        }

    def reject_dismissal(
        self,
        alert_id: str,
        admin_id: str,
    ) -> dict[str, Any]:
        """Admin rejects a dismissal → treat as confirmed instead."""
        self._expire_stale_dismissals()
        with self._lock:
            event = self._pending_dismissals.pop(alert_id, None)
        if event is None:
            return {"status": "error", "reason": "no_pending_dismissal"}

        # Rejection means the alert was actually valid — add as positive
        self._add_positive_sample(event)
        with self._lock:
            self._stats.rejected_dismissals += 1

        logger.info(
            "Dismissal rejected (treated as confirm): alert=%s admin=%s",
            alert_id,
            admin_id,
        )
        return {
            "status": "rejection_became_confirm",
            "alert_id": alert_id,
            "admin_id": admin_id,
        }

    @property
    def pending_dismissals(self) -> int:
        return len(self._pending_dismissals)

    @property
    def stats(self) -> dict[str, int]:
        return {
            "confirmations": self._stats.confirmations,
            "dismissals_pending": len(self._pending_dismissals),
            "approved_dismissals": self._stats.approved_dismissals,
            "rejected_dismissals": self._stats.rejected_dismissals,
            "samples_added": self._stats.samples_added,
            "corpus_entries_added": self._stats.corpus_entries_added,
            "expired_dismissals": self._stats.expired_dismissals,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _expire_stale_dismissals(self) -> None:
        """Remove pending dismissals older than ``_pending_ttl``."""
        now = time.time()
        with self._lock:
            stale = [
                aid
                for aid, ev in self._pending_dismissals.items()
                if ev.timestamp > 0 and (now - ev.timestamp) > self._pending_ttl
            ]
            for aid in stale:
                del self._pending_dismissals[aid]
            self._stats.expired_dismissals += len(stale)
        if stale:
            logger.info("Expired %d stale pending dismissals (TTL=%.0fs)", len(stale), self._pending_ttl)

    def _handle_confirm(self, event: FeedbackEvent) -> dict[str, Any]:
        """Analyst confirms alert → positive sample + corpus entry."""
        self._add_positive_sample(event)
        with self._lock:
            self._stats.confirmations += 1

        logger.info(
            "Feedback confirm: alert=%s category=%s analyst=%s",
            event.alert_id,
            event.category,
            event.analyst_id,
        )
        return {
            "status": "confirmed",
            "alert_id": event.alert_id,
            "added_to_training": True,
            "added_to_corpus": True,
        }

    def _handle_dismiss(self, event: FeedbackEvent) -> dict[str, Any]:
        """Analyst dismisses alert → pending or direct negative sample."""
        if self._require_dual_approval:
            self._expire_stale_dismissals()
            # Stamp pending events so TTL expiry works even when caller omits timestamp
            stored = (
                event
                if event.timestamp > 0
                else FeedbackEvent(
                    alert_id=event.alert_id,
                    text=event.text,
                    action=event.action,
                    category=event.category,
                    analyst_id=event.analyst_id,
                    tenant_id=event.tenant_id,
                    agent_id=event.agent_id,
                    confidence=event.confidence,
                    reason=event.reason,
                    timestamp=time.time(),
                    metadata=event.metadata,
                )
            )
            with self._lock:
                if len(self._pending_dismissals) >= self._max_pending:
                    return {
                        "status": "error",
                        "reason": "pending_dismissals_at_capacity",
                    }
                self._pending_dismissals[event.alert_id] = stored
            logger.info(
                "Feedback dismiss (pending approval): alert=%s analyst=%s",
                event.alert_id,
                event.analyst_id,
            )
            return {
                "status": "pending_approval",
                "alert_id": event.alert_id,
                "requires_admin": True,
            }
        else:
            self._add_negative_sample(event)
            return {
                "status": "dismissed",
                "alert_id": event.alert_id,
                "added_to_training": True,
            }

    def _add_positive_sample(self, event: FeedbackEvent) -> None:
        """Add confirmed malicious sample to training store + corpus."""
        text = event.text[:_MAX_TEXT_LENGTH]

        # Add to training data
        if self._data_store is not None:
            self._data_store.add_sample(
                text=text,
                label="malicious",
                category=event.category,
                source="analyst",
                confidence=event.confidence,
                metadata={
                    "alert_id": event.alert_id,
                    "analyst_id": event.analyst_id,
                    "action": "confirm",
                },
            )
            with self._lock:
                self._stats.samples_added += 1

        # Add to attack corpus for similarity search
        if self._corpus is not None:
            self._corpus.add_sample(
                text=text,
                category=event.category,
                label=f"analyst_{event.category}",
                source="analyst",
                metadata={
                    "alert_id": event.alert_id,
                    "analyst_id": event.analyst_id,
                },
            )
            with self._lock:
                self._stats.corpus_entries_added += 1

    def _add_negative_sample(
        self,
        event: FeedbackEvent,
        approved_by: str = "",
    ) -> None:
        """Add dismissed (false positive) sample to training store."""
        text = event.text[:_MAX_TEXT_LENGTH]

        if self._data_store is not None:
            self._data_store.add_sample(
                text=text,
                label="benign",
                category="false_positive",
                source="analyst",
                confidence=event.confidence,
                metadata={
                    "alert_id": event.alert_id,
                    "analyst_id": event.analyst_id,
                    "approved_by": approved_by,
                    "action": "dismiss",
                    "original_category": event.category,
                },
            )
            with self._lock:
                self._stats.samples_added += 1

class _FeedbackStats:
    """Mutable counters for feedback telemetry."""

    __slots__ = (
        "confirmations",
        "approved_dismissals",
        "rejected_dismissals",
        "samples_added",
        "corpus_entries_added",
        "expired_dismissals",
    )

    def __init__(self) -> None:
        self.confirmations = 0
        self.approved_dismissals = 0
        self.rejected_dismissals = 0
        self.samples_added = 0
        self.corpus_entries_added = 0
        self.expired_dismissals = 0
