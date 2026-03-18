# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Training Data Audit Trail (J5b).

Immutable, append-only audit log for every training data decision.
Records label governance actions, sanitization removals, and data mutations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class AuditAction(StrEnum):
    """Types of auditable training data actions."""

    LABEL_CONFIRMED = "label_confirmed"
    LABEL_DISMISSED = "label_dismissed"
    LABEL_APPROVED = "label_approved"
    LABEL_REJECTED = "label_rejected"
    SAMPLE_REMOVED_OUTLIER = "sample_removed_outlier"
    SAMPLE_REMOVED_VOLUME = "sample_removed_volume"
    SAMPLE_REMOVED_SPECTRAL = "sample_removed_spectral"
    SAMPLE_REMOVED_OVERRIDE = "sample_removed_override"
    TRAINING_STARTED = "training_started"
    TRAINING_COMPLETED = "training_completed"
    MODEL_REGISTERED = "model_registered"
    SANITIZATION_COMPLETE = "sanitization_complete"
    DATA_LOADED = "data_loaded"

@dataclass
class AuditEntry:
    """Single audit log entry."""

    action: AuditAction
    timestamp: str
    actor: str
    tenant_id: str
    details: dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute SHA-256 hash chaining this entry to previous."""
        payload = json.dumps(
            {
                "action": self.action.value,
                "timestamp": self.timestamp,
                "actor": self.actor,
                "tenant_id": self.tenant_id,
                "details": self.details,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        return d

class TrainingAuditLog:
    """Append-only training data audit trail.

    Each entry is hash-chained to the previous entry, forming a tamper-evident
    log (any modification breaks the chain). In production this would be backed
    by an append-only PostgreSQL table; this in-memory implementation provides
    the same API.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._last_hash: str = "genesis"

    def append(
        self,
        action: AuditAction,
        actor: str,
        tenant_id: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a new entry to the audit log.

        Returns:
            The created AuditEntry with its hash.
        """
        entry = AuditEntry(
            action=action,
            timestamp=datetime.now(UTC).isoformat(),
            actor=actor,
            tenant_id=tenant_id,
            details=details or {},
        )
        entry.entry_hash = entry.compute_hash(self._last_hash)
        self._last_hash = entry.entry_hash
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """Verify the hash chain integrity.

        Returns:
            True if chain is intact, False if tampered.
        """
        prev_hash = "genesis"
        for entry in self._entries:
            expected = entry.compute_hash(prev_hash)
            if entry.entry_hash != expected:
                return False
            prev_hash = entry.entry_hash
        return True

    def get_entries(
        self,
        *,
        tenant_id: str | None = None,
        action: AuditAction | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters.

        Args:
            tenant_id: Filter by tenant.
            action: Filter by action type.
            since: ISO timestamp — return entries after this time.
            limit: Max entries to return.
        """
        results = self._entries

        if tenant_id is not None:
            results = [e for e in results if e.tenant_id == tenant_id]

        if action is not None:
            results = [e for e in results if e.action == action]

        if since is not None:
            results = [e for e in results if e.timestamp >= since]

        return results[-limit:]

    @property
    def length(self) -> int:
        return len(self._entries)

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def log_sanitization(
        self,
        actor: str,
        tenant_id: str,
        report_dict: dict[str, Any],
    ) -> AuditEntry:
        """Convenience: log a full sanitization report."""
        return self.append(
            action=AuditAction.SANITIZATION_COMPLETE,
            actor=actor,
            tenant_id=tenant_id,
            details=report_dict,
        )

    def log_label_action(
        self,
        action: AuditAction,
        actor: str,
        tenant_id: str,
        alert_id: str,
        reason: str = "",
    ) -> AuditEntry:
        """Convenience: log a label governance action."""
        return self.append(
            action=action,
            actor=actor,
            tenant_id=tenant_id,
            details={"alert_id": alert_id, "reason": reason},
        )

    def log_sample_removal(
        self,
        actor: str,
        tenant_id: str,
        reason: AuditAction,
        sample_count: int,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Convenience: log bulk sample removal."""
        return self.append(
            action=reason,
            actor=actor,
            tenant_id=tenant_id,
            details={"sample_count": sample_count, **(details or {})},
        )
