# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Compliance Evidence Collector (JB5).

In COMPLIANCE mode, every content classification + policy decision is
logged as an evidence record for regulatory audit trails (EU AI Act,
HIPAA, PCI-DSS).

Records are append-only — no modification or deletion except via admin
purge with audit log.  Evidence is exportable as JSON.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ml.content.context.policy_modes import PolicyMode
from ml.content.verdict import Decision, Severity

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class ComplianceEvidence:
    """A single auditable evidence record."""

    timestamp: str  # ISO-8601 UTC
    agent_id: str
    tenant_id: str
    content_hash: str  # SHA-256 (never store raw content)
    classification_labels: tuple[str, ...]
    compliance_tags: tuple[str, ...]
    sensitivity_level: str
    verdict_decision: str
    verdict_severity: str
    policy_mode: str
    evidence_id: str = ""  # Unique ID for this record
    metadata: dict[str, Any] = field(default_factory=dict)

class ComplianceEvidenceCollector:
    """Append-only collector for compliance evidence records.

    Parameters
    ----------
    max_records:
        Maximum records in memory before FIFO eviction (default 100,000).
        Evicted records should be persisted to external storage first.
    """

    def __init__(self, max_records: int = 100_000) -> None:
        self._max = max_records
        self._lock = threading.Lock()
        self._records: list[ComplianceEvidence] = []
        self._counter = 0

    def collect(
        self,
        agent_id: str,
        tenant_id: str,
        content: str,
        classification_labels: tuple[str, ...],
        compliance_tags: tuple[str, ...],
        sensitivity_level: str,
        verdict_decision: Decision,
        verdict_severity: Severity,
        policy_mode: PolicyMode,
        metadata: dict[str, Any] | None = None,
    ) -> ComplianceEvidence:
        """Record a compliance evidence entry.

        The raw *content* is hashed — never stored.
        """
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        now = datetime.now(UTC).isoformat()

        with self._lock:
            self._counter += 1
            evidence_id = f"CE-{self._counter:08d}"

            record = ComplianceEvidence(
                timestamp=now,
                agent_id=agent_id,
                tenant_id=tenant_id,
                content_hash=content_hash,
                classification_labels=classification_labels,
                compliance_tags=compliance_tags,
                sensitivity_level=sensitivity_level,
                verdict_decision=verdict_decision.value,
                verdict_severity=verdict_severity.value,
                policy_mode=policy_mode.value,
                evidence_id=evidence_id,
                metadata=metadata or {},
            )

            self._records.append(record)

            # FIFO eviction
            if len(self._records) > self._max:
                evict_count = len(self._records) - self._max
                logger.warning(
                    "compliance evidence FIFO eviction: dropping %d oldest records",
                    evict_count,
                )
                self._records = self._records[-self._max :]

        return record

    def query(
        self,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[ComplianceEvidence]:
        """Query records, newest first."""
        with self._lock:
            filtered = self._records
            if tenant_id:
                filtered = [r for r in filtered if r.tenant_id == tenant_id]
            if agent_id:
                filtered = [r for r in filtered if r.agent_id == agent_id]
            return list(reversed(filtered[-limit:]))

    def export_json(
        self,
        tenant_id: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Export records as JSON for auditor review.

        Acceptance criteria: compliance evidence exportable as JSON.
        """
        records = self.query(tenant_id=tenant_id, agent_id=agent_id, limit=100_000)
        return json.dumps(
            [_evidence_to_dict(r) for r in records],
            indent=2,
            default=str,
        )

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def purge(self, tenant_id: str) -> int:
        """Admin purge for a tenant.  Returns count removed."""
        with self._lock:
            before = len(self._records)
            self._records = [r for r in self._records if r.tenant_id != tenant_id]
            return before - len(self._records)

def _evidence_to_dict(e: ComplianceEvidence) -> dict[str, Any]:
    """Convert evidence to a JSON-safe dict."""
    return {
        "evidence_id": e.evidence_id,
        "timestamp": e.timestamp,
        "agent_id": e.agent_id,
        "tenant_id": e.tenant_id,
        "content_hash": e.content_hash,
        "classification_labels": list(e.classification_labels),
        "compliance_tags": list(e.compliance_tags),
        "sensitivity_level": e.sensitivity_level,
        "verdict_decision": e.verdict_decision,
        "verdict_severity": e.verdict_severity,
        "policy_mode": e.policy_mode,
        "metadata": e.metadata,
    }
