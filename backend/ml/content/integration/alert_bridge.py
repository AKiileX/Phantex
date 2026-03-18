# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Alert Bridge (JB6).

Converts ContentVerdict into the same Alert model that behavioral ML
uses → same Kafka topic → same dashboard → same notifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ml.content.verdict import ContentVerdict, Decision

@dataclass(frozen=True)
class ContentAlert:
    """Alert generated from content analysis.

    Compatible with the existing behavioral alert pipeline.
    """

    severity: str
    rule_id: str
    agent_id: str
    tenant_id: str
    description: str
    atlas_technique: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

def content_verdict_to_alert(
    verdict: ContentVerdict,
    agent_id: str = "",
    tenant_id: str = "",
    event_id: str = "",
) -> ContentAlert | None:
    """Convert a ContentVerdict to a ContentAlert.

    Returns ``None`` if the verdict is ALLOW (no alert needed).
    All fields are sanitized before conversion.
    """
    if verdict.decision in (Decision.ALLOW, Decision.LOG):
        return None

    # Sanitize fields (defense against injection in alert metadata)
    safe_evidence = _sanitize(verdict.evidence)[:500]
    safe_classifier = _sanitize(verdict.classifier_name)[:100]
    safe_agent = _sanitize(agent_id)[:200]
    safe_tenant = _sanitize(tenant_id)[:200]

    return ContentAlert(
        severity=verdict.severity.value,
        rule_id=f"content_{safe_classifier}",
        agent_id=safe_agent,
        tenant_id=safe_tenant,
        description=safe_evidence,
        atlas_technique=verdict.atlas_technique or "",
        timestamp=datetime.now(UTC).isoformat(),
        metadata={
            "content_score": round(verdict.score, 4),
            "classifier": safe_classifier,
            "decision": verdict.decision.value,
            "degraded": verdict.degraded,
            "event_id": _sanitize(event_id)[:200],
        },
    )

def _sanitize(value: str) -> str:
    """Strip control chars and null bytes from alert fields."""
    return "".join(c for c in value if c.isprintable() or c in (" ", "\t"))
