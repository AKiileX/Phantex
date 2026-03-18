# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Verdict dataclass.

A ContentVerdict is the output of any content classifier.  It carries
the score, label, confidence, evidence chain, and an optional decision
that downstream policy evaluation may override.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

class Label(StrEnum):
    """High-level classification label."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SENSITIVE = "sensitive"  # For data-classification verdicts

class Severity(StrEnum):
    """Alert severity levels matching the behavioural pipeline."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Decision(StrEnum):
    """Final enforcement decision (may be overridden by context policy)."""

    ALLOW = "allow"
    LOG = "log"
    ALERT = "alert"
    BLOCK = "block"
    REDACT = "redact"

class Confidence(StrEnum):
    """How sure the classifier is about the verdict."""

    HIGH = "high"  # Exact regex / pattern match
    MEDIUM = "medium"  # Heuristic or moderate ML score
    LOW = "low"  # Weak signal, needs context

@dataclass(frozen=True)
class ContentVerdict:
    """Immutable result returned by every content classifier.

    Attributes:
        score:            0.0 (benign) – 1.0 (malicious/sensitive).
        label:            Human-readable category, e.g. "prompt_injection".
        classifier_name:  Which classifier produced this verdict.
        confidence:       HIGH / MEDIUM / LOW.
        evidence:         Human-readable explanation of *why* flagged.
        severity:         Suggested alert severity.
        decision:         Suggested enforcement action.
        atlas_technique:  MITRE ATLAS ID, e.g. "AML.T0051".
        matched_patterns: Names/IDs of patterns that fired (for debugging).
        degraded:         True if ML path was unavailable and only fast path ran.
        metadata:         Arbitrary extra context for downstream consumers.
    """

    score: float = 0.0
    label: str = "benign"
    classifier_name: str = "unknown"
    confidence: Confidence = Confidence.LOW
    evidence: str = ""
    severity: Severity = Severity.INFO
    decision: Decision = Decision.ALLOW
    atlas_technique: str = ""
    matched_patterns: tuple[str, ...] = ()
    degraded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Clamp score
        if not 0.0 <= self.score <= 1.0:
            object.__setattr__(self, "score", max(0.0, min(1.0, self.score)))

    @classmethod
    def benign(
        cls,
        classifier_name: str = "unknown",
        degraded: bool = False,
    ) -> ContentVerdict:
        """Factory for a clean, benign ALLOW verdict."""
        return cls(
            score=0.0,
            label=Label.BENIGN.value,
            classifier_name=classifier_name,
            confidence=Confidence.HIGH,
            evidence="",
            severity=Severity.INFO,
            decision=Decision.ALLOW,
            atlas_technique="",
            matched_patterns=(),
            degraded=degraded,
            metadata={},
        )

# ── Shared severity ordering (canonical) ───────────────────────────────────

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
