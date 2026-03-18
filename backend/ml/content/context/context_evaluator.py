# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Context Evaluator (JB5).

Ties JB1-JB4 together with agent identity and role-based policy.
Takes a content verdict + agent purpose → produces a context-aware
final decision that prevents false positives on legitimate work.

A pentester handling exploit payloads → ALLOW (matches purpose).
The same payload on a customer support bot → BLOCK.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from ml.content.context.baseline_tracker import SemanticBaselineTracker
from ml.content.context.compliance_evidence import ComplianceEvidenceCollector
from ml.content.context.policy_modes import PolicyMode, apply_mode, requires_evidence
from ml.content.context.purpose_profile import (
    AgentPurposeProfile,
    is_content_expected,
)
from ml.content.verdict import Decision, Severity

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class ContextDecision:
    """Final context-aware decision after evaluating all signals."""

    decision: Decision
    severity: Severity
    original_decision: Decision
    original_severity: Severity
    purpose_match: bool  # Content matches agent purpose
    baseline_drift: bool  # Content pattern drifted from baseline
    policy_mode: PolicyMode
    evidence_id: str = ""  # Non-empty if compliance evidence was collected
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class ContextEvaluator:
    """Evaluate content verdicts in the context of agent purpose + policy.

    Parameters
    ----------
    baseline_tracker:
        Shared SemanticBaselineTracker instance.
    evidence_collector:
        Shared ComplianceEvidenceCollector instance.
    default_mode:
        Default policy mode when no per-agent mode is set.
    """

    def __init__(
        self,
        baseline_tracker: SemanticBaselineTracker | None = None,
        evidence_collector: ComplianceEvidenceCollector | None = None,
        default_mode: PolicyMode = PolicyMode.STANDARD,
    ) -> None:
        self._baseline = baseline_tracker or SemanticBaselineTracker()
        self._evidence = evidence_collector or ComplianceEvidenceCollector()
        self._default_mode = default_mode

        # Agent → PolicyMode overrides
        self._agent_modes: dict[tuple[str, str], PolicyMode] = {}
        # Agent → AgentPurposeProfile
        self._profiles: dict[tuple[str, str], AgentPurposeProfile] = {}
        self._config_lock = threading.Lock()

    # ── Configuration ────────────────────────────────────────────────

    def set_profile(self, profile: AgentPurposeProfile) -> None:
        """Register or update an agent's purpose profile."""
        key = (profile.tenant_id, profile.agent_id)
        with self._config_lock:
            self._profiles[key] = profile

    def set_mode(
        self,
        tenant_id: str,
        agent_id: str,
        mode: PolicyMode,
    ) -> None:
        """Set the policy mode for a specific agent."""
        with self._config_lock:
            self._agent_modes[(tenant_id, agent_id)] = mode

    def get_mode(self, tenant_id: str, agent_id: str) -> PolicyMode:
        """Get the effective policy mode for an agent."""
        with self._config_lock:
            return self._agent_modes.get((tenant_id, agent_id), self._default_mode)

    # ── Evaluation ───────────────────────────────────────────────────

    def evaluate(
        self,
        tenant_id: str,
        agent_id: str,
        content: str,
        content_type: str,
        verdict_decision: Decision,
        verdict_severity: Severity,
        classification_labels: tuple[str, ...] = (),
        compliance_tags: tuple[str, ...] = (),
        sensitivity_level: str = "none",
        metadata: dict[str, Any] | None = None,
    ) -> ContextDecision:
        """Produce a context-aware decision.

        Parameters
        ----------
        content:
            The content being evaluated (used for baseline tracking only;
            not stored in evidence).
        content_type:
            e.g. "injection_payload", "employee_pii", "code_snippet"
        verdict_decision, verdict_severity:
            The raw verdict from JB1/JB3/JB4.
        classification_labels:
            e.g. ("PII", "FINANCIAL")
        compliance_tags:
            e.g. ("GDPR", "PCI-DSS")
        """
        key = (tenant_id, agent_id)
        with self._config_lock:
            profile = self._profiles.get(key)
            mode = self._agent_modes.get(key, self._default_mode)

        # ── 1. Purpose check
        purpose_match = False
        if profile is None:
            # No purpose → MONITOR_ONLY behaviour (never block, always log)
            effective_mode = PolicyMode.MONITOR_ONLY
            reason = "no purpose declaration → monitor-only"
        else:
            effective_mode = mode
            purpose_match = is_content_expected(profile, content_type)
            if purpose_match:
                reason = f"content type '{content_type}' matches purpose '{profile.role}'"
            else:
                reason = f"content type '{content_type}' outside purpose '{profile.role}'"

        # ── 2. Purpose-aware severity adjustment
        adjusted_severity = verdict_severity
        adjusted_decision = verdict_decision

        if purpose_match and verdict_severity in (Severity.HIGH, Severity.CRITICAL):
            # Dampen severity for expected content (pentester handling exploit payloads)
            # Exception: secret leaks are always at least ALERTed
            if content_type not in ("secret_leak", "credential_exfil"):
                adjusted_severity = Severity.INFO
                adjusted_decision = Decision.LOG
                reason += "; severity dampened (expected content)"

        # ── 3. Baseline drift check
        drift_info = self._baseline.record(tenant_id, agent_id, content)
        baseline_drift = drift_info["length_drift"] or drift_info["entropy_drift"]
        if baseline_drift:
            # Drift escalates severity by one level if not already high
            if adjusted_severity in (Severity.INFO, Severity.LOW):
                adjusted_severity = Severity.MEDIUM
                adjusted_decision = Decision.ALERT
                reason += "; baseline drift detected"

        # ── 4. Apply policy mode
        final_decision = apply_mode(effective_mode, adjusted_severity, adjusted_decision)

        # ── 5. Collect compliance evidence if required
        evidence_id = ""
        if requires_evidence(effective_mode):
            record = self._evidence.collect(
                agent_id=agent_id,
                tenant_id=tenant_id,
                content=content,
                classification_labels=classification_labels,
                compliance_tags=compliance_tags,
                sensitivity_level=sensitivity_level,
                verdict_decision=final_decision,
                verdict_severity=adjusted_severity,
                policy_mode=effective_mode,
                metadata=metadata,
            )
            evidence_id = record.evidence_id

        return ContextDecision(
            decision=final_decision,
            severity=adjusted_severity,
            original_decision=verdict_decision,
            original_severity=verdict_severity,
            purpose_match=purpose_match,
            baseline_drift=baseline_drift,
            policy_mode=effective_mode,
            evidence_id=evidence_id,
            reason=reason,
            metadata=drift_info,
        )

    # ── Accessors ────────────────────────────────────────────────────

    @property
    def baseline_tracker(self) -> SemanticBaselineTracker:
        return self._baseline

    @property
    def evidence_collector(self) -> ComplianceEvidenceCollector:
        return self._evidence
