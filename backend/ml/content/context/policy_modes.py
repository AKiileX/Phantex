# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Policy Modes (JB5).

Defines the four operational modes for content policy enforcement:
- MONITOR_ONLY: Classify everything, never block
- STANDARD: Alert on threats, block critical severity
- STRICT: Alert + block on medium+ severity
- COMPLIANCE: Strict + full audit trail + evidence collection
"""

from __future__ import annotations

import enum

from ml.content.verdict import SEVERITY_ORDER, Decision, Severity

class PolicyMode(enum.Enum):
    """Customer-configurable enforcement mode."""

    MONITOR_ONLY = "monitor_only"
    STANDARD = "standard"
    STRICT = "strict"
    COMPLIANCE = "compliance"

# ── Mode → decision logic ───────────────────────────────────────────────────

# Each mode defines the minimum severity that triggers BLOCK vs ALERT vs LOG.
# Secret leaks are always at least ALERTed regardless of mode.

_MODE_BLOCK_THRESHOLD: dict[PolicyMode, Severity | None] = {
    PolicyMode.MONITOR_ONLY: None,  # Never blocks
    PolicyMode.STANDARD: Severity.CRITICAL,  # Block only critical
    PolicyMode.STRICT: Severity.MEDIUM,  # Block medium+
    PolicyMode.COMPLIANCE: Severity.MEDIUM,  # Same as strict + evidence
}

_MODE_ALERT_THRESHOLD: dict[PolicyMode, Severity] = {
    PolicyMode.MONITOR_ONLY: Severity.MEDIUM,  # Alert on medium+ (inform, don't block)
    PolicyMode.STANDARD: Severity.MEDIUM,  # Alert on medium+
    PolicyMode.STRICT: Severity.LOW,  # Alert on low+
    PolicyMode.COMPLIANCE: Severity.LOW,  # Alert on low+ (maximum visibility)
}

_SEVERITY_ORDER = SEVERITY_ORDER  # Re-export for backward compat

def apply_mode(
    mode: PolicyMode,
    current_severity: Severity,
    current_decision: Decision,
) -> Decision:
    """Apply policy mode to refine a content decision.

    Parameters
    ----------
    mode:
        The active policy mode.
    current_severity:
        Severity from content analysis (JB1/JB3/JB4).
    current_decision:
        Decision proposed by the content pipeline.

    Returns
    -------
    The final decision after mode adjustment.
    """
    sev_val = _SEVERITY_ORDER.get(current_severity, 0)

    # ── MONITOR_ONLY: never blocks, downgrade BLOCK to LOG
    if mode == PolicyMode.MONITOR_ONLY:
        if current_decision == Decision.BLOCK:
            return Decision.LOG
        if current_decision == Decision.ALERT and sev_val < _SEVERITY_ORDER[Severity.MEDIUM]:
            return Decision.LOG
        return current_decision

    # ── STANDARD / STRICT / COMPLIANCE
    block_threshold = _MODE_BLOCK_THRESHOLD[mode]
    alert_threshold = _MODE_ALERT_THRESHOLD[mode]

    # Should block?
    if block_threshold is not None and sev_val >= _SEVERITY_ORDER[block_threshold]:
        return Decision.BLOCK

    # Should alert?
    if sev_val >= _SEVERITY_ORDER[alert_threshold]:
        if current_decision in (Decision.BLOCK, Decision.ALERT):
            return current_decision
        return Decision.ALERT

    # Below thresholds → LOG or ALLOW
    if current_decision in (Decision.BLOCK, Decision.ALERT):
        return Decision.LOG
    return current_decision

def requires_evidence(mode: PolicyMode) -> bool:
    """Whether this mode mandates compliance evidence collection."""
    return mode == PolicyMode.COMPLIANCE
