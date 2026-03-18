# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Agent Purpose Profile (JB5).

Extends the JB2 AgentPurpose with data_scope for context-aware policy.
Maps agent roles to expected content types so that security tools
handling exploit payloads aren't false-positived.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class AgentPurposeProfile:
    """Extended agent purpose with data scope and content expectations.

    ``expected_content_types`` lists content types this agent normally
    handles — when content matches these types, severity is dampened.
    """

    agent_id: str
    tenant_id: str
    role: str  # e.g. "security_research", "customer_support"
    data_scope: frozenset[str] = frozenset()  # e.g. {"employee_pii", "financial_data"}
    expected_content_types: frozenset[str] = frozenset()  # e.g. {"injection_payload", "exploit_code"}
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

# ── Role → expected content mapping ─────────────────────────────────────────

_ROLE_EXPECTED_CONTENT: dict[str, frozenset[str]] = {
    "security_research": frozenset(
        {
            "injection_payload",
            "exploit_code",
            "malware_sample",
            "vulnerability_report",
            "credential_test",
        }
    ),
    "penetration_tester": frozenset(
        {
            "injection_payload",
            "exploit_code",
            "credential_test",
            "network_scan",
        }
    ),
    "hr_assistant": frozenset(
        {
            "employee_pii",
            "ssn",
            "address",
            "salary",
        }
    ),
    "medical_assistant": frozenset(
        {
            "phi",
            "medical_record",
            "diagnosis",
            "prescription",
            "lab_result",
        }
    ),
    "financial_analyst": frozenset(
        {
            "financial_data",
            "credit_card",
            "bank_account",
            "transaction",
        }
    ),
    "customer_support": frozenset(
        {
            "customer_email",
            "customer_phone",
        }
    ),
    "code_assistant": frozenset(
        {
            "code_snippet",
            "config_file",
        }
    ),
    "data_analyst": frozenset(
        {
            "dataset",
            "aggregate_statistics",
        }
    ),
    "document_summarizer": frozenset(
        {
            "document_text",
        }
    ),
    "public_chatbot": frozenset(),  # No sensitive content expected
}

def get_role_expected_content(role: str) -> frozenset[str]:
    """Return expected content types for a role.

    Falls back to empty set for unknown roles.
    """
    return _ROLE_EXPECTED_CONTENT.get(role, frozenset())

def is_content_expected(profile: AgentPurposeProfile, content_type: str) -> bool:
    """Check if *content_type* is expected for this agent.

    Checks both the profile's explicit ``expected_content_types`` and
    the role-based defaults.
    """
    if content_type in profile.expected_content_types:
        return True
    role_expected = get_role_expected_content(profile.role)
    return content_type in role_expected
