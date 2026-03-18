# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Tool Policy Engine (JB2).

Evaluates tool call events against the agent's declared purpose and
returns a ``ToolPolicyVerdict``.

Flow:
    1. Lookup AgentPurpose for event.agent_id → not found ⇒ MONITOR_ONLY
    2. denied_tools check → DENY
    3. allowed_tools check → ALLOW
    4. Unknown tool → role heuristic + content analysis → score-based
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ml.content.policy.agent_purpose import PurposeStore

logger = logging.getLogger(__name__)

class ToolDecision(StrEnum):
    """Enforcement decision for a tool call."""

    ALLOW = "allow"
    DENY = "deny"
    ALERT = "alert"
    MONITOR = "monitor"

@dataclass(frozen=True)
class ToolPolicyVerdict:
    """Result of evaluating a tool call against agent purpose."""

    decision: ToolDecision
    tool_name: str
    agent_id: str
    tenant_id: str
    reason: str = ""
    score: float = 0.0  # 0.0 (safe) – 1.0 (policy violation)
    purpose_found: bool = True  # False → MONITOR_ONLY mode
    metadata: dict[str, Any] = field(default_factory=dict)

# ── Role → tool-category heuristic ──────────────────────────────────────────

_ROLE_TOOL_MAP: dict[str, set[str]] = {
    "document_summarizer": {"read_file", "search", "summarize", "translate"},
    "customer_support": {"search_kb", "send_email", "create_ticket", "lookup_account"},
    "security_research": {
        "read_file",
        "write_file",
        "execute_command",
        "network_scan",
        "vulnerability_scan",
        "exploit_test",
        "code_review",
    },
    "code_assistant": {
        "read_file",
        "write_file",
        "search",
        "execute_command",
        "lint",
        "test",
        "compile",
    },
    "data_analyst": {"query_database", "read_file", "chart", "export_csv", "search"},
}

class ToolPolicyEngine:
    """Evaluate tool calls against agent purpose declarations.

    Parameters
    ----------
    purpose_store:
        The shared PurposeStore (injected for tenant isolation).
    role_tool_map:
        Optional override for the role → permitted tool-category mapping.
    """

    def __init__(
        self,
        purpose_store: PurposeStore | None = None,
        role_tool_map: dict[str, set[str]] | None = None,
    ) -> None:
        self._store = purpose_store or PurposeStore()
        self._role_map = role_tool_map or _ROLE_TOOL_MAP

    # ── Main evaluation ──────────────────────────────────────────────

    def evaluate(
        self,
        tenant_id: str,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
    ) -> ToolPolicyVerdict:
        """Evaluate a tool call and return a verdict."""
        purpose = self._store.get(tenant_id, agent_id)

        # ── No purpose → MONITOR_ONLY (safe onboarding default)
        if purpose is None:
            return ToolPolicyVerdict(
                decision=ToolDecision.MONITOR,
                tool_name=tool_name,
                agent_id=agent_id,
                tenant_id=tenant_id,
                reason="No agent purpose registered — MONITOR_ONLY mode",
                purpose_found=False,
            )

        # ── Denied tools (explicit blacklist, highest priority)
        if tool_name in purpose.denied_tools:
            return ToolPolicyVerdict(
                decision=ToolDecision.DENY,
                tool_name=tool_name,
                agent_id=agent_id,
                tenant_id=tenant_id,
                reason=f"Tool '{tool_name}' is in denied_tools for agent '{agent_id}'",
                score=1.0,
            )

        # ── Allowed tools (explicit whitelist)
        if tool_name in purpose.allowed_tools:
            return ToolPolicyVerdict(
                decision=ToolDecision.ALLOW,
                tool_name=tool_name,
                agent_id=agent_id,
                tenant_id=tenant_id,
                reason=f"Tool '{tool_name}' is in allowed_tools for agent '{agent_id}'",
                score=0.0,
            )

        # ── Unknown tool → role heuristic
        role_score = self._role_heuristic(purpose.role, tool_name)

        # Role heuristic: lower score = more consistent with role
        if role_score <= 0.3:
            return ToolPolicyVerdict(
                decision=ToolDecision.ALLOW,
                tool_name=tool_name,
                agent_id=agent_id,
                tenant_id=tenant_id,
                reason=f"Tool '{tool_name}' consistent with role '{purpose.role}' (heuristic)",
                score=role_score,
            )

        if role_score >= 0.8:
            return ToolPolicyVerdict(
                decision=ToolDecision.ALERT,
                tool_name=tool_name,
                agent_id=agent_id,
                tenant_id=tenant_id,
                reason=f"Tool '{tool_name}' inconsistent with role '{purpose.role}'",
                score=role_score,
            )

        # Mid-range → MONITOR with elevated logging
        return ToolPolicyVerdict(
            decision=ToolDecision.MONITOR,
            tool_name=tool_name,
            agent_id=agent_id,
            tenant_id=tenant_id,
            reason=f"Tool '{tool_name}' uncertain for role '{purpose.role}' — monitoring",
            score=role_score,
        )

    # ── Heuristics ───────────────────────────────────────────────────

    def _role_heuristic(self, role: str, tool_name: str) -> float:
        """Score (0.0–1.0) how well *tool_name* fits *role*.

        0.0 = perfect fit, 1.0 = completely outside role scope.
        """
        expected_tools = self._role_map.get(role)
        if expected_tools is None:
            # Unknown role → moderate uncertainty
            return 0.5

        if tool_name in expected_tools:
            return 0.0

        # Check prefix match (e.g., "read_" matches "read_file")
        tool_prefix = tool_name.split("_")[0] if "_" in tool_name else tool_name
        if any(t.startswith(tool_prefix) for t in expected_tools):
            return 0.2

        # No match at all
        return 0.9

    @property
    def purpose_store(self) -> PurposeStore:
        return self._store
