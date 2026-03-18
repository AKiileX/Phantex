# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — A2A + MCP Cross-Correlator.

Detects when A2A task delegations lead to suspicious MCP tool usage.
Correlates the two protocol streams to find patterns like:
  - Agent A delegates "data export" → Agent B uses MCP write_file
  - Delegated task accesses tools outside the requested capability
  - Unknown agent receives delegation then calls sensitive MCP tools

Correlation is event-driven: as new events arrive they are matched
against recent A2A tasks and MCP tool calls within the same tenant.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.a2a.correlator")

# MCP tools that are high-risk when combined with delegation
_SENSITIVE_MCP_TOOLS = frozenset(
    {
        "write_file",
        "delete_file",
        "exec",
        "shell",
        "bash",
        "cmd",
        "http_request",
        "send_email",
        "database_query",
        "secret_read",
        "deploy",
        "kubectl",
        "terraform",
        "aws_cli",
    }
)

_CORRELATION_WINDOW = timedelta(minutes=30)

@dataclass
class CorrelationEvent:
    """A cross-protocol correlation finding."""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID = field(default_factory=uuid.uuid4)
    a2a_task_id: str = ""
    mcp_tool_call_id: str = ""
    source_agent_id: str = ""
    target_agent_id: str = ""
    delegated_capability: str = ""
    mcp_tool_name: str = ""
    severity: str = "medium"
    description: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

class A2AMCPCorrelator:
    """Correlate A2A delegations with MCP tool calls."""

    def __init__(self) -> None:
        # Recent A2A tasks: {tenant_id: [(timestamp, task_dict), ...]}
        self._recent_tasks: dict[uuid.UUID, list[tuple[datetime, dict[str, Any]]]] = {}
        # Recent MCP calls: {tenant_id: [(timestamp, call_dict), ...]}
        self._recent_mcp: dict[uuid.UUID, list[tuple[datetime, dict[str, Any]]]] = {}

    # ── Ingest events ─────────────────────────────────────────────────

    def ingest_a2a_task(
        self,
        tenant_id: uuid.UUID,
        task: dict[str, Any],
    ) -> list[CorrelationEvent]:
        """Ingest an A2A task event and check for correlations."""
        now = datetime.now(UTC)
        self._recent_tasks.setdefault(tenant_id, []).append((now, task))
        self._prune(tenant_id)

        # Check against recent MCP calls
        return self._correlate_task_vs_mcp(tenant_id, task)

    def ingest_mcp_call(
        self,
        tenant_id: uuid.UUID,
        mcp_call: dict[str, Any],
    ) -> list[CorrelationEvent]:
        """Ingest an MCP tool call event and check for correlations."""
        now = datetime.now(UTC)
        self._recent_mcp.setdefault(tenant_id, []).append((now, mcp_call))
        self._prune(tenant_id)

        # Check against recent A2A tasks
        return self._correlate_mcp_vs_tasks(tenant_id, mcp_call)

    # ── Correlation logic ─────────────────────────────────────────────

    def _correlate_task_vs_mcp(
        self,
        tenant_id: uuid.UUID,
        task: dict[str, Any],
    ) -> list[CorrelationEvent]:
        """Check if a new A2A task correlates with recent MCP activity."""
        findings: list[CorrelationEvent] = []
        target = task.get("target_agent_id", "")

        for _, mcp in self._recent_mcp.get(tenant_id, []):
            if mcp.get("agent_id") != target:
                continue

            tool = mcp.get("tool_name", "")
            if tool in _SENSITIVE_MCP_TOOLS:
                findings.append(
                    CorrelationEvent(
                        tenant_id=tenant_id,
                        a2a_task_id=task.get("task_id", ""),
                        mcp_tool_call_id=mcp.get("call_id", ""),
                        source_agent_id=task.get("source_agent_id", ""),
                        target_agent_id=target,
                        delegated_capability=task.get("capability", ""),
                        mcp_tool_name=tool,
                        severity="high",
                        description=(
                            f"Agent {target} used sensitive MCP tool '{tool}' "
                            f"after receiving delegation from {task.get('source_agent_id', '')}"
                        ),
                    )
                )

        if findings:
            logger.warning(
                "a2a_mcp_correlation_found",
                tenant_id=str(tenant_id),
                count=len(findings),
            )
        return findings

    def _correlate_mcp_vs_tasks(
        self,
        tenant_id: uuid.UUID,
        mcp_call: dict[str, Any],
    ) -> list[CorrelationEvent]:
        """Check if a new MCP call correlates with recent A2A delegations."""
        findings: list[CorrelationEvent] = []
        agent = mcp_call.get("agent_id", "")
        tool = mcp_call.get("tool_name", "")

        if tool not in _SENSITIVE_MCP_TOOLS:
            return findings

        for _, task in self._recent_tasks.get(tenant_id, []):
            if task.get("target_agent_id") != agent:
                continue

            findings.append(
                CorrelationEvent(
                    tenant_id=tenant_id,
                    a2a_task_id=task.get("task_id", ""),
                    mcp_tool_call_id=mcp_call.get("call_id", ""),
                    source_agent_id=task.get("source_agent_id", ""),
                    target_agent_id=agent,
                    delegated_capability=task.get("capability", ""),
                    mcp_tool_name=tool,
                    severity="high",
                    description=(
                        f"Sensitive MCP tool '{tool}' called by {agent} "
                        f"who was delegated '{task.get('capability', '')}' "
                        f"by {task.get('source_agent_id', '')}"
                    ),
                )
            )

        if findings:
            logger.warning(
                "mcp_a2a_correlation_found",
                tenant_id=str(tenant_id),
                agent=agent,
                tool=tool,
                count=len(findings),
            )
        return findings

    # ── Recent findings query ─────────────────────────────────────────

    def recent_correlations(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Return summary of recent cross-protocol correlations."""
        tasks_count = len(self._recent_tasks.get(tenant_id, []))
        mcp_count = len(self._recent_mcp.get(tenant_id, []))
        return {
            "window_minutes": int(_CORRELATION_WINDOW.total_seconds() / 60),
            "recent_a2a_tasks": tasks_count,
            "recent_mcp_calls": mcp_count,
        }

    # ── Pruning ───────────────────────────────────────────────────────

    def _prune(self, tenant_id: uuid.UUID) -> None:
        """Remove events older than the correlation window."""
        cutoff = datetime.now(UTC) - _CORRELATION_WINDOW
        if tenant_id in self._recent_tasks:
            self._recent_tasks[tenant_id] = [(ts, t) for ts, t in self._recent_tasks[tenant_id] if ts >= cutoff]
        if tenant_id in self._recent_mcp:
            self._recent_mcp[tenant_id] = [(ts, c) for ts, c in self._recent_mcp[tenant_id] if ts >= cutoff]
