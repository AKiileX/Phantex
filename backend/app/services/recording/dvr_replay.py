# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — DVR Replay Engine.

Reconstructs agent decision timelines from recorded events for
step-by-step forensic replay:
  - What the agent saw (inputs, environment)
  - What it decided (LLM reasoning, tool selection)
  - What it did (tool calls, API requests, results)

Supports side-by-side comparison of normal vs incident behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class StepType(StrEnum):
    """Types of replay timeline steps."""

    INPUT = "input"  # What the agent received
    DECISION = "decision"  # LLM reasoning / tool selection
    ACTION = "action"  # Tool call / API request
    RESULT = "result"  # Outcome of the action
    BLOCKED = "blocked"  # Action blocked by Phantex rule

@dataclass
class ReplayStep:
    """A single step in a DVR replay timeline."""

    index: int
    step_type: StepType
    timestamp: str
    agent_id: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    rule_matched: str | None = None
    trust_score: float | None = None
    duration_us: int | None = None  # Microseconds

@dataclass
class ReplaySession:
    """A complete replay session for an agent."""

    session_id: str
    tenant_id: str
    agent_id: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    steps: list[ReplayStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_total_us(self) -> int:
        """Total duration across all steps with timing."""
        return sum(s.duration_us for s in self.steps if s.duration_us)

    @property
    def blocked_count(self) -> int:
        """Number of steps that were blocked by rules."""
        return sum(1 for s in self.steps if s.step_type == StepType.BLOCKED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "step_count": len(self.steps),
            "duration_total_us": self.duration_total_us,
            "blocked_count": self.blocked_count,
            "steps": [
                {
                    "index": s.index,
                    "step_type": s.step_type.value,
                    "timestamp": s.timestamp,
                    "agent_id": s.agent_id,
                    "summary": s.summary,
                    "details": s.details,
                    "rule_matched": s.rule_matched,
                    "trust_score": s.trust_score,
                    "duration_us": s.duration_us,
                }
                for s in self.steps
            ],
            "metadata": self.metadata,
        }

class DVRReplayEngine:
    """Reconstructs agent timelines from RecordingEvents.

    Converts raw recording data into ordered ReplayStep sequences
    suitable for interactive timeline scrubbing in the dashboard.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, ReplaySession] = {}  # session_id → session
        self._max_sessions = 10_000  # Memory guard — evict oldest beyond this

    def build_replay(
        self,
        session_id: str,
        tenant_id: str,
        agent_id: str,
        events: list[dict[str, Any]],
    ) -> ReplaySession:
        """Build a replay session from a list of serialized recording events.

        Each event dict must have an ``audit`` key with at minimum
        ``timestamp``, ``event_type``, ``agent_id``.
        """
        session = ReplaySession(
            session_id=session_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
        )

        for idx, evt in enumerate(events):
            audit = evt.get("audit", {})
            extended = evt.get("extended", {})
            dvr_data = evt.get("dvr", {})

            event_type = audit.get("event_type", "unknown")
            step_type = self._classify_step(event_type, audit.get("result", "success"))

            details: dict[str, Any] = {}
            if audit.get("tool_name"):
                details["tool_name"] = audit["tool_name"]
            if audit.get("data_classification"):
                details["data_classification"] = audit["data_classification"]
            if audit.get("bytes_transferred"):
                details["bytes_transferred"] = audit["bytes_transferred"]

            # Include extended fields if present
            if extended:
                if extended.get("tool_parameters"):
                    details["tool_parameters"] = extended["tool_parameters"]
                if extended.get("api_request_body"):
                    details["api_request"] = extended["api_request_body"]
                if extended.get("api_response_body"):
                    details["api_response"] = extended["api_response_body"]
                if extended.get("llm_prompt_hash"):
                    details["llm_prompt_hash"] = extended["llm_prompt_hash"]

            # Include DVR fields if present
            if dvr_data:
                if dvr_data.get("llm_prompt_content"):
                    details["llm_prompt"] = dvr_data["llm_prompt_content"]
                if dvr_data.get("llm_response_content"):
                    details["llm_response"] = dvr_data["llm_response_content"]
                if dvr_data.get("rag_results"):
                    details["rag_results"] = dvr_data["rag_results"]
                if dvr_data.get("environment_snapshot"):
                    details["environment"] = dvr_data["environment_snapshot"]

            summary = self._build_summary(event_type, audit, step_type)

            step = ReplayStep(
                index=idx,
                step_type=step_type,
                timestamp=audit.get("timestamp", datetime.now(UTC).isoformat()),
                agent_id=audit.get("agent_id", agent_id),
                summary=summary,
                details=details,
                rule_matched=audit.get("rule_matched"),
                trust_score=audit.get("trust_score"),
                duration_us=dvr_data.get("timing_microseconds"),
            )
            session.steps.append(step)

        self._sessions[session_id] = session

        # Memory guard — evict oldest sessions beyond cap
        if len(self._sessions) > self._max_sessions:
            oldest_keys = list(self._sessions.keys())[: len(self._sessions) - self._max_sessions]
            for k in oldest_keys:
                del self._sessions[k]

        return session

    def get_session(self, session_id: str, tenant_id: str) -> ReplaySession | None:
        """Retrieve a built replay session, scoped to tenant."""
        session = self._sessions.get(session_id)
        if session and session.tenant_id == tenant_id:
            return session
        return None

    def list_sessions(self, tenant_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """List replay sessions for a tenant (metadata only)."""
        sessions = [
            {
                "session_id": s.session_id,
                "agent_id": s.agent_id,
                "created_at": s.created_at,
                "step_count": len(s.steps),
                "blocked_count": s.blocked_count,
            }
            for s in self._sessions.values()
            if s.tenant_id == tenant_id
        ]
        return sessions[-limit:]

    def compare_sessions(
        self,
        session_a_id: str,
        session_b_id: str,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """Side-by-side comparison of two replay sessions (normal vs incident)."""
        a = self.get_session(session_a_id, tenant_id)
        b = self.get_session(session_b_id, tenant_id)
        if not a or not b:
            return None

        return {
            "session_a": {
                "session_id": a.session_id,
                "agent_id": a.agent_id,
                "step_count": len(a.steps),
                "blocked_count": a.blocked_count,
                "duration_total_us": a.duration_total_us,
            },
            "session_b": {
                "session_id": b.session_id,
                "agent_id": b.agent_id,
                "step_count": len(b.steps),
                "blocked_count": b.blocked_count,
                "duration_total_us": b.duration_total_us,
            },
            "diff": {
                "step_count_delta": len(b.steps) - len(a.steps),
                "blocked_delta": b.blocked_count - a.blocked_count,
                "duration_delta_us": b.duration_total_us - a.duration_total_us,
            },
        }

    # ── Internal helpers ─────────────────────────────────────────────

    @staticmethod
    def _classify_step(event_type: str, result: str) -> StepType:
        """Map event type + result to a replay step type."""
        if result == "blocked":
            return StepType.BLOCKED
        mapping = {
            "llm_invoke": StepType.DECISION,
            "llm_response": StepType.RESULT,
            "tool_call": StepType.ACTION,
            "api_request": StepType.ACTION,
            "api_response": StepType.RESULT,
            "agent_input": StepType.INPUT,
            "user_message": StepType.INPUT,
        }
        return mapping.get(event_type, StepType.ACTION)

    @staticmethod
    def _build_summary(event_type: str, audit: dict[str, Any], step_type: StepType) -> str:
        """Build a human-readable summary for a replay step."""
        tool = audit.get("tool_name", "")
        result = audit.get("result", "success")
        classification = audit.get("data_classification", "clean")

        if step_type == StepType.BLOCKED:
            rule = audit.get("rule_matched", "unknown rule")
            return f"Blocked by {rule}: {event_type} → {tool or 'N/A'}"
        if step_type == StepType.DECISION:
            return f"LLM decision → selected {tool or 'next action'}"
        if step_type == StepType.INPUT:
            return f"Received {event_type}"
        if classification != "clean":
            return f"{event_type}: {tool or 'N/A'} ({result}) [{classification}]"
        return f"{event_type}: {tool or 'N/A'} ({result})"
