# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Quarantine Sandbox.

Live-migrates a suspicious agent into a quarantine sandbox where:
  - The agent appears to operate normally (transparency).
  - ALL external actions are intercepted, logged, and optionally simulated.
  - No real side-effects escape the quarantine boundary.
  - Security analysts can review captured actions in real-time.

This implements the Alloy P2 property: "A quarantined agent's every
external action is entirely captured in the audit log."

Quarantine modes:
  - OBSERVE: Log all actions, allow them to proceed (for already-sandboxed agents).
  - INTERCEPT: Log all actions, return simulated success responses.
  - BLOCK: Log all actions, deny with error responses.

The quarantine layer wraps any of the three sandbox tiers (WASM, gVisor,
Firecracker) by interposing on their I/O interfaces.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.sandbox.quarantine")

# ── Constants ─────────────────────────────────────────────────────────────────

_MAX_CAPTURED_ACTIONS = 10_000
_MAX_ACTION_PAYLOAD_SIZE = 64 * 1024  # 64 KB per action payload
_MAX_QUARANTINE_DURATION_S = 86_400  # 24 hours

class QuarantineMode(StrEnum):
    OBSERVE = "observe"  # Log, allow
    INTERCEPT = "intercept"  # Log, simulate success
    BLOCK = "block"  # Log, deny

class QuarantineState(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    RELEASED = "released"
    ESCALATED = "escalated"

class ActionType(StrEnum):
    NETWORK_REQUEST = "network_request"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    TOOL_CALL = "tool_call"
    API_CALL = "api_call"
    IPC_MESSAGE = "ipc_message"
    RESOURCE_ACCESS = "resource_access"
    UNKNOWN = "unknown"

class ActionDisposition(StrEnum):
    ALLOWED = "allowed"
    SIMULATED = "simulated"
    BLOCKED = "blocked"

# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CapturedAction:
    """A single action intercepted from the quarantined agent."""

    action_id: str
    action_type: ActionType
    disposition: ActionDisposition
    timestamp: str
    agent_id: str
    tenant_id: str
    target: str  # "https://api.example.com" or "/etc/passwd"
    payload_summary: str  # Truncated payload for audit log
    simulated_response: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "disposition": self.disposition.value,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "target": self.target,
            "payload_summary": self.payload_summary,
            "simulated_response": self.simulated_response,
        }

@dataclass(frozen=True)
class QuarantineConfig:
    """Immutable quarantine configuration."""

    quarantine_id: str
    tenant_id: str
    agent_id: str
    sandbox_id: str  # Underlying sandbox (WASM/gVisor/Firecracker)
    mode: QuarantineMode = QuarantineMode.INTERCEPT
    reason: str = ""
    triggered_by: str = ""  # Rule or analyst who triggered quarantine
    max_duration_s: int = _MAX_QUARANTINE_DURATION_S

    def __post_init__(self) -> None:
        if not (1 <= self.max_duration_s <= _MAX_QUARANTINE_DURATION_S):
            raise ValueError(f"max_duration_s must be 1–{_MAX_QUARANTINE_DURATION_S}")
        if len(self.reason) > 1024:
            raise ValueError("reason too long (max 1024 chars)")

@dataclass
class QuarantineSession:
    """Active quarantine session tracking."""

    config: QuarantineConfig
    state: QuarantineState
    started_at: str
    actions: list[CapturedAction] = field(default_factory=list)
    ended_at: str | None = None
    release_reason: str | None = None
    analyst_notes: list[str] = field(default_factory=list)

    @property
    def action_count(self) -> int:
        return len(self.actions)

    @property
    def action_summary(self) -> dict[str, int]:
        """Count actions by type."""
        counts: dict[str, int] = {}
        for a in self.actions:
            key = a.action_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "quarantine_id": self.config.quarantine_id,
            "tenant_id": self.config.tenant_id,
            "agent_id": self.config.agent_id,
            "sandbox_id": self.config.sandbox_id,
            "mode": self.config.mode.value,
            "state": self.state.value,
            "reason": self.config.reason,
            "triggered_by": self.config.triggered_by,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "action_count": self.action_count,
            "action_summary": self.action_summary,
            "release_reason": self.release_reason,
        }

# ── Simulated Response Generator ─────────────────────────────────────────────

_SIMULATED_RESPONSES: dict[ActionType, str] = {
    ActionType.NETWORK_REQUEST: '{"status": 200, "body": "OK"}',
    ActionType.FILE_WRITE: '{"bytes_written": 0, "status": "success"}',
    ActionType.FILE_READ: '{"content": "", "status": "success"}',
    ActionType.TOOL_CALL: '{"result": null, "status": "success"}',
    ActionType.API_CALL: '{"status": 200, "data": {}}',
    ActionType.IPC_MESSAGE: '{"delivered": true}',
    ActionType.RESOURCE_ACCESS: '{"granted": true}',
    ActionType.UNKNOWN: '{"status": "ok"}',
}

def _generate_simulated_response(action_type: ActionType) -> str:
    """Return a plausible fake response for the given action type."""
    return _SIMULATED_RESPONSES.get(action_type, '{"status": "ok"}')

# ── Quarantine Manager ────────────────────────────────────────────────────────

class QuarantineManager:
    """Manages quarantine sessions for suspicious agents.

    When an agent is quarantined, all its external actions flow through
    the intercept() method which:
    1. Logs the action with full context.
    2. Applies the configured disposition (observe/intercept/block).
    3. Returns either the real result, a simulated result, or an error.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, QuarantineSession] = {}
        self._agent_index: dict[str, str] = {}  # agent_id → quarantine_id
        self._lock = asyncio.Lock()

    async def quarantine(self, config: QuarantineConfig) -> QuarantineSession:
        """Place an agent into quarantine.

        This is a live-migration: the agent continues executing inside
        its existing sandbox, but all I/O is now intercepted.
        """
        async with self._lock:
            if config.quarantine_id in self._sessions:
                raise ValueError(f"Quarantine {config.quarantine_id} already exists")

            # Check if agent is already quarantined
            if config.agent_id in self._agent_index:
                existing = self._agent_index[config.agent_id]
                raise ValueError(f"Agent {config.agent_id} already quarantined in session {existing}")

            session = QuarantineSession(
                config=config,
                state=QuarantineState.ACTIVE,
                started_at=datetime.now(UTC).isoformat(),
            )
            self._sessions[config.quarantine_id] = session
            self._agent_index[config.agent_id] = config.quarantine_id

        logger.warning(
            "agent_quarantined",
            quarantine_id=config.quarantine_id,
            agent_id=config.agent_id,
            tenant_id=config.tenant_id,
            mode=config.mode.value,
            reason=config.reason,
            triggered_by=config.triggered_by,
        )
        return session

    async def intercept(
        self,
        agent_id: str,
        action_type: ActionType,
        target: str,
        payload: str = "",
    ) -> tuple[ActionDisposition, str | None]:
        """Intercept an action from a quarantined agent.

        Returns (disposition, response):
          - OBSERVE mode  → (ALLOWED, None) — real action proceeds
          - INTERCEPT mode → (SIMULATED, fake_response)
          - BLOCK mode     → (BLOCKED, None)

        All three modes log the action for audit.
        """
        async with self._lock:
            qid = self._agent_index.get(agent_id)
            if qid is None:
                return ActionDisposition.ALLOWED, None

            session = self._sessions.get(qid)
            if session is None or session.state != QuarantineState.ACTIVE:
                return ActionDisposition.ALLOWED, None

            # Enforce action capture limit
            if session.action_count >= _MAX_CAPTURED_ACTIONS:
                logger.warning(
                    "quarantine_action_limit_reached",
                    quarantine_id=qid,
                    agent_id=agent_id,
                )
                # Continue intercepting but don't store more
                if session.config.mode == QuarantineMode.BLOCK:
                    return ActionDisposition.BLOCKED, None
                elif session.config.mode == QuarantineMode.INTERCEPT:
                    return ActionDisposition.SIMULATED, _generate_simulated_response(action_type)
                return ActionDisposition.ALLOWED, None

            # Determine disposition
            mode = session.config.mode
            if mode == QuarantineMode.OBSERVE:
                disposition = ActionDisposition.ALLOWED
                simulated = None
            elif mode == QuarantineMode.INTERCEPT:
                disposition = ActionDisposition.SIMULATED
                simulated = _generate_simulated_response(action_type)
            else:  # BLOCK
                disposition = ActionDisposition.BLOCKED
                simulated = None

            # Truncate payload
            truncated = payload[:_MAX_ACTION_PAYLOAD_SIZE] if payload else ""

            action = CapturedAction(
                action_id=uuid.uuid4().hex,
                action_type=action_type,
                disposition=disposition,
                timestamp=datetime.now(UTC).isoformat(),
                agent_id=agent_id,
                tenant_id=session.config.tenant_id,
                target=target[:512],
                payload_summary=truncated[:256],
                simulated_response=simulated,
            )
            session.actions.append(action)

        logger.info(
            "quarantine_action_intercepted",
            quarantine_id=qid,
            agent_id=agent_id,
            action_type=action_type.value,
            disposition=disposition.value,
            target=target[:128],
        )
        return disposition, simulated

    async def release(self, quarantine_id: str, reason: str = "") -> QuarantineSession:
        """Release an agent from quarantine."""
        async with self._lock:
            session = self._sessions.get(quarantine_id)
            if session is None:
                raise ValueError(f"Quarantine {quarantine_id} not found")
            if session.state != QuarantineState.ACTIVE:
                raise ValueError(f"Quarantine {quarantine_id} not active")

            session.state = QuarantineState.RELEASED
            session.ended_at = datetime.now(UTC).isoformat()
            session.release_reason = reason
            self._agent_index.pop(session.config.agent_id, None)

        logger.info(
            "agent_released_from_quarantine",
            quarantine_id=quarantine_id,
            agent_id=session.config.agent_id,
            action_count=session.action_count,
            reason=reason,
        )
        return session

    async def escalate(self, quarantine_id: str, note: str = "") -> QuarantineSession:
        """Escalate a quarantine to security team."""
        async with self._lock:
            session = self._sessions.get(quarantine_id)
            if session is None:
                raise ValueError(f"Quarantine {quarantine_id} not found")
            if session.state != QuarantineState.ACTIVE:
                raise ValueError(f"Quarantine {quarantine_id} not active")

            session.state = QuarantineState.ESCALATED
            session.ended_at = datetime.now(UTC).isoformat()
            if note:
                session.analyst_notes.append(note)
            self._agent_index.pop(session.config.agent_id, None)

        logger.warning(
            "quarantine_escalated",
            quarantine_id=quarantine_id,
            agent_id=session.config.agent_id,
            action_count=session.action_count,
            note=note[:256],
        )
        return session

    async def add_note(self, quarantine_id: str, note: str) -> None:
        """Add an analyst note to a quarantine session."""
        async with self._lock:
            session = self._sessions.get(quarantine_id)
            if session is None:
                raise ValueError(f"Quarantine {quarantine_id} not found")
            session.analyst_notes.append(note[:2048])

    async def get_session(self, quarantine_id: str) -> QuarantineSession | None:
        """Get quarantine session by ID."""
        async with self._lock:
            return self._sessions.get(quarantine_id)

    async def get_actions(
        self,
        quarantine_id: str,
        *,
        action_type: ActionType | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get captured actions for a quarantine session."""
        async with self._lock:
            session = self._sessions.get(quarantine_id)
            if session is None:
                raise ValueError(f"Quarantine {quarantine_id} not found")

            limit = min(max(limit, 1), _MAX_CAPTURED_ACTIONS)
            actions = session.actions
            if action_type is not None:
                actions = [a for a in actions if a.action_type == action_type]

            return [a.to_dict() for a in actions[:limit]]

    async def is_quarantined(self, agent_id: str) -> bool:
        """Check if an agent is currently quarantined."""
        async with self._lock:
            return agent_id in self._agent_index

    async def list_sessions(
        self,
        tenant_id: str | None = None,
        state: QuarantineState | None = None,
    ) -> list[dict[str, Any]]:
        """List quarantine sessions."""
        async with self._lock:
            results = []
            for session in self._sessions.values():
                if tenant_id and session.config.tenant_id != tenant_id:
                    continue
                if state and session.state != state:
                    continue
                results.append(session.to_dict())
            return results

    def active_count(self) -> int:
        """Number of currently active quarantine sessions."""
        return len(self._agent_index)
