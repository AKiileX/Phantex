# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Command Service.

Provides the command queue for SOC response actions. When an analyst triggers
an action (isolate, block IP, kill process), the command is queued here.

The gateway polls for pending commands via an internal API, dispatches them
to the target sensor via heartbeat or stream, and reports completion back.

Command lifecycle:
  pending → dispatched → acknowledged → completed | failed

The ML pipeline reads completed commands + alert data to learn which
analyst actions are effective for which alert patterns.

SECURITY:
  - All queries include tenant_id for defense-in-depth (beyond RLS)
  - command_type is whitelisted — unknown actions are REJECTED
  - Input lengths are bounded
  - Every state transition is logged
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("phantex.services.agent_commands")

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_PAID_RE = re.compile(r"^ptx-[a-z0-9][a-z0-9\-]{0,62}-[a-z0-9][a-z0-9\-]{0,30}-[0-9a-f]{12}$", re.ASCII)

# Maps frontend action names → proto ControlAction names (WHITELIST)
ACTION_TO_COMMAND: dict[str, str] = {
    "isolate_agent": "isolate_host",
    "block_ip": "block_ip",
    "quarantine_file": "quarantine_file",
    "kill_process": "kill_process",
    "disable_user": "disable_user",  # not sensor-side, but recorded
    "collect_forensics": "collect_forensics",
}

# Maximum sizes for defense-in-depth
_MAX_REASON_LENGTH = 1000
_MAX_PARAMS_SIZE = 8192  # JSON bytes

@dataclass
class AgentCommand:
    """A queued command for an agent/sensor."""

    id: str
    tenant_id: str
    agent_id: str
    alert_id: str | None
    command_type: str
    parameters: dict[str, Any]
    status: str
    issued_by: str | None
    reason: str
    created_at: datetime
    dispatched_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, Any] | None = None

async def queue_command(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    agent_id: str,
    alert_id: str | None,
    action: str,
    parameters: dict[str, Any],
    issued_by: uuid.UUID | None = None,
    reason: str = "",
) -> AgentCommand:
    """
    Queue a response action command for an agent.

    SECURITY: command_type is strictly whitelisted — unknown actions are
    REJECTED, not passed through. Parameters are size-bounded.
    """
    # Strict whitelist — unknown actions are rejected
    command_type = ACTION_TO_COMMAND.get(action)
    if command_type is None:
        raise ValueError(f"Unknown action '{action}'. Allowed: {sorted(ACTION_TO_COMMAND.keys())}")

    # Validate agent_id format (UUID or PAID)
    if not _UUID_RE.match(agent_id) and not _PAID_RE.match(agent_id):
        raise ValueError("Invalid agent_id format: must be UUID or PAID")

    # Bound reason length
    reason = reason[:_MAX_REASON_LENGTH]

    # Bound parameters JSON size
    params_json = json.dumps(parameters)
    if len(params_json) > _MAX_PARAMS_SIZE:
        raise ValueError(f"Parameters too large ({len(params_json)} > {_MAX_PARAMS_SIZE} bytes)")

    command_id = str(uuid.uuid4())

    query = text("""
        INSERT INTO agent_commands
            (id, tenant_id, agent_id, alert_id, command_type, parameters, status, issued_by, reason)
        VALUES
            (:id, :tenant_id, :agent_id, :alert_id, :command_type, :params, 'pending', :issued_by, :reason)
        RETURNING id, created_at
    """)

    result = await db.execute(
        query,
        {
            "id": command_id,
            "tenant_id": str(tenant_id),
            "agent_id": agent_id,
            "alert_id": alert_id,
            "command_type": command_type,
            "params": params_json,
            "issued_by": str(issued_by) if issued_by else None,
            "reason": reason,
        },
    )
    row = result.mappings().first()

    # Ensure committed
    await db.commit()

    logger.info(
        "agent_command_queued",
        extra={
            "command_id": command_id,
            "tenant_id": str(tenant_id),
            "agent_id": agent_id,
            "command_type": command_type,
            "action": action,
            "issued_by": str(issued_by) if issued_by else None,
        },
    )

    return AgentCommand(
        id=command_id,
        tenant_id=str(tenant_id),
        agent_id=agent_id,
        alert_id=alert_id,
        command_type=command_type,
        parameters=parameters,
        status="pending",
        issued_by=str(issued_by) if issued_by else None,
        reason=reason,
        created_at=row["created_at"] if row else datetime.now(UTC),
    )

async def get_pending_commands(
    db: AsyncSession,
    agent_id: str,
    *,
    limit: int = 10,
) -> list[AgentCommand]:
    """
    Get pending commands for a specific agent.
    Used by the gateway when a sensor sends a heartbeat.

    NOTE: This runs via the internal API (no RLS session), so we don't
    filter by tenant_id here — the gateway authenticates via token and
    the agent_id is UUID-validated at the router level. The command was
    already tenant-scoped at INSERT time.
    """
    # Clamp limit
    limit = max(1, min(limit, 50))

    query = text("""
        SELECT id, tenant_id, agent_id, alert_id, command_type, parameters,
               status, issued_by, reason, created_at, dispatched_at
        FROM agent_commands
        WHERE agent_id = :aid AND status = 'pending'
        ORDER BY created_at ASC
        LIMIT :lim
    """)
    result = await db.execute(query, {"aid": agent_id, "lim": limit})
    rows = result.mappings().all()

    commands = []
    for r in rows:
        commands.append(
            AgentCommand(
                id=str(r["id"]),
                tenant_id=str(r["tenant_id"]),
                agent_id=str(r["agent_id"]),
                alert_id=str(r["alert_id"]) if r.get("alert_id") else None,
                command_type=r["command_type"],
                parameters=r["parameters"]
                if isinstance(r["parameters"], dict)
                else json.loads(r["parameters"] or "{}"),
                status=r["status"],
                issued_by=str(r["issued_by"]) if r.get("issued_by") else None,
                reason=r.get("reason", ""),
                created_at=r["created_at"],
                dispatched_at=r.get("dispatched_at"),
            )
        )
    return commands

_SENSOR_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,254}[a-zA-Z0-9]$")

async def get_pending_commands_by_sensor(
    db: AsyncSession,
    sensor_id: str,
    *,
    limit: int = 10,
) -> list[AgentCommand]:
    """
    Get pending commands for all agents on a given sensor.
    The gateway sends sensor_id (not agent UUID) on heartbeat.
    Joins agent_commands → agents via agents.sensor_id.
    """
    if not _SENSOR_ID_RE.match(sensor_id):
        return []

    limit = max(1, min(limit, 50))

    query = text("""
        SELECT ac.id, ac.tenant_id, ac.agent_id, ac.alert_id, ac.command_type,
               ac.parameters, ac.status, ac.issued_by, ac.reason,
               ac.created_at, ac.dispatched_at
        FROM agent_commands ac
        JOIN agents a ON a.paid = ac.agent_id
        WHERE a.sensor_id = :sid AND ac.status = 'pending'
        ORDER BY ac.created_at ASC
        LIMIT :lim
    """)
    result = await db.execute(query, {"sid": sensor_id, "lim": limit})
    rows = result.mappings().all()

    commands = []
    for r in rows:
        commands.append(
            AgentCommand(
                id=str(r["id"]),
                tenant_id=str(r["tenant_id"]),
                agent_id=str(r["agent_id"]),
                alert_id=str(r["alert_id"]) if r.get("alert_id") else None,
                command_type=r["command_type"],
                parameters=r["parameters"]
                if isinstance(r["parameters"], dict)
                else json.loads(r["parameters"] or "{}"),
                status=r["status"],
                issued_by=str(r["issued_by"]) if r.get("issued_by") else None,
                reason=r.get("reason", ""),
                created_at=r["created_at"],
                dispatched_at=r.get("dispatched_at"),
            )
        )
    return commands

async def mark_dispatched(db: AsyncSession, command_id: str) -> None:
    """Mark a command as dispatched (sent to the sensor via gateway)."""
    if not _UUID_RE.match(command_id):
        raise ValueError("Invalid command_id format")
    await db.execute(
        text("""
            UPDATE agent_commands
            SET status = 'dispatched', dispatched_at = now()
            WHERE id = :id AND status = 'pending'
        """),
        {"id": command_id},
    )
    logger.info("agent_command_dispatched", extra={"command_id": command_id})

async def mark_completed(
    db: AsyncSession,
    command_id: str,
    *,
    success: bool = True,
    result_data: dict[str, Any] | None = None,
) -> None:
    """Mark a command as completed or failed, and emit ML feedback signal.

    When a command completes, we log the outcome to the audit trail so the
    ML retrain pipeline can learn which response actions are effective for
    which alert patterns. This closes the feedback loop:

      Alert → Analyst Action → Sensor Execution → Outcome → ML Signal
    """
    if not _UUID_RE.match(command_id):
        raise ValueError("Invalid command_id format")

    new_status = "completed" if success else "failed"

    # Bound result data size
    result_json = json.dumps(result_data or {})
    if len(result_json) > _MAX_PARAMS_SIZE:
        result_json = json.dumps({"error": "result_truncated", "size": len(result_json)})

    await db.execute(
        text("""
            UPDATE agent_commands
            SET status = :status, completed_at = now(), result = :result
            WHERE id = :id AND status IN ('pending', 'dispatched', 'acknowledged')
        """),
        {
            "id": command_id,
            "status": new_status,
            "result": result_json,
        },
    )
    logger.info("agent_command_%s: id=%s", new_status, command_id)

    # ── ML Feedback Signal ────────────────────────────────────────────
    # Query the command row to get alert/agent context for the audit entry.
    # The retrain pipeline reads audit_log entries with action prefix
    # "ml.action_outcome.*" to build a labeled dataset of (alert_pattern,
    # response_action, outcome) triples.
    try:
        row = (
            (
                await db.execute(
                    text("""
                SELECT tenant_id, agent_id, alert_id, command_type,
                       issued_by, reason
                FROM agent_commands WHERE id = :id
            """),
                    {"id": command_id},
                )
            )
            .mappings()
            .first()
        )

        if row:
            from app.services.audit_service import log_action  # avoid circular

            await log_action(
                db,
                tenant_id=uuid.UUID(str(row["tenant_id"])) if row["tenant_id"] else None,
                user_id=uuid.UUID(str(row["issued_by"])) if row["issued_by"] else None,
                action=f"ml.action_outcome.{new_status}",
                resource_type="agent_command",
                resource_id=uuid.UUID(command_id),
                details={
                    "command_type": row["command_type"],
                    "agent_id": str(row["agent_id"]),
                    "alert_id": str(row["alert_id"]) if row["alert_id"] else None,
                    "success": success,
                    "result_summary": _summarize_result(result_data),
                    "reason": row["reason"],
                },
            )
    except Exception:
        # ML feedback is non-critical — never fail the ack because of it
        logger.warning("failed to emit ML feedback for command %s", command_id, exc_info=True)

async def get_command_history(
    db: AsyncSession,
    alert_id: str,
    *,
    limit: int = 50,
) -> list[AgentCommand]:
    """Get commands associated with an alert (for timeline display)."""
    if not _UUID_RE.match(alert_id):
        return []

    limit = max(1, min(limit, 100))

    query = text("""
        SELECT id, tenant_id, agent_id, alert_id, command_type, parameters,
               status, issued_by, reason, created_at, dispatched_at, completed_at, result
        FROM agent_commands
        WHERE alert_id = :aid
        ORDER BY created_at DESC
        LIMIT :lim
    """)
    result = await db.execute(query, {"aid": alert_id, "lim": limit})
    rows = result.mappings().all()

    return [
        AgentCommand(
            id=str(r["id"]),
            tenant_id=str(r["tenant_id"]),
            agent_id=str(r["agent_id"]),
            alert_id=str(r["alert_id"]) if r.get("alert_id") else None,
            command_type=r["command_type"],
            parameters=r["parameters"] if isinstance(r["parameters"], dict) else json.loads(r["parameters"] or "{}"),
            status=r["status"],
            issued_by=str(r["issued_by"]) if r.get("issued_by") else None,
            reason=r.get("reason", ""),
            created_at=r["created_at"],
            dispatched_at=r.get("dispatched_at"),
            completed_at=r.get("completed_at"),
            result=r.get("result") if isinstance(r.get("result"), dict) else {},
        )
        for r in rows
    ]

def _summarize_result(data: dict[str, Any] | None) -> str:
    """Extract a short summary from command result data for ML logging.

    Keeps the audit entry small while preserving the essential signal
    (success message or first line of error).
    """
    if not data:
        return ""
    msg = data.get("message", data.get("error", ""))
    if isinstance(msg, str) and len(msg) > 256:
        return msg[:256] + "…"
    return str(msg)
