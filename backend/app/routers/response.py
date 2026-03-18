# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Automated Response Router.

REST API for managing the auto-response decision layer:

  ── Kill Switch ──────────────────────────────────────────────────────────────
  GET  /api/v1/response/kill-switch          — Get kill switch status
  POST /api/v1/response/kill-switch          — Toggle kill switch (ON/OFF)

  ── Shadow Mode ──────────────────────────────────────────────────────────────
  GET  /api/v1/response/shadow               — Get shadow mode status
  POST /api/v1/response/shadow/enable        — Enable shadow mode
  POST /api/v1/response/shadow/disable       — Disable shadow mode (go live!)

  ── Response Policies ────────────────────────────────────────────────────────
  GET  /api/v1/response/policies             — List response policies
  POST /api/v1/response/policies             — Create a response policy
  PUT  /api/v1/response/policies/{id}        — Update a response policy
  DEL  /api/v1/response/policies/{id}        — Delete a response policy

  ── Escalation ───────────────────────────────────────────────────────────────
  GET  /api/v1/response/escalation           — List escalation states
  DEL  /api/v1/response/escalation/{agent_id} — Reset escalation for agent

  ── Action Log ───────────────────────────────────────────────────────────────
  GET  /api/v1/response/log                  — View auto-response action log

  ── Human Override ───────────────────────────────────────────────────────────
  POST /api/v1/response/override/{log_id}    — Override/undo a past action

  ── Config ───────────────────────────────────────────────────────────────────
  GET  /api/v1/response/config               — Get full response config
  PUT  /api/v1/response/config               — Update response config

SECURITY:
  - All endpoints require authentication (get_current_user)
  - Kill switch + override require "response.kill_switch" / "response.override"
  - Write operations require "response.write"
  - Read-only requires "response.read"
  - All mutations are audit-logged
  - Input validation via Pydantic models with strict bounds
  - Tenant isolation via enforce_tenant_isolation dependency
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.services import audit_service
from app.services.response.escalation import (
    get_escalation_state,
    reset_escalation,
)
from app.utils.validators import validate_agent_id
from app.services.response.orchestrator import (
    get_kill_switch_status,
    set_kill_switch,
)
from app.services.response.policy_engine import (
    ALLOWED_ACTIONS,
    invalidate_policy_cache,
)
from app.services.response.shadow import (
    disable_shadow_mode,
    enable_shadow_mode,
    get_shadow_status,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.router.response")

router = APIRouter(
    prefix="/api/v1/response",
    tags=["auto-response"],
    dependencies=[Depends(rate_limit)],
)

# ── Pydantic schemas ──────────────────────────────────────────────────────────

class KillSwitchRequest(BaseModel):
    active: bool
    reason: str = Field("", max_length=1000)

class ShadowEnableRequest(BaseModel):
    duration_hours: int | None = Field(None, ge=1, le=8760, description="Hours before auto-expiry (null=indefinite)")

class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=2000)
    severity: list[str] = Field(default_factory=list, max_length=10)
    attack_class: list[str] = Field(default_factory=list, max_length=20)
    event_type: list[str] = Field(default_factory=list, max_length=20)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    action: str
    action_params: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    priority: int = Field(100, ge=0, le=10000)
    cooldown_sec: int = Field(300, ge=0, le=86400)
    require_shadow: bool = True

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ALLOWED_ACTIONS:
            raise ValueError(f"Invalid action '{v}'. Allowed: {sorted(ALLOWED_ACTIONS)}")
        return v

    @field_validator("severity", "attack_class", "event_type", mode="before")
    @classmethod
    def validate_string_lists(cls, v: Any) -> list[str]:
        if isinstance(v, list):
            result = []
            for item in v[:20]:  # Cap at 20 items
                s = str(item).strip().lower()
                if s and len(s) <= 100:
                    result.append(s)
            return result
        return []

    @field_validator("action_params")
    @classmethod
    def validate_params_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(v)) > 8192:
            raise ValueError("action_params too large (>8KB)")
        return v

class PolicyUpdate(PolicyCreate):
    """Same as create — full replacement."""

    pass

class OverrideRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)

class ConfigUpdate(BaseModel):
    escalation_enabled: bool | None = None
    escalation_window: int | None = Field(None, ge=60, le=86400)
    escalation_steps: list[dict[str, Any]] | None = None
    max_actions_per_hour: int | None = Field(None, ge=1, le=1000)

    @field_validator("escalation_steps")
    @classmethod
    def validate_steps(cls, v: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if v is None:
            return None
        if len(v) > 10:
            raise ValueError("Maximum 10 escalation steps")
        for step in v:
            if "level" not in step or "action" not in step:
                raise ValueError("Each step must have 'level' and 'action'")
            if step["action"] not in ALLOWED_ACTIONS:
                raise ValueError(f"Invalid action in step: {step['action']}")
        return v

# ══════════════════════════════════════════════════════════════════════════════
#  KILL SWITCH
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/kill-switch",
    summary="Get kill switch status",
    dependencies=[Depends(require_permission("response.read"))],
)
async def get_kill_switch(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Check if the auto-response kill switch is active."""
    return await get_kill_switch_status(db, str(current_user.tenant_id))

@router.post(
    "/kill-switch",
    summary="Toggle kill switch",
    dependencies=[Depends(require_permission("response.kill_switch"))],
)
async def toggle_kill_switch(
    body: KillSwitchRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Toggle the auto-response kill switch. When ON, all auto-response is halted."""
    result = await set_kill_switch(
        db,
        str(current_user.tenant_id),
        active=body.active,
        reason=body.reason,
        set_by=str(current_user.user_id),
    )

    # Audit log
    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action=f"response.kill_switch.{'activate' if body.active else 'deactivate'}",
        resource_type="response_config",
        details={"active": body.active, "reason": body.reason},
    )
    await db.commit()

    return result

# ══════════════════════════════════════════════════════════════════════════════
#  SHADOW MODE
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/shadow",
    summary="Get shadow mode status",
    dependencies=[Depends(require_permission("response.read"))],
)
async def get_shadow(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Check if shadow mode is active (log-only, no enforcement)."""
    return await get_shadow_status(db, str(current_user.tenant_id))

@router.post(
    "/shadow/enable",
    summary="Enable shadow mode",
    dependencies=[Depends(require_permission("response.write"))],
)
async def enable_shadow(
    body: ShadowEnableRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Enable shadow mode — actions will be logged but NOT enforced."""
    result = await enable_shadow_mode(
        db,
        str(current_user.tenant_id),
        set_by=str(current_user.user_id),
        duration_hours=body.duration_hours,
    )

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.shadow.enable",
        resource_type="response_config",
        details=result,
    )
    await db.commit()

    return result

@router.post(
    "/shadow/disable",
    summary="Disable shadow mode (GO LIVE)",
    dependencies=[Depends(require_permission("response.write"))],
)
async def disable_shadow(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Disable shadow mode — actions will now enforce in real-time. High-impact!"""
    result = await disable_shadow_mode(
        db,
        str(current_user.tenant_id),
        set_by=str(current_user.user_id),
    )

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.shadow.disable",
        resource_type="response_config",
        details={"warning": "Auto-response is now LIVE — enforcement active"},
    )
    await db.commit()

    return result

# ══════════════════════════════════════════════════════════════════════════════
#  RESPONSE POLICIES (CRUD)
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/policies",
    summary="List response policies",
    dependencies=[Depends(require_permission("response.read"))],
)
async def list_policies(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    enabled_only: bool = Query(False),
):
    """List all response policies for the current tenant."""
    tid = str(current_user.tenant_id)
    query_str = """
        SELECT id, name, description, severity, attack_class, event_type,
               min_confidence, action, action_params, enabled, priority,
               cooldown_sec, require_shadow, created_by, created_at, updated_at
        FROM response_policies
        WHERE tenant_id = :tid
    """
    if enabled_only:
        query_str += " AND enabled = true"
    query_str += " ORDER BY priority ASC, created_at ASC"

    result = await db.execute(text(query_str), {"tid": tid})
    rows = result.mappings().all()

    return {
        "policies": [
            {
                "id": str(r["id"]),
                "name": r["name"],
                "description": r["description"],
                "severity": r["severity"] or [],
                "attack_class": r["attack_class"] or [],
                "event_type": r["event_type"] or [],
                "min_confidence": r["min_confidence"],
                "action": r["action"],
                "action_params": r["action_params"] or {},
                "enabled": r["enabled"],
                "priority": r["priority"],
                "cooldown_sec": r["cooldown_sec"],
                "require_shadow": r["require_shadow"],
                "created_by": str(r["created_by"]) if r["created_by"] else None,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
            }
            for r in rows
        ],
        "total": len(rows),
    }

@router.post(
    "/policies",
    status_code=status.HTTP_201_CREATED,
    summary="Create response policy",
    dependencies=[Depends(require_permission("response.write"))],
)
async def create_policy(
    body: PolicyCreate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Create a new auto-response policy."""
    tid = str(current_user.tenant_id)
    policy_id = str(uuid.uuid4())

    query = text("""
        INSERT INTO response_policies
            (id, tenant_id, name, description, severity, attack_class, event_type,
             min_confidence, action, action_params, enabled, priority, cooldown_sec,
             require_shadow, created_by)
        VALUES
            (:id, :tid, :name, :desc, :severity, :attack_class, :event_type,
             :min_conf, :action, CAST(:params AS jsonb), :enabled, :priority, :cooldown,
             :require_shadow, :created_by)
        RETURNING id, created_at
    """)
    result = await db.execute(
        query,
        {
            "id": policy_id,
            "tid": tid,
            "name": body.name,
            "desc": body.description,
            "severity": body.severity,
            "attack_class": body.attack_class,
            "event_type": body.event_type,
            "min_conf": body.min_confidence,
            "action": body.action,
            "params": json.dumps(body.action_params),
            "enabled": body.enabled,
            "priority": body.priority,
            "cooldown": body.cooldown_sec,
            "require_shadow": body.require_shadow,
            "created_by": str(current_user.user_id),
        },
    )
    row = result.mappings().first()
    await db.commit()

    # Invalidate cache for this tenant
    invalidate_policy_cache(tid)

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.policy.create",
        resource_type="response_policy",
        resource_id=uuid.UUID(policy_id),
        details={"name": body.name, "action": body.action},
    )
    await db.commit()

    return {"id": policy_id, "created_at": row["created_at"].isoformat() if row else None}

@router.put(
    "/policies/{policy_id}",
    summary="Update response policy",
    dependencies=[Depends(require_permission("response.write"))],
)
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Update an existing response policy (full replacement)."""
    tid = str(current_user.tenant_id)

    # Check exists + belongs to tenant
    check = await db.execute(
        text("SELECT id FROM response_policies WHERE id = :pid AND tenant_id = :tid"),
        {"pid": str(policy_id), "tid": tid},
    )
    if not check.first():
        raise HTTPException(status_code=404, detail="Policy not found")

    query = text("""
        UPDATE response_policies SET
            name = :name, description = :desc,
            severity = :severity, attack_class = :attack_class, event_type = :event_type,
            min_confidence = :min_conf, action = :action, action_params = CAST(:params AS jsonb),
            enabled = :enabled, priority = :priority, cooldown_sec = :cooldown,
            require_shadow = :require_shadow, updated_at = now()
        WHERE id = :pid AND tenant_id = :tid
    """)
    await db.execute(
        query,
        {
            "pid": str(policy_id),
            "tid": tid,
            "name": body.name,
            "desc": body.description,
            "severity": body.severity,
            "attack_class": body.attack_class,
            "event_type": body.event_type,
            "min_conf": body.min_confidence,
            "action": body.action,
            "params": json.dumps(body.action_params),
            "enabled": body.enabled,
            "priority": body.priority,
            "cooldown": body.cooldown_sec,
            "require_shadow": body.require_shadow,
        },
    )
    await db.commit()

    invalidate_policy_cache(tid)

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.policy.update",
        resource_type="response_policy",
        resource_id=policy_id,
        details={"name": body.name, "action": body.action},
    )
    await db.commit()

    return {"updated": True}

@router.delete(
    "/policies/{policy_id}",
    summary="Delete response policy",
    dependencies=[Depends(require_permission("response.write"))],
)
async def delete_policy(
    policy_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Delete a response policy."""
    tid = str(current_user.tenant_id)

    result = await db.execute(
        text("DELETE FROM response_policies WHERE id = :pid AND tenant_id = :tid"),
        {"pid": str(policy_id), "tid": tid},
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Policy not found")

    await db.commit()
    invalidate_policy_cache(tid)

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.policy.delete",
        resource_type="response_policy",
        resource_id=policy_id,
    )
    await db.commit()

    return {"deleted": True}

# ══════════════════════════════════════════════════════════════════════════════
#  ESCALATION
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/escalation",
    summary="List escalation states",
    dependencies=[Depends(require_permission("response.read"))],
)
async def list_escalation(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    agent_id: str | None = None,
):
    """List escalation ladder states for agents."""
    return {
        "states": await get_escalation_state(
            db,
            tenant_id=str(current_user.tenant_id),
            agent_id=str(agent_id) if agent_id else None,
        ),
    }

@router.delete(
    "/escalation/{agent_id}",
    summary="Reset agent escalation",
    dependencies=[Depends(require_permission("response.override"))],
)
async def reset_agent_escalation(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Reset the escalation ladder for a specific agent (Human Override)."""
    validate_agent_id(agent_id)
    tid = str(current_user.tenant_id)
    deleted = await reset_escalation(db, tenant_id=tid, agent_id=str(agent_id))
    await db.commit()

    if not deleted:
        raise HTTPException(status_code=404, detail="No escalation state for this agent")

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.escalation.reset",
        resource_type="escalation_state",
        details={"agent_id": str(agent_id)},
    )
    await db.commit()

    return {"reset": True, "agent_id": str(agent_id)}

# ══════════════════════════════════════════════════════════════════════════════
#  ACTION LOG
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/log",
    summary="View auto-response action log",
    dependencies=[Depends(require_permission("response.read"))],
)
async def get_action_log(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    decision: str | None = Query(None, description="Filter by decision type"),
    agent_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """View the immutable auto-response action log."""
    tid = str(current_user.tenant_id)

    # Whitelist decision filter values (defense-in-depth)
    _VALID_DECISIONS = frozenset(
        {
            "executed",
            "shadow",
            "blocked_kill_switch",
            "cooldown_skip",
            "escalated",
            "overridden",
            "rate_limited",
            "error",
        }
    )

    conditions = ["tenant_id = :tid"]
    params: dict[str, Any] = {"tid": tid, "lim": limit, "off": offset}

    if decision:
        if decision not in _VALID_DECISIONS:
            raise HTTPException(status_code=400, detail=f"Invalid decision filter. Allowed: {sorted(_VALID_DECISIONS)}")
        conditions.append("decision = :decision")
        params["decision"] = decision
    if agent_id:
        conditions.append("agent_id = :agent_id")
        params["agent_id"] = str(agent_id)

    where = " AND ".join(conditions)
    query_str = f"""
        SELECT id, alert_id, policy_id, agent_id, action, action_params,
               decision, escalation_level, alert_severity, alert_confidence,
               attack_class, event_type, overridden_by, override_reason,
               created_at, executed_at
        FROM response_action_log
        WHERE {where}
        ORDER BY created_at DESC
        LIMIT :lim OFFSET :off
    """
    result = await db.execute(text(query_str), params)
    rows = result.mappings().all()

    # Count total
    count_result = await db.execute(
        text(f"SELECT COUNT(*) AS cnt FROM response_action_log WHERE {where}"),
        {k: v for k, v in params.items() if k not in ("lim", "off")},
    )
    total = count_result.scalar() or 0

    return {
        "entries": [
            {
                "id": str(r["id"]),
                "alert_id": str(r["alert_id"]) if r["alert_id"] else None,
                "policy_id": str(r["policy_id"]) if r["policy_id"] else None,
                "agent_id": str(r["agent_id"]) if r["agent_id"] else None,
                "action": r["action"],
                "action_params": r["action_params"] or {},
                "decision": r["decision"],
                "escalation_level": r["escalation_level"],
                "alert_severity": r["alert_severity"],
                "alert_confidence": r["alert_confidence"],
                "attack_class": r["attack_class"],
                "event_type": r["event_type"],
                "overridden_by": str(r["overridden_by"]) if r["overridden_by"] else None,
                "override_reason": r["override_reason"] or "",
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "executed_at": r["executed_at"].isoformat() if r["executed_at"] else None,
            }
            for r in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  HUMAN OVERRIDE
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/override/{log_id}",
    summary="Override a past auto-response action",
    dependencies=[Depends(require_permission("response.override"))],
)
async def override_action(
    log_id: uuid.UUID,
    body: OverrideRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Mark a past auto-response action as overridden by a human operator.

    This records the override in the immutable log and can trigger
    reversal actions (e.g., unisolate an agent that was auto-isolated).
    """
    tid = str(current_user.tenant_id)

    # Load the original log entry
    query = text("""
        SELECT id, action, agent_id, decision, action_params
        FROM response_action_log
        WHERE id = :lid AND tenant_id = :tid
    """)
    result = await db.execute(query, {"lid": str(log_id), "tid": tid})
    row = result.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Action log entry not found")

    if row["decision"] == "overridden":
        raise HTTPException(status_code=409, detail="Action already overridden")

    # Record the override (new row — the original is immutable)
    override_id = str(uuid.uuid4())
    override_query = text("""
        INSERT INTO response_action_log
            (id, tenant_id, alert_id, policy_id, agent_id, action, action_params,
             decision, overridden_by, override_reason, created_at)
        SELECT :new_id, tenant_id, alert_id, policy_id, agent_id,
               action, action_params, 'overridden', :uid, :reason, now()
        FROM response_action_log
        WHERE id = :lid AND tenant_id = :tid
    """)
    await db.execute(
        override_query,
        {
            "new_id": override_id,
            "lid": str(log_id),
            "tid": tid,
            "uid": str(current_user.user_id),
            "reason": body.reason[:1000],
        },
    )

    # If the original action was an agent command, queue a reversal
    reversal_queued = False
    original_action = row["action"]
    agent_id = str(row["agent_id"]) if row["agent_id"] else None

    if original_action == "isolate_agent" and agent_id:
        try:
            from app.services.agent_command_service import queue_command

            await queue_command(
                db,
                tenant_id=uuid.UUID(tid),
                agent_id=agent_id,
                alert_id=None,
                action="isolate_agent",  # The command service maps this
                parameters={"unisolate": True},
                issued_by=current_user.user_id,
                reason=f"Human override: {body.reason[:500]}",
            )
            reversal_queued = True
        except Exception as exc:
            logger.warning("reversal_queue_failed", error=str(exc), agent_id=agent_id)

    await db.commit()

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.override",
        resource_type="response_action_log",
        resource_id=log_id,
        details={
            "original_action": original_action,
            "reason": body.reason,
            "reversal_queued": reversal_queued,
        },
    )
    await db.commit()

    return {
        "override_id": override_id,
        "original_action": original_action,
        "reversal_queued": reversal_queued,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/config",
    summary="Get response engine configuration",
    dependencies=[Depends(require_permission("response.read"))],
)
async def get_config(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get the full auto-response configuration for the current tenant."""
    tid = str(current_user.tenant_id)

    query = text("""
        SELECT kill_switch, kill_switch_reason, kill_switch_set_by, kill_switch_set_at,
               shadow_mode, shadow_expires_at, shadow_set_by,
               escalation_enabled, escalation_window, escalation_steps,
               max_actions_per_hour, updated_by, updated_at
        FROM response_config
        WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tid})
    row = result.mappings().first()

    if not row:
        return {
            "exists": False,
            "kill_switch": False,
            "shadow_mode": True,
            "escalation_enabled": True,
            "escalation_window": 3600,
            "max_actions_per_hour": 50,
        }

    return {
        "exists": True,
        "kill_switch": row["kill_switch"],
        "kill_switch_reason": row["kill_switch_reason"] or "",
        "kill_switch_set_at": row["kill_switch_set_at"].isoformat() if row["kill_switch_set_at"] else None,
        "shadow_mode": row["shadow_mode"],
        "shadow_expires_at": row["shadow_expires_at"].isoformat() if row["shadow_expires_at"] else None,
        "escalation_enabled": row["escalation_enabled"],
        "escalation_window": row["escalation_window"],
        "escalation_steps": row["escalation_steps"],
        "max_actions_per_hour": row["max_actions_per_hour"],
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }

@router.put(
    "/config",
    summary="Update response engine configuration",
    dependencies=[Depends(require_permission("response.write"))],
)
async def update_config(
    body: ConfigUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Update auto-response configuration for the current tenant."""
    tid = str(current_user.tenant_id)

    # Build dynamic SET clause — only update provided fields
    updates: list[str] = ["updated_by = :uid", "updated_at = now()"]
    params: dict[str, Any] = {"tid": tid, "uid": str(current_user.user_id)}

    if body.escalation_enabled is not None:
        updates.append("escalation_enabled = :esc_enabled")
        params["esc_enabled"] = body.escalation_enabled
    if body.escalation_window is not None:
        updates.append("escalation_window = :esc_window")
        params["esc_window"] = body.escalation_window
    if body.escalation_steps is not None:
        updates.append("escalation_steps = CAST(:esc_steps AS jsonb)")
        params["esc_steps"] = json.dumps(body.escalation_steps)
    if body.max_actions_per_hour is not None:
        updates.append("max_actions_per_hour = :max_hour")
        params["max_hour"] = body.max_actions_per_hour

    set_clause = ", ".join(updates)

    # Upsert
    query = text(f"""
        INSERT INTO response_config (tenant_id, updated_by, updated_at)
        VALUES (:tid, :uid, now())
        ON CONFLICT (tenant_id) DO UPDATE SET {set_clause}
    """)
    await db.execute(query, params)
    await db.commit()

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="response.config.update",
        resource_type="response_config",
        details={k: v for k, v in params.items() if k not in ("tid", "uid")},
    )
    await db.commit()

    return {"updated": True}
