# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Drift Detection + ABOM Router

REST endpoints:
  Snapshots:
    GET  /api/v1/drift/snapshots              — List snapshots (paginated)
    POST /api/v1/drift/snapshots              — Create a new snapshot
    GET  /api/v1/drift/snapshots/{id}         — Get a single snapshot
    GET  /api/v1/drift/snapshots/latest/{agent_id} — Latest snapshot for agent
    GET  /api/v1/drift/snapshots/diff          — Diff two snapshots
    GET  /api/v1/drift/agents                 — List monitored agent IDs

  Drift Events:
    GET  /api/v1/drift/events                 — List drift events (paginated)
    GET  /api/v1/drift/events/{id}            — Get a single drift event
    POST /api/v1/drift/events/{id}/approve    — Approve a drift event
    POST /api/v1/drift/events/{id}/reject     — Reject a drift event
    POST /api/v1/drift/events/{id}/escalate   — Escalate a drift event
    GET  /api/v1/drift/events/pending         — List pending approvals

  ABOM:
    GET  /api/v1/drift/abom                   — List ABOMs (paginated)
    POST /api/v1/drift/abom                   — Generate a new ABOM
    GET  /api/v1/drift/abom/{id}              — Get a single ABOM
    GET  /api/v1/drift/abom/latest/{agent_id} — Latest ABOM for agent
    GET  /api/v1/drift/abom/{id}/cyclonedx    — Export CycloneDX

  Policy & Stats:
    GET  /api/v1/drift/policy                 — Get drift policy
    PUT  /api/v1/drift/policy                 — Update drift policy
    GET  /api/v1/drift/stats                  — Aggregated stats
    GET  /api/v1/drift/audit-log              — Approval audit log

Security:
  - All endpoints require authentication
  - drift.read:    view snapshots, events, ABOMs, stats
  - drift.manage:  create snapshots, generate ABOMs, configure policy
  - drift.approve: approve/reject/escalate drift events
  - Rate limiting on all endpoints
  - Input validation via Pydantic schemas
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, field_validator

from app.database import get_raw_db
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.services.drift.abom import (
    export_abom_cyclonedx,
    generate_abom,
    get_abom,
    get_latest_abom,
    list_aboms,
)
from app.services.drift.detector import (
    get_drift_event,
    get_drift_stats,
    get_policy,
    list_drift_events,
    process_snapshot_drift,
    upsert_policy,
)
from app.services.drift.snapshot import (
    create_snapshot,
    diff_snapshots,
    get_agent_ids,
    get_latest_snapshot,
    get_snapshot,
    hash_env_vars,
    hash_prompt,
    list_snapshots,
)
from app.services.drift.workflow import (
    approve_drift,
    escalate_drift,
    get_pending_approvals,
    list_approval_log,
    reject_drift,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.router.drift")

router = APIRouter(
    prefix="/api/v1/drift",
    tags=["drift"],
    dependencies=[Depends(rate_limit)],
)

# ── Pydantic Schemas ──────────────────────────────────────────────────────────

_VALID_TRIGGERS = {"discovery", "change", "manual", "scheduled"}
_VALID_MODES = {"strict", "standard", "learning"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"open", "approved", "rejected", "auto_reverted"}

class SnapshotCreate(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255)
    model_provider: str | None = Field(None, max_length=128)
    model_name: str | None = Field(None, max_length=255)
    model_version: str | None = Field(None, max_length=128)
    prompt_text: str | None = Field(None, max_length=100000)  # hashed before storage
    tool_list: list[dict[str, Any]] = Field(default_factory=list)
    permissions: dict[str, Any] = Field(default_factory=dict)
    env_vars: dict[str, str] = Field(default_factory=dict)  # hashed before storage
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    rag_sources: list[dict[str, Any]] = Field(default_factory=list)
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    framework_name: str | None = Field(None, max_length=128)
    framework_version: str | None = Field(None, max_length=64)
    snapshot_trigger: str = Field("manual", max_length=32)
    captured_by: str | None = Field(None, max_length=255)

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w\-\.]+$", v):
            raise ValueError("agent_id must contain only letters, numbers, hyphens, dots, and underscores")
        return v

    @field_validator("snapshot_trigger")
    @classmethod
    def validate_trigger(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in _VALID_TRIGGERS:
            raise ValueError(f"snapshot_trigger must be one of: {', '.join(sorted(_VALID_TRIGGERS))}")
        return v

    @field_validator("tool_list")
    @classmethod
    def validate_tools(cls, v: list[dict]) -> list[dict]:
        if len(v) > 200:
            raise ValueError("Maximum 200 tools allowed")
        for i, t in enumerate(v):
            if "name" not in t:
                raise ValueError(f"Tool {i}: 'name' field required")
            if len(str(t.get("name", ""))) > 255:
                raise ValueError(f"Tool {i}: name too long (max 255 chars)")
        return v

    @field_validator("dependencies")
    @classmethod
    def validate_deps(cls, v: list[dict]) -> list[dict]:
        if len(v) > 1000:
            raise ValueError("Maximum 1000 dependencies allowed")
        return v

class DriftResolve(BaseModel):
    reason: str = Field(..., min_length=1, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        return v.strip()

class PolicyUpdate(BaseModel):
    mode: str = Field("standard", max_length=16)
    alert_on_model_swap: bool = True
    alert_on_prompt_change: bool = True
    alert_on_tool_change: bool = True
    alert_on_permission_escalation: bool = True
    alert_on_dependency_change: bool = False
    alert_on_rag_change: bool = True
    auto_revert_enabled: bool = False
    maintenance_windows: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in _VALID_MODES:
            raise ValueError(f"Mode must be one of: {', '.join(sorted(_VALID_MODES))}")
        return v

    @field_validator("maintenance_windows")
    @classmethod
    def validate_windows(cls, v: list[dict]) -> list[dict]:
        if len(v) > 21:
            raise ValueError("Maximum 21 maintenance windows (3 per day)")
        for i, w in enumerate(v):
            dow = w.get("day_of_week")
            if not isinstance(dow, int) or dow < 0 or dow > 6:
                raise ValueError(f"Window {i}: day_of_week must be 0-6 (Mon-Sun)")
            sh = w.get("start_hour", 0)
            eh = w.get("end_hour", 0)
            if not (0 <= sh < 24 and 0 < eh <= 24 and sh < eh):
                raise ValueError(f"Window {i}: invalid hour range ({sh}-{eh})")
        return v

class AbomGenerate(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255)
    snapshot_id: str | None = Field(None, max_length=64)  # auto-resolves to latest if omitted
    compliance_tags: list[str] = Field(default_factory=list)
    owner: str | None = Field(None, max_length=255)
    data_sources: list[dict[str, Any]] = Field(default_factory=list)
    output_destinations: list[dict[str, Any]] = Field(default_factory=list)
    hitl_enabled: bool = False

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w\-\.]+$", v):
            raise ValueError("agent_id must contain only letters, numbers, hyphens, dots, and underscores")
        return v

    @field_validator("compliance_tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        if len(v) > 50:
            raise ValueError("Maximum 50 compliance tags")
        return [t.strip().lower() for t in v if t.strip()]

# ── Snapshot Endpoints ────────────────────────────────────────────────────────

@router.get("/snapshots", dependencies=[Depends(require_permission("drift.read"))])
async def get_snapshots(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
    agent_id: str | None = Query(None, max_length=255),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List agent config snapshots with optional agent filter."""
    snapshots, total = await list_snapshots(db, user.tenant_id, agent_id=agent_id, limit=limit, offset=offset)
    return {"snapshots": snapshots, "total": total, "limit": limit, "offset": offset}

@router.post("/snapshots", status_code=201, dependencies=[Depends(require_permission("drift.manage"))])
async def create_config_snapshot(
    body: SnapshotCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """
    Create a new agent configuration snapshot.

    If prompt_text is provided, it is hashed (SHA-256) before storage — the raw
    text is never persisted. Same for env_vars values.
    """
    try:
        # Hash sensitive fields before storage
        prompt_hash_val = hash_prompt(body.prompt_text) if body.prompt_text else None
        env_hashes = hash_env_vars(body.env_vars) if body.env_vars else {}

        snapshot = await create_snapshot(
            db,
            tenant_id=user.tenant_id,
            agent_id=body.agent_id,
            model_provider=body.model_provider,
            model_name=body.model_name,
            model_version=body.model_version,
            prompt_hash=prompt_hash_val,
            tool_list=body.tool_list,
            permissions=body.permissions,
            env_var_hashes=env_hashes,
            dependencies=body.dependencies,
            rag_sources=body.rag_sources,
            temperature=body.temperature,
            framework_name=body.framework_name,
            framework_version=body.framework_version,
            snapshot_trigger=body.snapshot_trigger,
            captured_by=body.captured_by,
        )

        # Auto-detect drift against baseline
        drift_events = await process_snapshot_drift(db, user.tenant_id, body.agent_id, snapshot["id"])

        return {
            "snapshot": snapshot,
            "drift_events": drift_events,
            "drift_count": len(drift_events),
        }
    except Exception as e:
        logger.error("snapshot_create_failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/snapshots/diff", dependencies=[Depends(require_permission("drift.read"))])
async def diff_config_snapshots(
    snapshot_a: str = Query(..., min_length=1, max_length=64),
    snapshot_b: str = Query(..., min_length=1, max_length=64),
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Compute a git-style diff between two snapshots."""
    result = await diff_snapshots(db, user.tenant_id, snapshot_a, snapshot_b)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/snapshots/latest/{agent_id}", dependencies=[Depends(require_permission("drift.read"))])
async def get_agent_latest_snapshot(
    agent_id: Annotated[str, Path(max_length=255)],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get the latest config snapshot for a specific agent."""
    snapshot = await get_latest_snapshot(db, user.tenant_id, agent_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No snapshots found for this agent")
    return snapshot

@router.get("/snapshots/{snapshot_id}", dependencies=[Depends(require_permission("drift.read"))])
async def get_single_snapshot(
    snapshot_id: Annotated[str, Path(max_length=64)],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get a single config snapshot by ID."""
    snapshot = await get_snapshot(db, user.tenant_id, snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot

# ── Agent List ────────────────────────────────────────────────────────────────

@router.get("/agents", dependencies=[Depends(require_permission("drift.read"))])
async def list_monitored_agents(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List distinct agent IDs that have config snapshots."""
    agents = await get_agent_ids(db, user.tenant_id)
    return {"agents": agents, "total": len(agents)}

# ── Drift Event Endpoints ────────────────────────────────────────────────────

@router.get("/events/pending", dependencies=[Depends(require_permission("drift.approve"))])
async def get_pending_drift_events(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List open drift events waiting for approval (sorted by severity)."""
    events, total = await get_pending_approvals(db, user.tenant_id, limit=limit, offset=offset)
    return {"events": events, "total": total, "limit": limit, "offset": offset}

@router.get("/events", dependencies=[Depends(require_permission("drift.read"))])
async def get_drift_events_list(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
    agent_id: str | None = Query(None, max_length=255),
    status: str | None = Query(None, pattern=r"^(open|approved|rejected|auto_reverted)$"),
    severity: str | None = Query(None, pattern=r"^(critical|high|medium|low)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List drift events with optional filters."""
    events, total = await list_drift_events(
        db,
        user.tenant_id,
        agent_id=agent_id,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {"events": events, "total": total, "limit": limit, "offset": offset}

@router.get("/events/{event_id}", dependencies=[Depends(require_permission("drift.read"))])
async def get_single_drift_event(
    event_id: Annotated[str, Path(max_length=64)],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get a single drift event by ID."""
    event = await get_drift_event(db, user.tenant_id, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    return event

@router.post("/events/{event_id}/approve", dependencies=[Depends(require_permission("drift.approve"))])
async def approve_drift_event(
    event_id: Annotated[str, Path(max_length=64)],
    body: DriftResolve,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Approve a drift event — marks the config change as intentional."""
    try:
        result = await approve_drift(db, user.tenant_id, event_id, str(user.user_id), body.reason, body.metadata)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/events/{event_id}/reject", dependencies=[Depends(require_permission("drift.approve"))])
async def reject_drift_event(
    event_id: Annotated[str, Path(max_length=64)],
    body: DriftResolve,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Reject a drift event — flags the config change as unauthorized."""
    try:
        result = await reject_drift(db, user.tenant_id, event_id, str(user.user_id), body.reason, body.metadata)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/events/{event_id}/escalate", dependencies=[Depends(require_permission("drift.approve"))])
async def escalate_drift_event(
    event_id: Annotated[str, Path(max_length=64)],
    body: DriftResolve,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Escalate a drift event to a senior analyst."""
    try:
        result = await escalate_drift(db, user.tenant_id, event_id, str(user.user_id), body.reason, body.metadata)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ── ABOM Endpoints ───────────────────────────────────────────────────────────

@router.get("/abom", dependencies=[Depends(require_permission("drift.read"))])
async def get_abom_list(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
    agent_id: str | None = Query(None, max_length=255),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List Agent Bill of Materials with optional agent filter."""
    aboms, total = await list_aboms(db, user.tenant_id, agent_id=agent_id, limit=limit, offset=offset)
    return {"aboms": aboms, "total": total, "limit": limit, "offset": offset}

@router.post("/abom", status_code=201, dependencies=[Depends(require_permission("drift.manage"))])
async def generate_new_abom(
    body: AbomGenerate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Generate a new Agent Bill of Materials from a snapshot."""
    try:
        snapshot_id = body.snapshot_id
        # Auto-resolve to latest snapshot if not provided
        if not snapshot_id:
            latest = await get_latest_snapshot(db, user.tenant_id, body.agent_id)
            if not latest:
                raise ValueError(f"No snapshots found for agent {body.agent_id}")
            snapshot_id = str(latest["id"])

        abom = await generate_abom(
            db,
            tenant_id=user.tenant_id,
            agent_id=body.agent_id,
            snapshot_id=snapshot_id,
            compliance_tags=body.compliance_tags,
            owner=body.owner,
            data_sources=body.data_sources,
            output_destinations=body.output_destinations,
            hitl_enabled=body.hitl_enabled,
        )
        return abom
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("abom_generate_failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/abom/latest/{agent_id}", dependencies=[Depends(require_permission("drift.read"))])
async def get_agent_latest_abom(
    agent_id: Annotated[str, Path(max_length=255)],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get the latest ABOM for a specific agent."""
    abom = await get_latest_abom(db, user.tenant_id, agent_id)
    if not abom:
        raise HTTPException(status_code=404, detail="No ABOM found for this agent")
    return abom

@router.get("/abom/{abom_id}", dependencies=[Depends(require_permission("drift.read"))])
async def get_single_abom(
    abom_id: Annotated[str, Path(max_length=64)],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get a single ABOM by ID."""
    abom = await get_abom(db, user.tenant_id, abom_id)
    if not abom:
        raise HTTPException(status_code=404, detail="ABOM not found")
    return abom

@router.get("/abom/{abom_id}/cyclonedx", dependencies=[Depends(require_permission("drift.read"))])
async def export_abom_cyclonedx_format(
    abom_id: Annotated[str, Path(max_length=64)],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Export an ABOM in CycloneDX SBOM format."""
    cdx = await export_abom_cyclonedx(db, user.tenant_id, abom_id)
    if not cdx:
        raise HTTPException(status_code=404, detail="ABOM not found")
    return cdx

# ── Policy Endpoints ─────────────────────────────────────────────────────────

@router.get("/policy", dependencies=[Depends(require_permission("drift.read"))])
async def get_drift_policy(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get the tenant's drift detection policy."""
    policy = await get_policy(db, user.tenant_id)
    if not policy:
        return {
            "mode": "learning",
            "alert_on_model_swap": True,
            "alert_on_prompt_change": True,
            "alert_on_tool_change": True,
            "alert_on_permission_escalation": True,
            "alert_on_dependency_change": False,
            "alert_on_rag_change": True,
            "auto_revert_enabled": False,
            "maintenance_windows": [],
        }
    return policy

@router.put("/policy", dependencies=[Depends(require_permission("drift.manage"))])
async def update_drift_policy(
    body: PolicyUpdate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create or update the tenant's drift detection policy."""
    try:
        policy = await upsert_policy(
            db,
            tenant_id=user.tenant_id,
            mode=body.mode,
            alert_on_model_swap=body.alert_on_model_swap,
            alert_on_prompt_change=body.alert_on_prompt_change,
            alert_on_tool_change=body.alert_on_tool_change,
            alert_on_permission_escalation=body.alert_on_permission_escalation,
            alert_on_dependency_change=body.alert_on_dependency_change,
            alert_on_rag_change=body.alert_on_rag_change,
            auto_revert_enabled=body.auto_revert_enabled,
            maintenance_windows=body.maintenance_windows,
        )
        return policy
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ── Stats & Audit ─────────────────────────────────────────────────────────────

@router.get("/stats", dependencies=[Depends(require_permission("drift.read"))])
async def get_stats(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get aggregated drift & ABOM statistics for the dashboard."""
    stats = await get_drift_stats(db, user.tenant_id)
    return stats

@router.get("/audit-log", dependencies=[Depends(require_permission("drift.approve"))])
async def get_audit_log(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
    drift_event_id: str | None = Query(None, max_length=64),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """View the immutable drift approval audit log."""
    entries, total = await list_approval_log(
        db,
        user.tenant_id,
        drift_event_id=drift_event_id,
        limit=limit,
        offset=offset,
    )
    return {"entries": entries, "total": total, "limit": limit, "offset": offset}

# ── Reference Data ────────────────────────────────────────────────────────────

@router.get("/drift-types")
async def get_drift_types():
    """List available drift types and their default severities."""
    return {
        "drift_types": [
            {"type": "model_swap", "severity": "critical", "description": "LLM model changed"},
            {"type": "prompt_change", "severity": "high", "description": "System prompt hash changed"},
            {"type": "tool_added", "severity": "high", "description": "New tool or MCP server added"},
            {"type": "tool_removed", "severity": "medium", "description": "Tool or MCP server removed"},
            {"type": "permission_escalation", "severity": "critical", "description": "Permissions widened"},
            {"type": "dependency_change", "severity": "medium", "description": "Dependency version changed"},
            {"type": "rag_change", "severity": "high", "description": "RAG sources changed"},
            {
                "type": "config_change",
                "severity": "low",
                "description": "Other config change (temperature, env vars, etc.)",
            },
        ]
    }

@router.get("/risk-factors")
async def get_risk_factors():
    """List ABOM risk scoring factors and their weights."""
    from app.services.drift.abom import RISK_FACTORS

    return {"risk_factors": RISK_FACTORS}
