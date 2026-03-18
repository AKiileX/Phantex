# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Audit & DVR Recording Router.

Endpoints:
  GET   /api/v1/audit-recording/config            — List recording configs
  PUT   /api/v1/audit-recording/config             — Set recording level
  GET   /api/v1/audit-recording/events             — Query recorded events
  GET   /api/v1/audit-recording/timeline/:agent_id — Agent session timeline
  GET   /api/v1/audit-recording/stats              — Recording + chain stats
  POST  /api/v1/audit-recording/replay             — Build DVR replay session
  GET   /api/v1/audit-recording/replay/:session_id — Get replay session
  GET   /api/v1/audit-recording/replay             — List replay sessions
  POST  /api/v1/audit-recording/replay/compare     — Compare two sessions
  GET   /api/v1/audit-recording/chain              — Query audit chain entries
  POST  /api/v1/audit-recording/chain/verify       — Verify chain integrity
  POST  /api/v1/audit-recording/legal-hold         — Set legal hold
  DELETE /api/v1/audit-recording/legal-hold        — Release legal hold
  GET   /api/v1/audit-recording/legal-hold         — List legal holds
  POST  /api/v1/audit-recording/export             — Generate compliance export
  GET   /api/v1/audit-recording/export             — List exports

All endpoints are tenant-scoped via auth token.
"""

from __future__ import annotations

import re as _re
import uuid as _uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.services.recording.compliance_export import (
    ComplianceExporter,
    ComplianceFramework,
)
from app.services.recording.dvr_replay import DVRReplayEngine
from app.services.recording.session_recorder import (
    RecordingLevel,
    SessionRecorder,
)
from app.services.recording.tamper_proof_chain import (
    ChainAction,
    TamperProofChain,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.audit_recording_router")

router = APIRouter(
    prefix="/api/v1/audit-recording",
    tags=["audit-recording"],
    dependencies=[
        Depends(rate_limit),
        Depends(require_permission("analytics.view")),
    ],
)

# Service singletons (production: DI container)
_recorder = SessionRecorder()
_replay = DVRReplayEngine()
_chain = TamperProofChain()
_exporter = ComplianceExporter(_chain, _recorder)

_User = Annotated[CurrentUser, Depends(get_current_active_user)]

# ── Helpers ──────────────────────────────────────────────────────────────

def _tenant(user: CurrentUser) -> str:
    return str(user.tenant_id)

def _user_id(user: CurrentUser) -> str:
    return str(user.user_id)

_SAFE_ID = _re.compile(r"^[a-zA-Z0-9_\-.:]+$")

def _validated_id(value: str, name: str, max_len: int = 128) -> str:
    """Validate an identifier contains only safe characters."""
    if len(value) > max_len:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{name} too long")
    if not _SAFE_ID.match(value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid {name}")
    return value

_VALID_LEVELS = {1, 2, 3}
_VALID_FRAMEWORKS = {f.value for f in ComplianceFramework}

# ── Request / Response models ────────────────────────────────────────────

class SetConfigRequest(BaseModel):
    agent_id: str | None = Field(None, max_length=128)
    level: int = Field(1, ge=1, le=3)
    enabled: bool = True

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: int) -> int:
        if v not in _VALID_LEVELS:
            raise ValueError("level must be 1, 2, or 3")
        return v

class ReplayBuildRequest(BaseModel):
    agent_id: str = Field(..., max_length=128)
    limit: int = Field(500, ge=1, le=5000)

class ReplayCompareRequest(BaseModel):
    session_a_id: str = Field(..., max_length=64)
    session_b_id: str = Field(..., max_length=64)

class LegalHoldRequest(BaseModel):
    agent_id: str = Field(..., max_length=128)
    reason: str = Field(..., min_length=1, max_length=500)

class LegalHoldReleaseRequest(BaseModel):
    agent_id: str = Field(..., max_length=128)

class ExportRequest(BaseModel):
    framework: str = Field(..., max_length=32)
    period_start: str | None = Field(None, max_length=64)
    period_end: str | None = Field(None, max_length=64)

    @field_validator("framework")
    @classmethod
    def validate_framework(cls, v: str) -> str:
        if v not in _VALID_FRAMEWORKS:
            raise ValueError(f"framework must be one of: {', '.join(sorted(_VALID_FRAMEWORKS))}")
        return v

# ── Recording Config endpoints ───────────────────────────────────────────

@router.get("/config")
async def list_configs(user: _User) -> dict[str, Any]:
    """List all recording configurations for the tenant."""
    configs = _recorder.get_configs(_tenant(user))
    logger.info("audit_recording.config.list", user_id=_user_id(user), tenant_id=_tenant(user))
    return {
        "configs": [
            {
                "tenant_id": c.tenant_id,
                "agent_id": c.agent_id,
                "level": c.level.value,
                "enabled": c.enabled,
            }
            for c in configs
        ]
    }

@router.put("/config")
async def set_config(body: SetConfigRequest, user: _User) -> dict[str, Any]:
    """Set recording level for tenant or specific agent."""
    level = RecordingLevel(body.level)
    config = _recorder.set_config(_tenant(user), body.agent_id, level, enabled=body.enabled)

    _chain.append(
        _tenant(user),
        ChainAction.LEVEL_CHANGED,
        _user_id(user),
        agent_id=body.agent_id,
        details={"new_level": body.level},
    )

    logger.info(
        "audit_recording.config.set",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        agent_id=body.agent_id,
        level=body.level,
    )
    return {
        "tenant_id": config.tenant_id,
        "agent_id": config.agent_id,
        "level": config.level.value,
        "enabled": config.enabled,
    }

# ── Recording Events endpoints ──────────────────────────────────────────

@router.get("/events")
async def get_events(
    user: _User,
    agent_id: str | None = Query(None, max_length=128),
    event_type: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """Query recorded events for the tenant."""
    events = _recorder.get_events(
        _tenant(user),
        agent_id=agent_id,
        event_type=event_type,
        limit=limit,
    )
    logger.info(
        "audit_recording.events.query",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        count=len(events),
    )
    return {"events": [e.to_dict() for e in events], "count": len(events)}

@router.get("/timeline/{agent_id}")
async def get_timeline(agent_id: str, user: _User, limit: int = Query(500, ge=1, le=5000)) -> dict[str, Any]:
    """Get session timeline for a specific agent."""
    agent_id = _validated_id(agent_id, "agent_id")
    timeline = _recorder.get_session_timeline(_tenant(user), agent_id, limit=limit)
    return {"agent_id": agent_id, "events": timeline, "count": len(timeline)}

@router.get("/stats")
async def get_stats(user: _User) -> dict[str, Any]:
    """Recording + chain aggregate stats."""
    rec_stats = _recorder.stats(_tenant(user))
    chain_stats = _chain.stats(_tenant(user))
    return {
        "recording": rec_stats,
        "chain": chain_stats,
    }

# ── DVR Replay endpoints ────────────────────────────────────────────────

@router.post("/replay")
async def build_replay(body: ReplayBuildRequest, user: _User) -> dict[str, Any]:
    """Build a DVR replay session from recorded events."""
    events = _recorder.get_events(_tenant(user), agent_id=body.agent_id, limit=body.limit)
    if not events:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No events found for agent")

    session_id = _uuid.uuid4().hex
    event_dicts = [e.to_dict() for e in events]
    session = _replay.build_replay(session_id, _tenant(user), body.agent_id, event_dicts)

    _chain.append(
        _tenant(user),
        ChainAction.SESSION_REPLAYED,
        _user_id(user),
        agent_id=body.agent_id,
        details={"session_id": session_id, "step_count": len(session.steps)},
    )

    logger.info(
        "audit_recording.replay.built",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        session_id=session_id,
        steps=len(session.steps),
    )
    return session.to_dict()

@router.get("/replay/{session_id}")
async def get_replay(session_id: str, user: _User) -> dict[str, Any]:
    """Get a previously built replay session."""
    session_id = _validated_id(session_id, "session_id", max_len=64)
    session = _replay.get_session(session_id, _tenant(user))
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Replay session not found")
    return session.to_dict()

@router.get("/replay")
async def list_replays(user: _User, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    """List replay sessions for the tenant."""
    sessions = _replay.list_sessions(_tenant(user), limit=limit)
    return {"sessions": sessions, "count": len(sessions)}

@router.post("/replay/compare")
async def compare_replays(body: ReplayCompareRequest, user: _User) -> dict[str, Any]:
    """Side-by-side comparison of two replay sessions."""
    result = _replay.compare_sessions(body.session_a_id, body.session_b_id, _tenant(user))
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both sessions not found")
    return result

# ── Tamper-Proof Chain endpoints ─────────────────────────────────────────

@router.get("/chain")
async def get_chain_entries(
    user: _User,
    action: str | None = Query(None, max_length=64),
    agent_id: str | None = Query(None, max_length=128),
    since: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """Query tamper-proof audit chain entries."""
    chain_action = None
    if action:
        try:
            chain_action = ChainAction(action)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid action. Valid: {', '.join(a.value for a in ChainAction)}",
            )
    if since:
        # Basic ISO 8601 format check to prevent garbage string comparison
        from datetime import datetime as _dt

        try:
            _dt.fromisoformat(since)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="since must be ISO 8601")
    entries = _chain.get_entries(
        _tenant(user),
        action=chain_action,
        agent_id=agent_id,
        since=since,
        limit=limit,
    )
    return {"entries": [e.to_dict() for e in entries], "count": len(entries)}

@router.post("/chain/verify")
async def verify_chain(user: _User) -> dict[str, Any]:
    """Verify the tamper-proof audit chain integrity."""
    result = _chain.verify_chain(_tenant(user))

    _chain.append(
        _tenant(user),
        ChainAction.CHAIN_VERIFIED,
        _user_id(user),
        details={"result": result},
    )

    logger.info(
        "audit_recording.chain.verified",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        valid=result.get("valid"),
    )
    return result

# ── Legal Hold endpoints ─────────────────────────────────────────────────

@router.post("/legal-hold")
async def set_legal_hold(body: LegalHoldRequest, user: _User) -> dict[str, Any]:
    """Set a legal hold on an agent's recordings."""
    hold = _chain.set_legal_hold(
        _tenant(user),
        body.agent_id,
        body.reason,
        _user_id(user),
    )
    logger.info(
        "audit_recording.legal_hold.set",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        agent_id=body.agent_id,
    )
    return {
        "agent_id": hold.agent_id,
        "reason": hold.reason,
        "held_by": hold.held_by,
        "held_at": hold.held_at,
        "active": hold.active,
    }

@router.delete("/legal-hold")
async def release_legal_hold(body: LegalHoldReleaseRequest, user: _User) -> dict[str, Any]:
    """Release an active legal hold."""
    hold = _chain.release_legal_hold(_tenant(user), body.agent_id, _user_id(user))
    if not hold:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active hold found for agent")
    logger.info(
        "audit_recording.legal_hold.released",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        agent_id=body.agent_id,
    )
    return {
        "agent_id": hold.agent_id,
        "released_at": hold.released_at,
        "released_by": hold.released_by,
        "active": hold.active,
    }

@router.get("/legal-hold")
async def list_legal_holds(
    user: _User,
    active_only: bool = Query(True),
) -> dict[str, Any]:
    """List legal holds for the tenant."""
    holds = _chain.get_legal_holds(_tenant(user), active_only=active_only)
    return {
        "holds": [
            {
                "agent_id": h.agent_id,
                "reason": h.reason,
                "held_by": h.held_by,
                "held_at": h.held_at,
                "released_at": h.released_at,
                "active": h.active,
            }
            for h in holds
        ],
        "count": len(holds),
    }

# ── Compliance Export endpoints ──────────────────────────────────────────

@router.post("/export")
async def generate_export(body: ExportRequest, user: _User) -> dict[str, Any]:
    """Generate a compliance evidence package."""
    framework = ComplianceFramework(body.framework)
    package = _exporter.generate(
        _tenant(user),
        framework,
        _user_id(user),
        period_start=body.period_start,
        period_end=body.period_end,
    )
    logger.info(
        "audit_recording.export.generated",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        framework=body.framework,
        entries=len(package.audit_entries),
    )
    return package.to_dict()

@router.get("/export")
async def list_exports(user: _User, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    """List compliance exports for the tenant."""
    exports = _exporter.list_exports(_tenant(user), limit=limit)
    return {"exports": exports, "count": len(exports)}
