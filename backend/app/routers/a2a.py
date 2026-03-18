# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — A2A Protocol Monitoring Router.

Endpoints:
  GET  /api/v1/a2a/cards              — List registered agent cards
  POST /api/v1/a2a/cards              — Register / re-register an agent card
  GET  /api/v1/a2a/cards/:card_id     — Retrieve single agent card
  POST /api/v1/a2a/cards/:card_id/verify  — Mark card verified
  POST /api/v1/a2a/cards/:card_id/revoke  — Revoke card
  GET  /api/v1/a2a/tasks              — List tracked A2A tasks
  GET  /api/v1/a2a/tasks/graph        — Communication graph (nodes + edges)
  GET  /api/v1/a2a/correlations       — Recent A2A ↔ MCP correlations
  POST /api/v1/a2a/fingerprint        — Fingerprint an A2A message
  GET  /api/v1/a2a/stats              — Aggregate stats across all services

All endpoints are tenant-scoped via auth token.
"""

from __future__ import annotations

import uuid as _uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.services.a2a.correlator import A2AMCPCorrelator
from app.services.a2a.fingerprinter import ProtocolFingerprinter
from app.services.a2a.registry import AgentCardRegistry, CardStatus
from app.services.a2a.task_tracker import TaskFlowTracker, TaskStatus
from app.utils.logging import get_logger

logger = get_logger("phantex.a2a_router")

router = APIRouter(
    prefix="/api/v1/a2a",
    tags=["a2a"],
    dependencies=[
        Depends(rate_limit),
        Depends(require_permission("analytics.view")),
    ],
)

_registry = AgentCardRegistry()
_tracker = TaskFlowTracker()
_correlator = A2AMCPCorrelator()
_fingerprinter = ProtocolFingerprinter()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_uuid(value: str, label: str = "id") -> _uuid.UUID:
    """Parse a path/query string as UUID, raising 400 on invalid."""
    try:
        return _uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: {value!r}")

# ── Request / Response schemas ────────────────────────────────────────────────

class CardRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    url: str = Field(..., min_length=1, max_length=2048)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    description: str = Field("", max_length=1024)
    version: str = Field("1.0", max_length=16)
    auth_type: str = Field("none", max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def cap_items_bounded(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > 128:
                raise ValueError("Each capability must be ≤128 chars")
        return v

class FingerprintRequest(BaseModel):
    message: dict[str, Any] = Field(..., description="Raw A2A protocol message to fingerprint")
    message_type: str = Field(
        "", description="Override auto-detection: agent_card, task_request, task_response", max_length=32
    )

    @field_validator("message")
    @classmethod
    def message_bounded(cls, v: dict) -> dict:
        if len(v) > 100:
            raise ValueError("Message may have at most 100 top-level keys")
        return v

# ── Agent Card endpoints ──────────────────────────────────────────────────────

@router.get("/cards")
async def list_cards(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    card_status: str | None = Query(None, alias="status"),
    capability: str | None = None,
):
    """List all registered agent cards with optional filters."""
    status_enum: CardStatus | None = None
    if card_status:
        try:
            status_enum = CardStatus(card_status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {card_status!r}")

    cards = _registry.list_cards(user.tenant_id, status=status_enum, capability=capability)
    return [
        {
            "card_id": str(c.id),
            "name": c.name,
            "url": c.url,
            "capabilities": c.capabilities,
            "status": c.status.value,
            "fingerprint": c.fingerprint,
            "description": c.description,
            "version": c.version,
            "registered_at": c.registered_at.isoformat(),
        }
        for c in cards
    ]

@router.post(
    "/cards", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission("analytics.manage"))]
)
async def register_card(
    body: CardRegisterRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Register or re-register an agent card."""
    card_dict = body.model_dump()
    try:
        card, validation = _registry.register(user.tenant_id, card_dict)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    logger.info(
        "a2a_card_registered_by_user",
        user_id=str(user.user_id),
        tenant_id=str(user.tenant_id),
        card_id=str(card.id),
    )
    return {
        "card_id": str(card.id),
        "name": card.name,
        "status": card.status.value,
        "fingerprint": card.fingerprint,
        "warnings": validation.warnings,
    }

@router.get("/cards/{card_id}")
async def get_card(
    card_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Retrieve a single agent card by ID."""
    cid = _parse_uuid(card_id, "card_id")
    card = _registry.get(user.tenant_id, cid)
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    return {
        "card_id": str(card.id),
        "name": card.name,
        "url": card.url,
        "capabilities": card.capabilities,
        "status": card.status.value,
        "fingerprint": card.fingerprint,
        "description": card.description,
        "version": card.version,
        "auth_type": card.auth_type,
        "registered_at": card.registered_at.isoformat(),
        "updated_at": card.updated_at.isoformat(),
    }

@router.post("/cards/{card_id}/verify", dependencies=[Depends(require_permission("analytics.manage"))])
async def verify_card(
    card_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Mark an agent card as verified."""
    cid = _parse_uuid(card_id, "card_id")
    ok = _registry.verify(user.tenant_id, cid)
    if not ok:
        raise HTTPException(status_code=404, detail="Card not found or already revoked")
    logger.info("a2a_card_verified_by_user", user_id=str(user.user_id), card_id=card_id)
    return {"card_id": card_id, "status": "verified"}

@router.post("/cards/{card_id}/revoke", dependencies=[Depends(require_permission("analytics.manage"))])
async def revoke_card(
    card_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Revoke an agent card."""
    cid = _parse_uuid(card_id, "card_id")
    ok = _registry.revoke(user.tenant_id, cid)
    if not ok:
        raise HTTPException(status_code=404, detail="Card not found")
    logger.info("a2a_card_revoked_by_user", user_id=str(user.user_id), card_id=card_id)
    return {"card_id": card_id, "status": "revoked"}

# ── Task tracking endpoints ───────────────────────────────────────────────────

@router.get("/tasks")
async def list_tasks(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    task_status: str | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
):
    """List tracked A2A delegation tasks."""
    status_enum: TaskStatus | None = None
    if task_status:
        try:
            status_enum = TaskStatus(task_status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {task_status!r}")

    tasks = _tracker.list_tasks(user.tenant_id, status=status_enum, limit=limit)
    return [
        {
            "task_id": t.task_id,
            "source_agent": t.source_agent_id,
            "target_agent": t.target_agent_id,
            "capability": t.capability,
            "status": t.status.value,
            "chain_depth": t.chain_depth,
            "parent_task_id": t.parent_task_id,
            "created_at": t.created_at.isoformat(),
        }
        for t in tasks
    ]

@router.get("/tasks/graph")
async def communication_graph(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return node/edge graph of A2A communication for visualisation."""
    return _tracker.communication_graph(user.tenant_id)

# ── Correlation endpoints ─────────────────────────────────────────────────────

@router.get("/correlations")
async def list_correlations(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Recent A2A ↔ MCP cross-correlation summary."""
    return _correlator.recent_correlations(user.tenant_id)

# ── Fingerprinting ────────────────────────────────────────────────────────────

@router.post("/fingerprint", dependencies=[Depends(require_permission("analytics.manage"))])
async def fingerprint_message(
    body: FingerprintRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Fingerprint an A2A protocol message for conformance."""
    result = _fingerprinter.fingerprint(body.message, body.message_type)
    logger.info(
        "a2a_fingerprint_requested",
        user_id=str(user.user_id),
        message_type=result.message_type,
        score=result.conformance_score,
        suspicious=result.suspicious,
    )
    return {
        "conformance_score": result.conformance_score,
        "message_type": result.message_type,
        "deviations": result.deviations,
        "warnings": result.warnings,
        "suspicious": result.suspicious,
    }

# ── Aggregate stats ──────────────────────────────────────────────────────────

@router.get("/stats")
async def stats(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Aggregate stats across registry, tracker, and correlator."""
    return {
        "registry": _registry.stats(user.tenant_id),
        "tracker": _tracker.stats(user.tenant_id),
        "correlator": _correlator.recent_correlations(user.tenant_id),
    }
