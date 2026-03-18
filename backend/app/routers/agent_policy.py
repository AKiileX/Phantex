# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Tagging & Policy Router

P1: PATCH /api/v1/agents/{id}/tags    — Set agent tags
     GET  /api/v1/agents/{id}/tags    — Get agent tags
P2: POST  /api/v1/policies/exemptions  — Create exemption
     GET  /api/v1/policies/exemptions  — List exemptions
     GET  /api/v1/policies/exemptions/{id}
    PATCH /api/v1/policies/exemptions/{id}
   DELETE /api/v1/policies/exemptions/{id}
P3: POST  /api/v1/policies/routing     — Create routing rule
     GET  /api/v1/policies/routing     — List routing rules
     GET  /api/v1/policies/routing/{id}
     PUT  /api/v1/policies/routing/{id}
   DELETE /api/v1/policies/routing/{id}
    POST /api/v1/policies/routing/simulate — Simulate routing
P4: POST  /api/v1/policies/maintenance-windows           — Create
     GET  /api/v1/policies/maintenance-windows           — List
     GET  /api/v1/policies/maintenance-windows/{id}
     PUT  /api/v1/policies/maintenance-windows/{id}
   DELETE /api/v1/policies/maintenance-windows/{id}
    POST /api/v1/policies/maintenance-windows/{id}/force-end
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.agent_policy import (
    AgentTagsResponse,
    AgentTagsUpdate,
    ExemptionCreate,
    ExemptionResponse,
    ExemptionUpdate,
    MaintenanceWindowCreate,
    MaintenanceWindowResponse,
    MaintenanceWindowUpdate,
    RoutingRuleCreate,
    RoutingRuleResponse,
    RoutingRuleUpdate,
    RoutingSimulationRequest,
    RoutingSimulationResult,
)
from app.schemas.auth import CurrentUser
from app.services import agent_policy_service as svc

# ═══════════════════════════════════════════════════════════════════════════════
#  P1: Agent Tags (mounted on the agents prefix)
# ═══════════════════════════════════════════════════════════════════════════════

tag_router = APIRouter(
    prefix="/api/v1/agents",
    tags=["agent-tags"],
    dependencies=[Depends(rate_limit)],
)

@tag_router.get(
    "/{agent_id}/tags",
    summary="Get agent tags",
)
async def get_agent_tags(
    agent_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    tags = await svc.get_agent_tags(db, agent_id)
    if tags is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return {"agent_id": agent_id, "tags": tags}

@tag_router.patch(
    "/{agent_id}/tags",
    response_model=AgentTagsResponse,
    summary="Set agent tags",
    dependencies=[Depends(require_permission("agent_policy.manage"))],
)
async def set_agent_tags(
    agent_id: uuid.UUID,
    body: AgentTagsUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    agent = await svc.set_agent_tags(
        db,
        agent_id,
        body.tags,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
    )
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return AgentTagsResponse(agent_id=agent.id, tags=agent.tags, updated_at=agent.updated_at)

# ═══════════════════════════════════════════════════════════════════════════════
#  P2: Rule Exemptions
# ═══════════════════════════════════════════════════════════════════════════════

exemption_router = APIRouter(
    prefix="/api/v1/policies/exemptions",
    tags=["exemptions"],
    dependencies=[Depends(rate_limit), Depends(require_permission("agent_policy.manage"))],
)

@exemption_router.post(
    "",
    response_model=ExemptionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create rule exemption",
)
async def create_exemption(
    body: ExemptionCreate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    exemption = await svc.create_exemption(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        rule_name=body.rule_name,
        match_tags=body.match_tags,
        reason=body.reason,
        expires_at=body.expires_at,
    )
    return exemption

@exemption_router.get(
    "",
    response_model=list[ExemptionResponse],
    summary="List exemptions",
)
async def list_exemptions(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    rule_name: str | None = None,
    enabled_only: bool = True,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    return await svc.list_exemptions(
        db,
        rule_name=rule_name,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset,
    )

@exemption_router.get(
    "/{exemption_id}",
    response_model=ExemptionResponse,
    summary="Get exemption details",
)
async def get_exemption(
    exemption_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    exemption = await svc.get_exemption(db, exemption_id)
    if exemption is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exemption not found")
    return exemption

@exemption_router.patch(
    "/{exemption_id}",
    response_model=ExemptionResponse,
    summary="Update exemption",
)
async def update_exemption(
    exemption_id: uuid.UUID,
    body: ExemptionUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    kwargs = body.model_dump(exclude_unset=True)
    exemption = await svc.update_exemption(
        db,
        exemption_id,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
        **kwargs,
    )
    if exemption is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exemption not found")
    return exemption

@exemption_router.delete(
    "/{exemption_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete exemption",
)
async def delete_exemption(
    exemption_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    deleted = await svc.delete_exemption(
        db,
        exemption_id,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
    )
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exemption not found")

# ═══════════════════════════════════════════════════════════════════════════════
#  P3: Tag-Based Alert Routing
# ═══════════════════════════════════════════════════════════════════════════════

routing_router = APIRouter(
    prefix="/api/v1/policies/routing",
    tags=["routing"],
    dependencies=[Depends(rate_limit), Depends(require_permission("agent_policy.manage"))],
)

@routing_router.post(
    "",
    response_model=RoutingRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create routing rule",
)
async def create_routing_rule(
    body: RoutingRuleCreate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    rule = await svc.create_routing_rule(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        name=body.name,
        description=body.description,
        match_tags=body.match_tags,
        severity_min=body.severity_min,
        channels=body.channels,
        priority=body.priority,
    )
    return rule

@routing_router.get(
    "",
    response_model=list[RoutingRuleResponse],
    summary="List routing rules",
)
async def list_routing_rules(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    enabled_only: bool = True,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    return await svc.list_routing_rules(
        db,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset,
    )

@routing_router.get(
    "/{rule_id}",
    response_model=RoutingRuleResponse,
    summary="Get routing rule",
)
async def get_routing_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    rule = await svc.get_routing_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Routing rule not found")
    return rule

@routing_router.put(
    "/{rule_id}",
    response_model=RoutingRuleResponse,
    summary="Update routing rule",
)
async def update_routing_rule(
    rule_id: uuid.UUID,
    body: RoutingRuleUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    kwargs = body.model_dump(exclude_unset=True)
    rule = await svc.update_routing_rule(
        db,
        rule_id,
        user_id=current_user.user_id,
        **kwargs,
    )
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Routing rule not found")
    return rule

@routing_router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete routing rule",
)
async def delete_routing_rule(
    rule_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    deleted = await svc.delete_routing_rule(
        db,
        rule_id,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
    )
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Routing rule not found")

@routing_router.post(
    "/simulate",
    response_model=RoutingSimulationResult,
    summary="Simulate alert routing",
)
async def simulate_routing(
    body: RoutingSimulationRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Dry-run routing logic to preview which channels an alert would reach."""
    rules = await svc.list_routing_rules(db, enabled_only=True, limit=500)
    channels = svc.evaluate_tag_routing(body.agent_tags, body.severity, rules)

    # Check exemption (dry_run=True — simulation should NOT mutate state)
    exempted = False
    exemption_reason = None
    if body.rule_name:
        ex = await svc.check_exemption(db, body.rule_name, body.agent_tags, dry_run=True)
        if ex:
            exempted = True
            exemption_reason = ex.reason

    # Filter matched_rules for response
    matched = [r for r in rules if svc.tags_match(body.agent_tags, r.match_tags or {})]

    return RoutingSimulationResult(
        matched_rules=matched,
        channels=channels,
        would_be_exempted=exempted,
        exemption_reason=exemption_reason,
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  P4: Maintenance Windows
# ═══════════════════════════════════════════════════════════════════════════════

window_router = APIRouter(
    prefix="/api/v1/policies/maintenance-windows",
    tags=["maintenance-windows"],
    dependencies=[Depends(rate_limit), Depends(require_permission("agent_policy.manage"))],
)

@window_router.post(
    "",
    response_model=MaintenanceWindowResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create maintenance window",
)
async def create_maintenance_window(
    body: MaintenanceWindowCreate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    window = await svc.create_maintenance_window(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        name=body.name,
        description=body.description,
        cron_schedule=body.cron_schedule,
        duration_minutes=body.duration_minutes,
        rules=body.rules,
        match_tags=body.match_tags,
    )
    return window

@window_router.get(
    "",
    response_model=list[MaintenanceWindowResponse],
    summary="List maintenance windows",
)
async def list_maintenance_windows(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    enabled_only: bool = True,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    return await svc.list_maintenance_windows(
        db,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset,
    )

@window_router.get(
    "/{window_id}",
    response_model=MaintenanceWindowResponse,
    summary="Get maintenance window",
)
async def get_maintenance_window(
    window_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    window = await svc.get_maintenance_window(db, window_id)
    if window is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found")
    return window

@window_router.put(
    "/{window_id}",
    response_model=MaintenanceWindowResponse,
    summary="Update maintenance window",
)
async def update_maintenance_window(
    window_id: uuid.UUID,
    body: MaintenanceWindowUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    kwargs = body.model_dump(exclude_unset=True)
    window = await svc.update_maintenance_window(
        db,
        window_id,
        user_id=current_user.user_id,
        **kwargs,
    )
    if window is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found")
    return window

@window_router.delete(
    "/{window_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete maintenance window",
)
async def delete_maintenance_window(
    window_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    deleted = await svc.delete_maintenance_window(
        db,
        window_id,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
    )
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found")

@window_router.post(
    "/{window_id}/force-end",
    response_model=MaintenanceWindowResponse,
    summary="Emergency override — force end maintenance window",
    dependencies=[Depends(require_permission("agent_policy.manage"))],
)
async def force_end_maintenance_window(
    window_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    window = await svc.force_end_maintenance_window(
        db,
        window_id,
        user_id=current_user.user_id,
        tenant_id=current_user.tenant_id,
    )
    if window is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found")
    return window
