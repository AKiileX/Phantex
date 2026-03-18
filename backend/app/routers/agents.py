# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agents Router.

GET   /api/v1/agents         — List agents (paginated, filterable)
GET   /api/v1/agents/{id}    — Get agent details
PATCH /api/v1/agents/{id}    — Update agent name/status
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.agent import AgentFilter, AgentResponse, AgentSummary, AgentUpdate
from app.schemas.auth import CurrentUser
from app.schemas.common import CursorPage
from app.services import agent_service

router = APIRouter(prefix="/api/v1/agents", tags=["agents"], dependencies=[Depends(rate_limit)])

@router.get(
    "",
    response_model=CursorPage[AgentSummary],
    summary="List agents",
)
async def list_agents(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    status_filter: str | None = Query(None, alias="status"),
    framework: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=100),
):
    """List agents for the current tenant with optional filters."""
    filters = AgentFilter(status=status_filter, framework=framework, search=search)
    page = await agent_service.list_agents(db, filters, cursor=cursor, limit=limit)

    return CursorPage(
        items=[AgentSummary.model_validate(a) for a in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )

@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    summary="Get agent details",
)
async def get_agent(
    agent_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get full details of a specific agent."""
    agent = await agent_service.get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent

@router.patch(
    "/{agent_id}",
    response_model=AgentResponse,
    summary="Update agent",
    dependencies=[Depends(require_permission("agents.write"))],
)
async def update_agent(
    agent_id: uuid.UUID,
    body: AgentUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Update agent name or status. Requires admin or analyst role."""
    agent = await agent_service.update_agent(db, agent_id, body)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent
