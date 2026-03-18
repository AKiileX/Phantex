# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Events Router.

GET /api/v1/events       — List events (paginated, filterable)
GET /api/v1/events/{id}  — Get event details
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.schemas.common import CursorPage
from app.schemas.event import EventFilter, EventResponse, EventSummary
from app.services import event_service
from app.utils.validators import validate_agent_id

router = APIRouter(prefix="/api/v1/events", tags=["events"], dependencies=[Depends(rate_limit)])

@router.get(
    "",
    response_model=CursorPage[EventSummary],
    summary="List events",
)
async def list_events(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    agent_id: str | None = Query(None, max_length=128),
    event_type: str | None = None,
    severity: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    agent_only: bool = True,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=100),
):
    """
    List security events for the current tenant.
    Supports filtering by agent, type, severity, and time range.
    Set agent_only=false to include raw sensor events without an agent.
    """
    if agent_id:
        validate_agent_id(agent_id)
    filters = EventFilter(
        agent_id=agent_id,
        event_type=event_type,
        severity=severity,
        since=since,
        until=until,
        agent_only=agent_only,
    )
    page = await event_service.list_events(db, filters, cursor=cursor, limit=limit)

    return CursorPage(
        items=[EventSummary.model_validate(e) for e in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )

@router.get(
    "/{event_id}",
    response_model=EventResponse,
    summary="Get event details",
)
async def get_event(
    event_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get full details of a specific event including raw data."""
    event = await event_service.get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
