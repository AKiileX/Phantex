# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Analytics Router (I2).

ClickHouse-powered analytics endpoints for event volume, top agents,
attack breakdown, network destinations, and tool usage.

All queries are tenant-scoped via the authenticated user's tenant_id.
Returns 503 if ClickHouse is not configured/available.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.clickhouse import get_clickhouse
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.services import analytics_service
from app.services.analytics_service import ValidInterval, ValidRange
from app.utils.validators import validate_agent_id

router = APIRouter(
    prefix="/api/v1/analytics",
    tags=["analytics"],
    dependencies=[Depends(rate_limit)],
)

async def _require_clickhouse():
    """Dependency that ensures ClickHouse is available."""
    ch = await get_clickhouse()
    if ch is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analytics service (ClickHouse) is not configured",
        )
    return ch

@router.get(
    "/event-volume",
    summary="Event volume time-series",
    response_model=list[dict[str, Any]],
)
async def get_event_volume(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_clickhouse),
    interval: ValidInterval = Query("1h", description="Bucket interval"),
    range: ValidRange = Query("7d", alias="range", description="Time range"),
    agent_id: str | None = Query(None, max_length=128, description="Filter by agent"),
    event_type: str | None = Query(None, max_length=100, description="Filter by event type"),
):
    """Time-series event counts grouped by interval and event_type."""
    if agent_id:
        validate_agent_id(agent_id)
    return await analytics_service.event_volume(
        ch,
        current_user.tenant_id,
        interval=interval,
        range_str=range,
        agent_id=agent_id,
        event_type=event_type,
    )

@router.get(
    "/top-agents",
    summary="Top agents by event volume",
    response_model=list[dict[str, Any]],
)
async def get_top_agents(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_clickhouse),
    range: ValidRange = Query("24h", alias="range", description="Time range"),
    limit: int = Query(10, ge=1, le=100, description="Number of agents"),
):
    """Agents ranked by event volume in the given range."""
    return await analytics_service.top_agents(
        ch,
        current_user.tenant_id,
        range_str=range,
        limit=limit,
    )

@router.get(
    "/attack-breakdown",
    summary="Alert counts by attack class",
    response_model=list[dict[str, Any]],
)
async def get_attack_breakdown(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_clickhouse),
    range: ValidRange = Query("30d", alias="range", description="Time range"),
):
    """Alert counts grouped by attack class and severity."""
    return await analytics_service.attack_breakdown(
        ch,
        current_user.tenant_id,
        range_str=range,
    )

@router.get(
    "/network-destinations",
    summary="Network destinations for an agent",
    response_model=list[dict[str, Any]],
)
async def get_network_destinations(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_clickhouse),
    agent_id: str = Query(..., max_length=128, description="Agent ID"),
    range: ValidRange = Query("7d", alias="range", description="Time range"),
    limit: int = Query(50, ge=1, le=200, description="Max destinations"),
):
    """Unique network destinations with byte totals for an agent."""
    validate_agent_id(agent_id)
    return await analytics_service.network_destinations(
        ch,
        current_user.tenant_id,
        agent_id=agent_id,
        range_str=range,
        limit=limit,
    )

@router.get(
    "/tool-usage",
    summary="Tool call frequency for an agent",
    response_model=list[dict[str, Any]],
)
async def get_tool_usage(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_clickhouse),
    agent_id: str = Query(..., max_length=128, description="Agent ID"),
    range: ValidRange = Query("7d", alias="range", description="Time range"),
    limit: int = Query(50, ge=1, le=200, description="Max tools"),
):
    """Tool call frequency and duration stats for an agent."""
    validate_agent_id(agent_id)
    return await analytics_service.tool_usage(
        ch,
        current_user.tenant_id,
        agent_id=agent_id,
        range_str=range,
        limit=limit,
    )
