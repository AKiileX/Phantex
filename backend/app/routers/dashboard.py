# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Dashboard Router.

GET /api/v1/dashboard/stats — Aggregate stats for the current tenant
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.schemas.dashboard import DashboardStats
from app.services import agent_service, alert_service, event_service, rule_service

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"], dependencies=[Depends(rate_limit)])

@router.get(
    "/stats",
    response_model=DashboardStats,
    summary="Dashboard summary statistics",
)
async def get_stats(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Aggregate statistics for the current tenant.
    Used by the dashboard overview page.
    """
    total_agents, active_agents = await agent_service.count_agents(db)
    total_events = await event_service.count_events_simple(db)
    events_24h = await event_service.count_events_last_24h(db)
    total_alerts, open_alerts, critical_alerts = await alert_service.count_alerts(db)
    total_rules, enabled_rules = await rule_service.count_rules(db)

    return DashboardStats(
        total_agents=total_agents,
        active_agents=active_agents,
        total_events=total_events,
        events_last_24h=events_24h,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        total_rules=total_rules,
        enabled_rules=enabled_rules,
    )
