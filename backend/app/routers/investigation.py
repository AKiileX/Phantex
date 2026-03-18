# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Investigation Router (I3).

Graph-backed investigation endpoints for threat analysis.
All endpoints require authentication and tenant_id from the
current user's context.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.neo4j_client import get_neo4j
from app.services import graph_service
from app.utils.logging import get_logger
from app.utils.validators import validate_agent_id

logger = get_logger("phantex.router.investigation")

router = APIRouter(
    prefix="/api/v1/investigate",
    tags=["investigation"],
    dependencies=[Depends(rate_limit)],
)

# ── Dependencies ─────────────────────────────────────────────────────────────

async def _require_neo4j():
    """Fail fast if Neo4j is not available."""
    driver = await get_neo4j()
    if driver is None:
        raise HTTPException(
            status_code=503,
            detail="Graph database unavailable",
        )
    return driver

# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/agent-graph")
async def get_agent_graph(
    agent_id: Annotated[str, Query(max_length=128, description="Agent to visualize")],
    depth: Annotated[int, Query(ge=1, le=3, description="Hop depth")] = 2,
    user=Depends(get_current_active_user),
    neo4j_driver=Depends(_require_neo4j),
):
    """Return the N-hop neighborhood graph for an agent.

    Returns nodes and edges ready for graph visualization.
    """
    validate_agent_id(agent_id)
    tenant_id = user.tenant_id

    return await graph_service.agent_graph(
        neo4j_driver,
        uuid.UUID(str(tenant_id)),
        agent_id=agent_id,
        depth=depth,
    )

@router.get("/blast-radius")
async def get_blast_radius(
    alert_id: Annotated[uuid.UUID, Query(description="Alert to analyze")],
    user=Depends(get_current_active_user),
    neo4j_driver=Depends(_require_neo4j),
):
    """Return all agents and resources affected by an alert's attack chain."""
    tenant_id = user.tenant_id

    return await graph_service.alert_blast_radius(
        neo4j_driver,
        uuid.UUID(str(tenant_id)),
        alert_id=alert_id,
    )

@router.get("/shortest-path")
async def get_shortest_path(
    from_agent_id: Annotated[str, Query(max_length=128, description="Source agent")],
    to_ip: Annotated[str, Query(max_length=45, description="Destination IP")],
    user=Depends(get_current_active_user),
    neo4j_driver=Depends(_require_neo4j),
):
    """Shortest investigation path between an agent and a network destination."""
    validate_agent_id(from_agent_id)
    tenant_id = user.tenant_id

    return await graph_service.shortest_path(
        neo4j_driver,
        uuid.UUID(str(tenant_id)),
        from_agent_id=from_agent_id,
        to_ip=to_ip,
    )

@router.get("/lateral-movement")
async def get_lateral_movement(
    hours: Annotated[int, Query(ge=1, le=168, description="Lookback hours")] = 24,
    limit: Annotated[int, Query(ge=1, le=100, description="Max results")] = 20,
    user=Depends(get_current_active_user),
    neo4j_driver=Depends(_require_neo4j),
):
    """Cross-agent connection patterns suggesting lateral movement."""
    tenant_id = user.tenant_id

    return await graph_service.lateral_movement(
        neo4j_driver,
        uuid.UUID(str(tenant_id)),
        hours=hours,
        limit=limit,
    )
