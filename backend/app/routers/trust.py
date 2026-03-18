# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Trust Graph Router.

REST endpoints wrapping the gRPC TrustClient for dashboard consumption.

Routes:
  GET  /api/v1/trust/graph           — full tenant trust graph (capped 2000 nodes)
  GET  /api/v1/trust/score/{id}      — single entity trust score + factor breakdown
  GET  /api/v1/trust/health          — trust engine health

Security:
  - All endpoints require authentication (get_current_active_user)
  - Graph/score endpoints enforce tenant isolation via CurrentUser.tenant_id
  - Node cap (MAX_GRAPH_NODES) prevents browser OOM / server fan-out DoS
  - Entity ID validated as UUID (path-traversal defence)
  - Rate-limited: 30 req/min per user
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.trust import (
    TrustFactorResponse,
    TrustGraphEdgeResponse,
    TrustGraphNodeResponse,
    TrustGraphResponse,
    TrustHealthResponse,
    TrustScoreResponse,
)
from app.services.trust_client import get_trust_client

router = APIRouter(
    prefix="/api/v1/trust",
    tags=["trust"],
    dependencies=[Depends(rate_limit)],
)

# Maximum nodes returned in a graph query (prevent browser OOM).
MAX_GRAPH_NODES = 2_000

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

def _validate_uuid(value: str, label: str = "id") -> str:
    """Validate and return a UUID string.  Raises 422 on bad input."""
    if not _UUID_RE.match(value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid {label}: expected UUID format.",
        )
    return value

# ── GET /graph — full tenant trust graph ─────────────────────────────────────

@router.get(
    "/graph",
    response_model=TrustGraphResponse,
    summary="Tenant trust graph",
    description="Returns the force-directed graph for the current tenant's agents "
    "and their tool/resource connections. Capped at 2 000 nodes.",
)
async def get_trust_graph(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    depth: int = Query(2, ge=1, le=5, description="Neighbourhood traversal depth"),
    entity_id: str | None = Query(
        None,
        description="Optional: centre the graph on this entity (UUID). If omitted, returns full-tenant overview.",
    ),
):
    """Return the trust graph neighbourhood for the tenant, optionally centred
    on a specific entity."""
    tenant_id = str(current_user.tenant_id)

    client = get_trust_client()

    if entity_id:
        _validate_uuid(entity_id, "entity_id")
        neighbourhood = await client.get_trust_graph(
            tenant_id=tenant_id,
            entity_id=entity_id,
            entity_type="agent",
            depth=depth,
        )
    else:
        # Full-tenant graph: the Rust trust engine requires a concrete
        # entity_id — there is no "all-tenant" query.  Strategy: fetch
        # distinct agent_ids from PG and merge their neighbour graphs.
        from sqlalchemy import text

        from app.database import get_tenant_session
        from app.services.trust_client import TrustNeighbourhood

        agent_ids: list[str] = []
        async with get_tenant_session(tenant_id) as session:
            result = await session.execute(
                text("SELECT DISTINCT agent_id FROM events LIMIT 50"),
            )
            agent_ids = [str(row[0]) for row in result.fetchall()]

        if not agent_ids:
            neighbourhood = TrustNeighbourhood()
        else:
            # Query each agent's neighbourhood and merge (de-dup by id)

            seen_nodes: dict[str, object] = {}
            seen_edges: set[tuple[str, str, str]] = set()
            merged_edges: list[object] = []
            for aid in agent_ids:
                nb = await client.get_trust_graph(
                    tenant_id=tenant_id,
                    entity_id=aid,
                    entity_type="agent",
                    depth=depth,
                )
                for n in nb.nodes:
                    if n.id not in seen_nodes:
                        seen_nodes[n.id] = n
                for e in nb.edges:
                    key = (e.source_id, e.target_id, e.edge_type)
                    if key not in seen_edges:
                        seen_edges.add(key)
                        merged_edges.append(e)
            neighbourhood = TrustNeighbourhood(
                nodes=list(seen_nodes.values()),
                edges=merged_edges,
            )

    # Enforce node cap — return first MAX_GRAPH_NODES nodes + relevant edges.
    truncated = len(neighbourhood.nodes) > MAX_GRAPH_NODES
    capped_nodes = neighbourhood.nodes[:MAX_GRAPH_NODES]
    capped_ids = {n.id for n in capped_nodes}
    capped_edges = [e for e in neighbourhood.edges if e.source_id in capped_ids and e.target_id in capped_ids]

    return TrustGraphResponse(
        nodes=[
            TrustGraphNodeResponse(
                id=n.id,
                entity_type=n.entity_type,
                trust_score=max(0.0, min(1.0, n.trust_score)),
                metadata=n.metadata,
            )
            for n in capped_nodes
        ],
        edges=[
            TrustGraphEdgeResponse(
                source_id=e.source_id,
                target_id=e.target_id,
                edge_type=e.edge_type,
                count=e.count,
                weight=e.weight,
            )
            for e in capped_edges
        ],
        truncated=truncated,
    )

# ── Entity type allowlist ────────────────────────────────────────────────────

class EntityType(StrEnum):
    agent = "agent"
    tool = "tool"
    file = "file"
    network = "network"
    tenant = "tenant"

# ── GET /score/{entity_id} — single entity trust breakdown ──────────────────

@router.get(
    "/score/{entity_id}",
    response_model=TrustScoreResponse,
    summary="Entity trust score",
    description="Returns the trust score and factor breakdown for one entity.",
)
async def get_trust_score(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    entity_id: str = Path(..., description="Agent UUID"),
    entity_type: EntityType = Query(EntityType.agent, description="Entity type"),
):
    """Return the trust score + breakdown for the given entity."""
    _validate_uuid(entity_id, "entity_id")
    tenant_id = str(current_user.tenant_id)

    client = get_trust_client()
    try:
        result = await client.get_trust_score(
            tenant_id=tenant_id,
            entity_id=entity_id,
            entity_type=entity_type,
        )
    except Exception:
        # Trust engine unreachable — return graph-derived score with empty factors
        return TrustScoreResponse(
            entity_id=entity_id,
            entity_type=entity_type,
            trust_score=0.0,
            factors=[],
            last_updated=None,
        )

    return TrustScoreResponse(
        entity_id=result.entity_id or entity_id,
        entity_type=result.entity_type or entity_type,
        trust_score=max(0.0, min(1.0, result.trust_score)),
        factors=[
            TrustFactorResponse(
                name=f.name,
                weight=f.weight,
                value=f.value,
            )
            for f in result.factors
        ],
        last_updated=result.last_updated,
    )

# ── GET /health — engine health ──────────────────────────────────────────────

@router.get(
    "/health",
    response_model=TrustHealthResponse,
    summary="Trust engine health",
    dependencies=[Depends(require_permission("trust.compute"))],
)
async def get_trust_health(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return the trust engine health status (admin only)."""
    client = get_trust_client()
    h = await client.health_check()

    return TrustHealthResponse(
        status=h.status,
        total_nodes=h.total_nodes,
        total_edges=h.total_edges,
        tenants=h.tenants,
        uptime_secs=h.uptime_secs,
    )
