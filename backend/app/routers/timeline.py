# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Timeline & MITRE ATLAS Router (L1 + L2).

Investigation timeline endpoints (multi-source forensic event assembly)
and MITRE ATLAS coverage/mapping endpoints.

Rate limited: timeline queries fan out to PG + ClickHouse + Neo4j + Trust
Engine — expensive. Capped at 30 requests/min per user.
"""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.clickhouse import get_clickhouse
from app.database import get_tenant_session
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.neo4j_client import get_neo4j
from app.schemas.auth import CurrentUser
from app.utils.validators import validate_agent_id
from app.schemas.timeline import (
    AtlasCoverageResponse,
    AtlasRuleMappingResponse,
    TimelineResponse,
)
from app.services import mitre_service, timeline_service
from app.utils.logging import get_logger

logger = get_logger("phantex.router.timeline")

# ── Timeline Router ───────────────────────────────────────────────────────────

timeline_router = APIRouter(
    prefix="/api/v1/timeline",
    tags=["timeline"],
    dependencies=[Depends(rate_limit)],
)

ValidRange = Literal["1h", "6h", "12h", "24h", "48h", "72h"]

async def _get_trust_client():
    """Best-effort trust client acquisition.

    ``get_trust_client()`` is synchronous (returns an already-created
    TrustClient instance) — do NOT await it.  Previous code did
    ``await get_trust_client()`` which raised TypeError (non-awaitable)
    and was silently swallowed, leaving trust enrichment permanently
    disabled.
    """
    try:
        from app.services.trust_client import get_trust_client

        return get_trust_client()  # sync — do NOT await
    except Exception:
        return None

@timeline_router.get(
    "/agent/{agent_id}",
    response_model=TimelineResponse,
    summary="Agent investigation timeline",
)
async def get_agent_timeline(
    agent_id: Annotated[str, Path(max_length=128)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    range: ValidRange = Query("24h", description="Time range (max 72h)"),
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    cursor: Annotated[str | None, Query(max_length=64, description="Pagination cursor (ISO timestamp)")] = None,
):
    """Assemble a forensic event timeline for an agent.

    Queries PostgreSQL (alerts), ClickHouse (raw events), Neo4j
    (relationship context), and the Rust trust engine (trust scores).

    Partial results returned if any data source is unavailable — check
    ``data_sources`` in the response for availability status.
    """
    validate_agent_id(agent_id)
    tenant_id = current_user.tenant_id

    # Acquire data source connections (best-effort)
    ch_client = await get_clickhouse()
    neo4j_driver = await get_neo4j()
    trust_client = await _get_trust_client()

    async with get_tenant_session(str(tenant_id)) as session:
        return await timeline_service.get_agent_timeline(
            uuid.UUID(str(tenant_id)),
            agent_id,
            range_str=range,
            limit=limit,
            cursor=cursor,
            ch_client=ch_client,
            pg_session=session,
            neo4j_driver=neo4j_driver,
            trust_client=trust_client,
        )

@timeline_router.get(
    "/alert/{alert_id}",
    response_model=TimelineResponse,
    summary="Alert investigation timeline",
)
async def get_alert_timeline(
    alert_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
):
    """Assemble a forensic timeline for an alert.

    Returns events in a ±5 minute window around the alert timestamp,
    enriched with MITRE ATLAS techniques and trust scores.
    """
    tenant_id = current_user.tenant_id

    ch_client = await get_clickhouse()
    neo4j_driver = await get_neo4j()
    trust_client = await _get_trust_client()

    async with get_tenant_session(str(tenant_id)) as session:
        result = await timeline_service.get_alert_timeline(
            uuid.UUID(str(tenant_id)),
            alert_id,
            limit=limit,
            ch_client=ch_client,
            pg_session=session,
            neo4j_driver=neo4j_driver,
            trust_client=trust_client,
        )

    if result.total_events == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found or no timeline data available",
        )

    return result

# ── ATLAS Router ──────────────────────────────────────────────────────────────

atlas_router = APIRouter(
    prefix="/api/v1/atlas",
    tags=["mitre-atlas"],
    dependencies=[Depends(rate_limit)],
)

@atlas_router.get(
    "/coverage",
    response_model=AtlasCoverageResponse,
    summary="MITRE ATLAS coverage matrix",
)
async def get_atlas_coverage(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return ATLAS technique coverage matrix showing which techniques
    Phantex can detect and which detection mechanisms cover each one."""
    return mitre_service.coverage_report()

@atlas_router.get(
    "/technique/{technique_id}",
    summary="ATLAS technique details",
)
async def get_technique_detail(
    technique_id: Annotated[str, Path(max_length=20)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return full details for a single ATLAS technique."""
    # Validate technique ID format: AML.TXXXX or AML.TXXXX.XXX (subtechnique)
    technique_id = technique_id.strip()
    _ATLAS_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{1,3})?$")
    if not _ATLAS_ID_RE.match(technique_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid ATLAS technique ID format (expected AML.TXXXX or AML.TXXXX.XXX)",
        )

    info = mitre_service.get_technique(technique_id)
    if info is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found in ATLAS mapping",
        )

    # Enrich with detected_by from coverage data so the frontend can
    # render detectors without a separate coverage call.
    coverage = mitre_service.coverage_report()
    detected_by: list[dict] = []
    best_confidence = "none"
    for t in coverage.get("techniques", []):
        if t["id"] == technique_id:
            detected_by = t.get("detected_by", [])
            best_confidence = t.get("best_confidence", "none")
            break

    return {
        "id": technique_id,
        **info,
        "detected": len(detected_by) > 0,
        "detected_by": detected_by,
        "best_confidence": best_confidence,
    }

@atlas_router.get(
    "/rule/{rule_name}",
    response_model=AtlasRuleMappingResponse,
    summary="ATLAS mapping for a rule",
)
async def get_rule_atlas_mapping(
    rule_name: Annotated[str, Path(max_length=128)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return ATLAS technique mapping for a specific PRL rule."""
    mapping = mitre_service.rule_mapping_detail(rule_name)
    if mapping is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ATLAS mapping found for rule '{rule_name}'",
        )

    # Resolve technique details
    techniques_data = mitre_service.get_all_techniques()
    enriched_techniques = []
    for tid in mapping.get("atlas_techniques", []):
        info = techniques_data.get(tid, {})
        enriched_techniques.append(
            {
                "id": tid,
                "name": info.get("name", tid),
                "url": info.get("url", ""),
            }
        )

    return AtlasRuleMappingResponse(
        rule_name=rule_name,
        atlas_techniques=enriched_techniques,
        confidence=mapping.get("confidence", "none"),
        rationale=mapping.get("rationale", ""),
    )

# ── Combined router for main.py import ───────────────────────────────────────

router = APIRouter()
router.include_router(timeline_router)
router.include_router(atlas_router)
