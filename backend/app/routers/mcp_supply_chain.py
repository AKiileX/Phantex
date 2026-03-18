# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — MCP Supply Chain Router

REST endpoints for MCP server inventory, package scanning,
anomaly tracking, risk assessment, and MCP-correlated alerts.

Routes:
  GET    /api/v1/mcp/servers              — list MCP servers
  GET    /api/v1/mcp/servers/{server_id}  — single server detail
  POST   /api/v1/mcp/servers/{server_id}/block    — block server
  POST   /api/v1/mcp/servers/{server_id}/unblock  — unblock server
  POST   /api/v1/mcp/servers/{server_id}/scan     — trigger package scan
  GET    /api/v1/mcp/servers/{server_id}/risk      — risk assessment
  GET    /api/v1/mcp/scans                — list scan results
  GET    /api/v1/mcp/anomalies            — list anomalies
  GET    /api/v1/mcp/stats                — supply chain dashboard stats
  GET    /api/v1/mcp/alerts               — MCP-correlated alerts

Security:
  - All endpoints require authentication
  - ABAC: mcp.read / mcp.write permissions
  - Rate limited: 30 req/min
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.models.alert import Alert
from app.schemas.auth import CurrentUser
from app.schemas.mcp import (
    MCPAnomalyListResponse,
    MCPAnomalyResponse,
    MCPRiskAssessmentResponse,
    MCPScanListResponse,
    MCPScanRequest,
    MCPScanResultResponse,
    MCPServerBlockRequest,
    MCPServerListResponse,
    MCPServerResponse,
    MCPSupplyChainStatsResponse,
)
from app.services import mcp_service

router = APIRouter(
    prefix="/api/v1/mcp",
    tags=["mcp-supply-chain"],
    dependencies=[Depends(rate_limit)],
)

# ── Helpers ──────────────────────────────────────────────────────────────

def _server_to_response(srv) -> MCPServerResponse:
    return MCPServerResponse(
        id=str(srv.id),
        server_id=srv.server_id,
        name=srv.name,
        trust_level=srv.trust_level,
        risk_score=srv.risk_score,
        risk_level=srv.risk_level,
        content_hash=srv.content_hash,
        protocol_version=srv.protocol_version,
        capabilities=srv.capabilities or [],
        metadata=srv.metadata_ or {},
        connection_count=srv.connection_count,
        anomaly_count=srv.anomaly_count,
        error_rate=srv.error_rate,
        last_seen=srv.last_seen.isoformat() if srv.last_seen else None,
        first_seen=srv.first_seen.isoformat() if srv.first_seen else None,
        blocked_at=srv.blocked_at.isoformat() if srv.blocked_at else None,
        blocked_reason=srv.blocked_reason,
    )

def _scan_to_response(scan) -> MCPScanResultResponse:
    return MCPScanResultResponse(
        id=str(scan.id),
        server_id=scan.server_id,
        scan_type=scan.scan_type,
        ecosystem=scan.ecosystem,
        total_packages=scan.total_packages,
        clean_packages=scan.clean_packages,
        vulnerable=scan.vulnerable,
        malicious=scan.malicious,
        typosquat=scan.typosquat,
        reputation_avg=scan.reputation_avg,
        findings=scan.findings or [],
        scanned_at=scan.scanned_at.isoformat() if scan.scanned_at else None,
    )

def _anomaly_to_response(a) -> MCPAnomalyResponse:
    return MCPAnomalyResponse(
        id=str(a.id),
        server_id=a.server_id,
        anomaly_type=a.anomaly_type,
        severity=a.severity,
        detail=a.detail,
        raw_evidence=a.raw_evidence,
        detected_at=a.detected_at.isoformat() if a.detected_at else None,
    )

# ── GET /servers ─────────────────────────────────────────────────────────

@router.get(
    "/servers",
    response_model=MCPServerListResponse,
    summary="List MCP servers",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def list_servers(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    trust_level: str | None = Query(None),
    risk_level: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    rows, total = await mcp_service.list_servers(db, current_user.tenant_id, trust_level, risk_level, limit, offset)
    return MCPServerListResponse(
        items=[_server_to_response(r) for r in rows],
        total=total,
    )

# ── GET /servers/{server_id} ────────────────────────────────────────────

@router.get(
    "/servers/{server_id}",
    response_model=MCPServerResponse,
    summary="Get MCP server detail",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def get_server(
    server_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    srv = await mcp_service.get_server(db, current_user.tenant_id, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return _server_to_response(srv)

# ── POST /servers/{server_id}/block ─────────────────────────────────────

@router.post(
    "/servers/{server_id}/block",
    response_model=MCPServerResponse,
    summary="Block an MCP server",
    dependencies=[Depends(require_permission("mcp.write"))],
)
async def block_server(
    server_id: str,
    body: MCPServerBlockRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    srv = await mcp_service.block_server(db, current_user.tenant_id, server_id, body.reason)
    if not srv:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return _server_to_response(srv)

# ── POST /servers/{server_id}/unblock ───────────────────────────────────

@router.post(
    "/servers/{server_id}/unblock",
    response_model=MCPServerResponse,
    summary="Unblock an MCP server",
    dependencies=[Depends(require_permission("mcp.write"))],
)
async def unblock_server(
    server_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    srv = await mcp_service.unblock_server(db, current_user.tenant_id, server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return _server_to_response(srv)

# ── POST /servers/{server_id}/scan ──────────────────────────────────────

@router.post(
    "/servers/{server_id}/scan",
    response_model=MCPScanResultResponse,
    summary="Run package scan on MCP server",
    dependencies=[Depends(require_permission("mcp.write"))],
)
async def scan_server(
    server_id: str,
    body: MCPScanRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    scan = await mcp_service.run_package_scan(db, current_user.tenant_id, server_id, body.ecosystem, body.packages)
    return _scan_to_response(scan)

# ── GET /servers/{server_id}/risk ───────────────────────────────────────

@router.get(
    "/servers/{server_id}/risk",
    response_model=MCPRiskAssessmentResponse,
    summary="Get risk assessment for MCP server",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def get_risk(
    server_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await mcp_service.assess_risk(db, current_user.tenant_id, server_id)
    if not result:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return result

# ── GET /scans ───────────────────────────────────────────────────────────

@router.get(
    "/scans",
    response_model=MCPScanListResponse,
    summary="List package scan results",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def list_scans(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    server_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows, total = await mcp_service.list_scans(db, current_user.tenant_id, server_id, limit, offset)
    return MCPScanListResponse(
        items=[_scan_to_response(r) for r in rows],
        total=total,
    )

# ── GET /anomalies ──────────────────────────────────────────────────────

@router.get(
    "/anomalies",
    response_model=MCPAnomalyListResponse,
    summary="List MCP anomalies",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def list_anomalies(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    server_id: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    rows, total = await mcp_service.list_anomalies(db, current_user.tenant_id, server_id, severity, limit, offset)
    return MCPAnomalyListResponse(
        items=[_anomaly_to_response(r) for r in rows],
        total=total,
    )

# ── GET /stats ───────────────────────────────────────────────────────────

@router.get(
    "/stats",
    response_model=MCPSupplyChainStatsResponse,
    summary="MCP supply chain dashboard stats",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def get_stats(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await mcp_service.get_stats(db, current_user.tenant_id)

# ── GET /alerts — MCP-correlated alerts ──────────────────────────────────

@router.get(
    "/alerts",
    summary="List MCP-correlated alerts",
    dependencies=[Depends(require_permission("mcp.read"))],
)
async def list_mcp_alerts(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = Query(None),
    alert_status: str | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Return alerts whose triggering event was an MCP tool call.

    Filters alerts by checking the context JSONB for:
    - context->'event_snapshot'->'raw_data'->>'tool_category' = 'mcp_tool'
    - OR context->'event_snapshot'->'raw_data'->>'tool_name' LIKE 'mcp_%'

    This ensures only genuinely MCP-related alerts are returned,
    rather than relying on trust graph presence as a proxy.
    """
    q = select(Alert).where(
        Alert.tenant_id == current_user.tenant_id,
        or_(
            Alert.context["event_snapshot"]["raw_data"]["tool_category"].as_string() == "mcp_tool",
            Alert.context["event_snapshot"]["raw_data"]["tool_name"].as_string().like("mcp_%"),
        ),
    )

    if severity:
        q = q.where(Alert.severity == severity)
    if alert_status:
        q = q.where(Alert.status == alert_status)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    q = q.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()

    items = []
    for a in rows:
        # Extract MCP server info from context for richer response
        ctx = a.context or {}
        snapshot = ctx.get("event_snapshot", {})
        raw = snapshot.get("raw_data", {})
        tool_name = raw.get("tool_name", "")
        tool_category = raw.get("tool_category", "")

        # Derive server_id from tool_name (match known prefixes, longest first)
        _known_prefixes = sorted(
            [
                "mcp_filesystem",
                "mcp_github",
                "mcp_slack",
                "mcp_browser",
                "mcp_memory",
                "mcp_code_exec",
            ],
            key=len,
            reverse=True,
        )
        mcp_server_id = tool_name
        if tool_name and tool_name.startswith("mcp_"):
            for prefix in _known_prefixes:
                if tool_name == prefix or tool_name.startswith(prefix + "_"):
                    mcp_server_id = prefix
                    break
            else:
                parts = tool_name.split("_")
                mcp_server_id = f"{parts[0]}_{parts[1]}" if len(parts) >= 3 else tool_name

        items.append(
            {
                "id": str(a.id),
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
                "updated_at": a.updated_at.isoformat(),
                "agent_id": str(a.agent_id) if a.agent_id else None,
                "event_id": str(a.event_id) if a.event_id else None,
                "rule_id": str(a.rule_id) if a.rule_id else None,
                "mcp_server_id": mcp_server_id,
                "tool_name": tool_name,
                "tool_category": tool_category,
            }
        )

    return {"items": items, "total": total}
