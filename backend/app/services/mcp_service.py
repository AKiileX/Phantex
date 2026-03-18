# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — MCP Supply Chain Service

Business logic for MCP server inventory, package scanning, anomaly
tracking, and composite risk scoring.  All DB ops use RLS via
``app.current_tenant`` set by the session factory.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mcp import MCPAnomaly, MCPScanResult, MCPServer
from app.utils.logging import get_logger

# ML modules — imported lazily to avoid circular imports at module level
from ml.content.policy.package_scanner import PackageReputationScanner
from ml.content.policy.risk_scorer import MCPRiskScorer

logger = get_logger("phantex.services.mcp")

# Singletons (thread-safe by design)
_package_scanner = PackageReputationScanner()
_risk_scorer = MCPRiskScorer()

# ── List servers ─────────────────────────────────────────────────────────

async def list_servers(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    trust_level: str | None = None,
    risk_level: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[MCPServer], int]:
    """List MCP servers for tenant with optional filters."""
    limit = min(limit, 500)  # defense-in-depth clamp
    offset = max(offset, 0)
    q = select(MCPServer).where(MCPServer.tenant_id == tenant_id)

    if trust_level:
        q = q.where(MCPServer.trust_level == trust_level)
    if risk_level:
        q = q.where(MCPServer.risk_level == risk_level)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    q = q.order_by(MCPServer.risk_score.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return list(rows), total

# ── Get single server ───────────────────────────────────────────────────

async def get_server(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str,
) -> MCPServer | None:
    """Get a single MCP server by tenant + server_id."""
    q = select(MCPServer).where(
        MCPServer.tenant_id == tenant_id,
        MCPServer.server_id == server_id,
    )
    return (await db.execute(q)).scalar_one_or_none()

# ── Block / Unblock ─────────────────────────────────────────────────────

async def block_server(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str,
    reason: str,
) -> MCPServer | None:
    """Block an MCP server."""
    srv = await get_server(db, tenant_id, server_id)
    if not srv:
        return None

    srv.trust_level = "blocked"
    srv.blocked_at = datetime.now(UTC)
    srv.blocked_reason = reason
    srv.updated_at = datetime.now(UTC)
    await db.flush()
    logger.info("mcp_server_blocked", server_id=server_id, reason=reason)
    return srv

async def unblock_server(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str,
) -> MCPServer | None:
    """Unblock an MCP server — resets to 'unknown'."""
    srv = await get_server(db, tenant_id, server_id)
    if not srv:
        return None

    srv.trust_level = "unknown"
    srv.blocked_at = None
    srv.blocked_reason = None
    srv.updated_at = datetime.now(UTC)
    await db.flush()
    logger.info("mcp_server_unblocked", server_id=server_id)
    return srv

# ── Package scan ─────────────────────────────────────────────────────────

async def run_package_scan(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str,
    ecosystem: str,
    packages: list[str],
) -> MCPScanResult:
    """Run a package reputation scan and persist results."""
    # Build name → version dict (version unknown from list input)
    pkg_dict = {p: "*" for p in packages}

    if ecosystem == "npm":
        result = _package_scanner.scan_npm(server_id, str(tenant_id), pkg_dict)
    else:
        result = _package_scanner.scan_pypi(server_id, str(tenant_id), pkg_dict)

    # Serialize findings
    findings: list[dict] = []
    for v in result.vulnerabilities:
        findings.append(
            {
                "type": "vulnerability",
                "package": v.package,
                "severity": v.severity.value,
                "description": v.title,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
            }
        )
    for t in result.typosquat_suspects:
        findings.append(
            {
                "type": "typosquat",
                "package": t.suspect_package,
                "target": t.target_package,
                "distance": t.edit_distance,
                "confidence": round(t.confidence, 3),
            }
        )

    # Compute clean = total - vulns - typosquats - malicious
    malicious_count = sum(1 for v in result.vulnerabilities if v.severity.value == "critical")
    clean_count = max(
        0,
        result.total_packages - len(result.vulnerabilities) - len(result.typosquat_suspects),
    )
    # Average reputation from package_reputations (0–100 scale → 0.0–1.0)
    if result.package_reputations:
        avg_rep = sum(p.reputation_score for p in result.package_reputations) / len(result.package_reputations) / 100.0
    else:
        avg_rep = 1.0

    scan = MCPScanResult(
        tenant_id=tenant_id,
        server_id=server_id,
        scan_type="package",
        ecosystem=ecosystem,
        total_packages=result.total_packages,
        clean_packages=clean_count,
        vulnerable=len(result.vulnerabilities),
        malicious=malicious_count,
        typosquat=len(result.typosquat_suspects),
        reputation_avg=round(avg_rep, 3),
        findings=findings,
    )
    db.add(scan)
    await db.flush()

    logger.info(
        "mcp_package_scan_complete",
        server_id=server_id,
        ecosystem=ecosystem,
        total=result.total_packages,
        clean=clean_count,
    )
    return scan

# ── List scans ───────────────────────────────────────────────────────────

async def list_scans(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[MCPScanResult], int]:
    """List scan results."""
    limit = min(limit, 200)  # defense-in-depth clamp
    offset = max(offset, 0)
    q = select(MCPScanResult).where(MCPScanResult.tenant_id == tenant_id)
    if server_id:
        q = q.where(MCPScanResult.server_id == server_id)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    q = q.order_by(MCPScanResult.scanned_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return list(rows), total

# ── Anomalies ────────────────────────────────────────────────────────────

async def list_anomalies(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[MCPAnomaly], int]:
    """List anomalies."""
    limit = min(limit, 200)  # defense-in-depth clamp
    offset = max(offset, 0)
    q = select(MCPAnomaly).where(MCPAnomaly.tenant_id == tenant_id)
    if server_id:
        q = q.where(MCPAnomaly.server_id == server_id)
    if severity:
        q = q.where(MCPAnomaly.severity == severity)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    q = q.order_by(MCPAnomaly.detected_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return list(rows), total

# ── Risk assessment ──────────────────────────────────────────────────────

async def assess_risk(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    server_id: str,
) -> dict[str, Any]:
    """Compute full risk assessment for an MCP server."""
    srv = await get_server(db, tenant_id, server_id)
    if not srv:
        return None

    # Count anomalies by type
    anomaly_q = select(MCPAnomaly.anomaly_type).where(
        MCPAnomaly.tenant_id == tenant_id,
        MCPAnomaly.server_id == server_id,
    )
    anomaly_rows = (await db.execute(anomaly_q)).scalars().all()
    anomaly_types = list(anomaly_rows)

    # Get latest scan
    scan_q = (
        select(MCPScanResult)
        .where(
            MCPScanResult.tenant_id == tenant_id,
            MCPScanResult.server_id == server_id,
        )
        .order_by(MCPScanResult.scanned_at.desc())
        .limit(1)
    )
    latest_scan = (await db.execute(scan_q)).scalar_one_or_none()

    assessment = _risk_scorer.assess(
        server_id=server_id,
        tenant_id=str(tenant_id),
        trust_level=srv.trust_level,
        anomaly_count=srv.anomaly_count,
        anomaly_types=anomaly_types,
        calls_total=srv.connection_count,
        error_rate=srv.error_rate,
        package_vulns=latest_scan.vulnerable if latest_scan else 0,
        typosquat_matches=latest_scan.typosquat if latest_scan else 0,
        malicious_packages=latest_scan.malicious if latest_scan else 0,
        package_reputation=latest_scan.reputation_avg if latest_scan else 1.0,
    )

    # Persist score back to server
    srv.risk_score = assessment.score
    srv.risk_level = assessment.level.value
    srv.updated_at = datetime.now(UTC)

    # Auto-block if threshold exceeded
    if assessment.auto_blocked and srv.trust_level != "blocked":
        srv.trust_level = "blocked"
        srv.blocked_at = datetime.now(UTC)
        srv.blocked_reason = f"Auto-blocked: risk score {assessment.score:.0f}"
        logger.warning("mcp_auto_block", server_id=server_id, score=assessment.score)

    await db.flush()
    return assessment.to_dict()

# ── Stats ────────────────────────────────────────────────────────────────

async def get_stats(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict[str, Any]:
    """Aggregate supply chain stats for dashboard."""
    base = select(MCPServer).where(MCPServer.tenant_id == tenant_id)

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

    # By trust level
    tl_q = (
        select(MCPServer.trust_level, func.count())
        .where(MCPServer.tenant_id == tenant_id)
        .group_by(MCPServer.trust_level)
    )
    by_trust = {row[0]: row[1] for row in (await db.execute(tl_q)).all()}

    # By risk level
    rl_q = (
        select(MCPServer.risk_level, func.count())
        .where(MCPServer.tenant_id == tenant_id)
        .group_by(MCPServer.risk_level)
    )
    by_risk = {row[0]: row[1] for row in (await db.execute(rl_q)).all()}

    # Anomaly counts
    total_anomalies = (await db.execute(select(func.count()).where(MCPAnomaly.tenant_id == tenant_id))).scalar() or 0
    critical_anomalies = (
        await db.execute(
            select(func.count()).where(
                MCPAnomaly.tenant_id == tenant_id,
                MCPAnomaly.severity == "critical",
            )
        )
    ).scalar() or 0

    # Scan count
    total_scans = (await db.execute(select(func.count()).where(MCPScanResult.tenant_id == tenant_id))).scalar() or 0

    # Avg risk score
    avg_risk = (
        await db.execute(select(func.avg(MCPServer.risk_score)).where(MCPServer.tenant_id == tenant_id))
    ).scalar() or 0.0

    return {
        "total_servers": total,
        "by_trust_level": by_trust,
        "by_risk_level": by_risk,
        "total_anomalies": total_anomalies,
        "critical_anomalies": critical_anomalies,
        "total_scans": total_scans,
        "servers_blocked": by_trust.get("blocked", 0),
        "avg_risk_score": round(float(avg_risk), 1),
    }
