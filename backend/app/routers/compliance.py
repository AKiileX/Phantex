# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Compliance Router

Endpoints:
  POST /compliance/report          — Generate a new compliance report (JSON).
  POST /compliance/report/pdf      — Generate and download a PDF report.
  GET  /compliance/score            — Quick scorecard (no full evidence).
  GET  /compliance/history          — List saved reports (paginated).
  GET  /compliance/report/{id}      — Retrieve a stored report by ID.
  GET  /compliance/report/{id}/pdf  — Download stored report as PDF.
  GET  /compliance/scan/status      — Scheduled-scanner status.
  PUT  /compliance/scan/config      — Update scanner schedule.
  POST /compliance/scan/trigger     — Trigger an on-demand scan.

All endpoints require ``analytics.view`` permission (re-uses the
existing ABAC permission instead of adding a new permission row).
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.database import get_raw_db
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.schemas.auth import CurrentUser
from app.schemas.compliance import (
    ComplianceHistoryResponse,
    ComplianceReportFull,
    ComplianceReportMeta,
    ComplianceReportRequest,
    ComplianceScorecard,
    FrameworkScore,
    ScanScheduleUpdate,
    ScanStatusResponse,
)
from app.services.compliance.report_builder import (
    export_pdf,
    generate_compliance_report,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.routers.compliance")

router = APIRouter(
    prefix="/api/v1/compliance",
    tags=["compliance"],
    dependencies=[Depends(require_permission("analytics.view"))],
)

# ── Constants & Hardening ─────────────────────────────────────────────────────

_MAX_REPORT_SIZE = 10 * 1024 * 1024  # 10 MB cap on stored report JSONB
_SCORE_CACHE_TTL = 60  # seconds
_MAX_CACHE_ENTRIES = 200  # bound cache memory
_MAX_SCAN_LOCKS = 200  # bound lock dict memory
_CRON_RE = re.compile(
    r"^[\d*,/\-]+\s+[\d*,/\-]+\s+[\d*,/\-]+\s+[\d*,/\-]+\s+[\d*,/\-]+$"
)  # Basic 5-field cron validation

# Per-tenant scorecard cache: {tenant_id: (timestamp, scorecard_data)}
_score_cache: dict[str, tuple[float, dict]] = {}

# Per-tenant scan lock to prevent parallel scans (T-5)
_scan_locks: dict[str, asyncio.Lock] = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _default_period() -> tuple[str, str]:
    """Return (start, end) ISO strings for the last 30 days."""
    now = datetime.now(UTC)
    start = now - timedelta(days=30)
    return start.isoformat(), now.isoformat()

async def _store_report(
    db,
    tenant_id: str,
    user_id: str,
    report_data: dict[str, Any],
    frameworks: list[str],
) -> uuid.UUID:
    """Persist report JSON to the compliance_reports table. Returns the report id."""
    import json as _json

    report_id = uuid.uuid4()

    # Compute overall score as average across frameworks
    scores = [fw.get("overall_score", 0) for fw in report_data.get("frameworks", [])]
    overall_score = sum(scores) / max(len(scores), 1)

    # T-2: Enforce size limit on JSONB payload
    payload = _json.dumps(report_data, default=str)
    if len(payload) > _MAX_REPORT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Report data exceeds {_MAX_REPORT_SIZE // (1024 * 1024)} MB limit",
        )

    await db.execute(
        """
        INSERT INTO compliance_reports (id, tenant_id, frameworks, overall_score, report_data, created_by, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, now())
        """,
        report_id,
        uuid.UUID(tenant_id),
        frameworks,
        round(overall_score, 4),
        payload,
        uuid.UUID(user_id) if user_id else None,
    )
    return report_id

# ── POST /report — Generate JSON report ──────────────────────────────────────

@router.post(
    "/report",
    response_model=ComplianceReportFull,
    status_code=status.HTTP_200_OK,
    summary="Generate compliance report",
)
async def generate_report(
    body: ComplianceReportRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Generate a compliance report for specified frameworks and persist it."""
    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    period_start = body.period_start.isoformat() if body.period_start else _default_period()[0]
    period_end = body.period_end.isoformat() if body.period_end else _default_period()[1]

    data = await generate_compliance_report(
        db,
        tenant_id,
        body.frameworks,
        period_start,
        period_end,
    )

    report_id = await _store_report(db, tenant_id, str(user.user_id), data, body.frameworks)
    data["id"] = str(report_id)
    data["tenant_id"] = tenant_id

    logger.info(
        "compliance_report_generated",
        tenant=tenant_id,
        frameworks=body.frameworks,
        report_id=str(report_id),
    )
    return data

# ── POST /report/pdf — Generate PDF report ───────────────────────────────────

@router.post(
    "/report/pdf",
    status_code=status.HTTP_200_OK,
    summary="Generate compliance report as PDF",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def generate_report_pdf(
    body: ComplianceReportRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Generate a compliance report and return it as a downloadable PDF."""
    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    period_start = body.period_start.isoformat() if body.period_start else _default_period()[0]
    period_end = body.period_end.isoformat() if body.period_end else _default_period()[1]

    data = await generate_compliance_report(
        db,
        tenant_id,
        body.frameworks,
        period_start,
        period_end,
    )

    pdf_bytes = export_pdf(data, title="Phantex Compliance Report")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="phantex-compliance-{datetime.now(UTC):%Y%m%d}.pdf"',
        },
    )

# ── GET /score — Quick scorecard ─────────────────────────────────────────────

@router.get(
    "/score",
    response_model=ComplianceScorecard,
    summary="Quick compliance scorecard",
)
async def get_scorecard(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Return headline compliance scores without full evidence detail.

    T-4: Cached per tenant (60s TTL) to avoid regenerating expensive reports
    on every dashboard load.
    """
    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    # T-4: Check cache first
    now = time.monotonic()
    cached = _score_cache.get(tenant_id)
    if cached and (now - cached[0]) < _SCORE_CACHE_TTL:
        return cached[1]

    period_start, period_end = _default_period()
    data = await generate_compliance_report(
        db,
        tenant_id,
        ["eu_ai_act", "nist_ai_rmf"],
        period_start,
        period_end,
    )

    fw_scores = []
    for fw in data.get("frameworks", []):
        summary = fw.get("summary", {})
        total_key = "total_requirements" if "total_requirements" in summary else "total_controls"
        sat_key = "satisfied" if "satisfied" in summary else "implemented"
        gap_key = "gaps" if "gaps" in summary else "not_implemented"

        fw_scores.append(
            FrameworkScore(
                framework=fw["framework"],
                overall_score=round(fw.get("overall_score", 0), 4),
                total_items=summary.get(total_key, 0),
                satisfied=summary.get(sat_key, 0),
                partial=summary.get("partial", 0),
                gaps=summary.get(gap_key, 0),
            )
        )

    result = ComplianceScorecard(
        tenant_id=user.tenant_id,
        generated_at=datetime.now(UTC),
        frameworks=fw_scores,
    )

    # T-4: Update cache (bounded to prevent memory exhaustion)
    if len(_score_cache) >= _MAX_CACHE_ENTRIES:
        # Evict oldest entries
        sorted_keys = sorted(_score_cache, key=lambda k: _score_cache[k][0])
        for k in sorted_keys[: len(sorted_keys) // 2]:
            _score_cache.pop(k, None)
    _score_cache[tenant_id] = (time.monotonic(), result)

    return result

# ── GET /history — List stored reports ────────────────────────────────────────

@router.get(
    "/history",
    response_model=ComplianceHistoryResponse,
    summary="List compliance report history",
)
async def list_reports(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    """Return paginated metadata for previously generated reports."""
    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    rows = await db.fetch(
        """
        SELECT id, tenant_id, frameworks, overall_score, created_at, created_by
        FROM compliance_reports
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        """,
        uuid.UUID(tenant_id),
        limit,
        offset,
    )

    count_row = await db.fetchrow(
        "SELECT count(*) AS cnt FROM compliance_reports WHERE tenant_id = $1",
        uuid.UUID(tenant_id),
    )
    total = count_row["cnt"] if count_row else 0

    items = [
        ComplianceReportMeta(
            id=r["id"],
            tenant_id=r["tenant_id"],
            frameworks=r["frameworks"],
            overall_score=r["overall_score"],
            created_at=r["created_at"],
            created_by=r["created_by"],
        )
        for r in rows
    ]

    return ComplianceHistoryResponse(items=items, total=total)

# ── GET /report/{id} — Retrieve stored report ────────────────────────────────

@router.get(
    "/report/{report_id}",
    response_model=ComplianceReportFull,
    summary="Retrieve a stored compliance report",
)
async def get_report(
    report_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Retrieve full report data by ID."""
    import json as _json

    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    row = await db.fetchrow(
        "SELECT * FROM compliance_reports WHERE id = $1 AND tenant_id = $2",
        report_id,
        uuid.UUID(tenant_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    data = _json.loads(row["report_data"]) if isinstance(row["report_data"], str) else row["report_data"]
    data["id"] = str(row["id"])
    data["tenant_id"] = str(row["tenant_id"])

    return data

# ── GET /report/{id}/pdf — Download stored report as PDF ─────────────────────

@router.get(
    "/report/{report_id}/pdf",
    summary="Download stored report as PDF",
    responses={200: {"content": {"application/pdf": {}}}},
)
async def get_report_pdf(
    report_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Download a previously generated report as a PDF."""
    import json as _json

    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    row = await db.fetchrow(
        "SELECT * FROM compliance_reports WHERE id = $1 AND tenant_id = $2",
        report_id,
        uuid.UUID(tenant_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    data = _json.loads(row["report_data"]) if isinstance(row["report_data"], str) else row["report_data"]
    pdf_bytes = export_pdf(data, title="Phantex Compliance Report")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="phantex-compliance-{report_id}.pdf"',
        },
    )

# ── Scanner Endpoints ─────────────────────────────────────────────────────────

async def _get_scan_config(db, tenant_id: str) -> dict[str, Any]:
    """Load tenant-scoped scan config from DB (T-1: no global shared state)."""
    row = await db.fetchrow(
        "SELECT * FROM compliance_scan_config WHERE tenant_id = $1",
        uuid.UUID(tenant_id),
    )
    if row:
        return {
            "enabled": row["enabled"],
            "quick_scan_cron": row["quick_scan_cron"],
            "full_scan_cron": row["full_scan_cron"],
            "drift_threshold": float(row["drift_threshold"]),
            "last_quick_scan": row["last_quick_scan"],
            "last_full_scan": row["last_full_scan"],
        }
    # Default config if not yet created
    return {
        "enabled": False,
        "quick_scan_cron": "0 6 * * *",
        "full_scan_cron": "0 2 * * 0",
        "drift_threshold": 0.05,
        "last_quick_scan": None,
        "last_full_scan": None,
    }

def _validate_cron(expr: str) -> bool:
    """Validate a basic 5-field cron expression (T-10)."""
    return bool(_CRON_RE.match(expr.strip()))

@router.get(
    "/scan/status",
    response_model=ScanStatusResponse,
    summary="Get scanner status",
)
async def get_scan_status(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Return the current scanner configuration and last-run timestamps."""
    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)
    cfg = await _get_scan_config(db, tenant_id)
    return ScanStatusResponse(**cfg)

@router.put(
    "/scan/config",
    response_model=ScanStatusResponse,
    summary="Update scanner configuration",
    dependencies=[Depends(require_permission("policies.write"))],
)
async def update_scan_config(
    body: ScanScheduleUpdate,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Update the automated compliance scanner schedule."""
    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    # T-10: Validate cron expressions
    if body.quick_scan_cron is not None and not _validate_cron(body.quick_scan_cron):
        raise HTTPException(status_code=422, detail="Invalid quick_scan_cron expression")
    if body.full_scan_cron is not None and not _validate_cron(body.full_scan_cron):
        raise HTTPException(status_code=422, detail="Invalid full_scan_cron expression")

    # Upsert tenant scan config (T-1: tenant-scoped, DB-backed)
    await db.execute(
        """
        INSERT INTO compliance_scan_config
            (tenant_id, enabled, quick_scan_cron, full_scan_cron, drift_threshold, updated_at)
        VALUES ($1, $2, $3, $4, $5, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            quick_scan_cron = COALESCE(EXCLUDED.quick_scan_cron, compliance_scan_config.quick_scan_cron),
            full_scan_cron = COALESCE(EXCLUDED.full_scan_cron, compliance_scan_config.full_scan_cron),
            drift_threshold = EXCLUDED.drift_threshold,
            updated_at = now()
        """,
        uuid.UUID(tenant_id),
        body.enabled,
        body.quick_scan_cron or "0 6 * * *",
        body.full_scan_cron or "0 2 * * 0",
        body.drift_threshold,
    )

    logger.info("scan_config_updated", tenant=tenant_id)
    cfg = await _get_scan_config(db, tenant_id)
    return ScanStatusResponse(**cfg)

@router.post(
    "/scan/trigger",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger on-demand compliance scan",
)
async def trigger_scan(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Run an immediate compliance scan and store the result.

    T-5: Uses per-tenant asyncio lock to prevent parallel scans.
    """
    from app.services.compliance.scanner import run_scan

    tenant_id = str(user.tenant_id)
    await db.set_tenant(tenant_id)

    # T-5: Acquire per-tenant lock (non-blocking check, bounded dict)
    if tenant_id not in _scan_locks:
        if len(_scan_locks) >= _MAX_SCAN_LOCKS:
            # Evict unlocked entries
            to_remove = [k for k, v in _scan_locks.items() if not v.locked()]
            for k in to_remove[: len(to_remove) // 2]:
                _scan_locks.pop(k, None)
        _scan_locks[tenant_id] = asyncio.Lock()

    lock = _scan_locks[tenant_id]
    if lock.locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A compliance scan is already running for this tenant",
        )

    async with lock:
        report_id = await run_scan(db, tenant_id, str(user.user_id))

    return {"status": "accepted", "report_id": str(report_id)}
