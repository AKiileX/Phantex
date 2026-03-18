# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Advanced Analytics Router

Drill-down endpoints, KPI summary, trend data, and CSV/PDF export
for the AC dashboard pages.

All queries are tenant-scoped. CSV export returns text/csv; PDF export
returns application/pdf built with fpdf2.
"""

from __future__ import annotations

from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.clickhouse import get_clickhouse
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.models.alert import Alert
from app.schemas.auth import CurrentUser
from app.services import analytics_v2_service as svc
from app.utils.logging import get_logger

logger = get_logger("phantex.analytics_v2_router")

_ALLOWED_QUERY_TYPES = frozenset(
    {
        "kpi",
        "severity-trend",
        "attack-trend",
        "top-agents",
        "tool-heatmap",
        "framework",
        "data-volume",
        "drill-down",
    }
)

router = APIRouter(
    prefix="/api/v1/analytics/v2",
    tags=["analytics-v2"],
    dependencies=[
        Depends(rate_limit),
        Depends(require_permission("analytics.view")),
    ],
)

async def _require_ch():
    ch = await get_clickhouse()
    if ch is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ClickHouse analytics service not configured",
        )
    return ch

# ── KPI Summary ──────────────────────────────────────────────────────────────

@router.get("/kpi", summary="KPI summary cards")
async def get_kpi(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("24h", alias="range"),
):
    since = svc._since(range)
    # PG is the source of truth for alerts (rule-engine → PG, not all go to CH).
    row = (
        await db.execute(
            select(
                func.count().label("total"),
                func.count().filter(Alert.severity == "critical").label("critical"),
                func.count().filter(Alert.severity == "high").label("high"),
                func.count().filter(Alert.severity == "medium").label("medium"),
                func.count().filter(Alert.severity == "low").label("low"),
            )
            .select_from(Alert)
            .where(Alert.created_at >= since)
        )
    ).one()
    return await svc.kpi_summary(
        ch,
        current_user.tenant_id,
        range_str=range,
        pg_alert_count=row.total,
        pg_severity_counts={
            "critical": row.critical,
            "high": row.high,
            "medium": row.medium,
            "low": row.low,
        },
    )

# ── Severity Trend ───────────────────────────────────────────────────────────

@router.get("/severity-trend", summary="Daily severity distribution")
async def get_severity_trend(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("30d", alias="range"),
):
    return await svc.severity_trend(ch, current_user.tenant_id, range_str=range)

# ── Attack Class Trend ───────────────────────────────────────────────────────

@router.get("/attack-trend", summary="Daily attack-class breakdown")
async def get_attack_trend(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("30d", alias="range"),
):
    return await svc.attack_class_trend(ch, current_user.tenant_id, range_str=range)

# ── Top Agents by Risk ───────────────────────────────────────────────────────

@router.get("/top-agents-risk", summary="Top agents by risk score")
async def get_top_agents_risk(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("7d", alias="range"),
    limit: int = Query(20, ge=1, le=100),
):
    return await svc.top_agents_risk(ch, current_user.tenant_id, range_str=range, limit=limit)

# ── Tool Heatmap ─────────────────────────────────────────────────────────────

@router.get("/tool-heatmap", summary="Hourly tool-call heatmap")
async def get_tool_heatmap(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("7d", alias="range"),
    limit: int = Query(20, ge=1, le=50),
):
    return await svc.tool_heatmap(ch, current_user.tenant_id, range_str=range, limit=limit)

# ── Framework Breakdown ──────────────────────────────────────────────────────

@router.get("/framework-breakdown", summary="Framework usage breakdown")
async def get_framework_breakdown(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("30d", alias="range"),
):
    return await svc.framework_breakdown(ch, current_user.tenant_id, range_str=range)

# ── Data Volume Trend ────────────────────────────────────────────────────────

@router.get("/data-volume", summary="Hourly data volume trend")
async def get_data_volume(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("7d", alias="range"),
):
    return await svc.data_volume_trend(ch, current_user.tenant_id, range_str=range)

# ── Drill-Down ───────────────────────────────────────────────────────────────

@router.get("/drill-down", summary="Flexible drill-down query")
async def get_drill_down(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    dim1: svc.ValidDimension = Query(..., alias="dimension1"),
    dim2: svc.ValidDimension | None = Query(None, alias="dimension2"),
    metric: svc.ValidMetric = Query("count"),
    range: svc.ValidRange = Query("7d", alias="range"),
    limit: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None, max_length=20),
    attack_class: str | None = Query(None, max_length=100),
    event_type: str | None = Query(None, max_length=100),
):
    return await svc.drill_down(
        ch,
        current_user.tenant_id,
        dimension1=dim1,
        dimension2=dim2,
        metric=metric,
        range_str=range,
        limit=limit,
        filter_severity=severity,
        filter_attack_class=attack_class,
        filter_event_type=event_type,
    )

# ── CSV Export ───────────────────────────────────────────────────────────────

@router.get("/export/csv", summary="Export query result as CSV")
async def export_csv(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    query_type: str = Query(
        ...,
        description="kpi|severity-trend|attack-trend|top-agents|tool-heatmap|framework|data-volume|drill-down",
        max_length=30,
    ),
    range: svc.ValidRange = Query("7d", alias="range"),
    # Drill-down params (used only when query_type=drill-down)
    dim1: svc.ValidDimension | None = Query(None, alias="dimension1"),
    dim2: svc.ValidDimension | None = Query(None, alias="dimension2"),
    metric: svc.ValidMetric = Query("count"),
    limit: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None, max_length=20),
    attack_class: str | None = Query(None, max_length=100),
    event_type: str | None = Query(None, max_length=100),
):
    """Export any analytics query result as CSV download."""
    if query_type not in _ALLOWED_QUERY_TYPES:
        raise HTTPException(400, "Invalid query_type")

    tid = current_user.tenant_id
    logger.info(
        "csv_export requested",
        extra={"user": str(current_user.user_id), "tenant": str(tid), "query_type": query_type, "range": range},
    )

    if query_type == "kpi":
        data = [await svc.kpi_summary(ch, tid, range_str=range)]
    elif query_type == "severity-trend":
        data = await svc.severity_trend(ch, tid, range_str=range)
    elif query_type == "attack-trend":
        data = await svc.attack_class_trend(ch, tid, range_str=range)
    elif query_type == "top-agents":
        data = await svc.top_agents_risk(ch, tid, range_str=range, limit=limit)
    elif query_type == "tool-heatmap":
        data = await svc.tool_heatmap(ch, tid, range_str=range, limit=limit)
    elif query_type == "framework":
        data = await svc.framework_breakdown(ch, tid, range_str=range)
    elif query_type == "data-volume":
        data = await svc.data_volume_trend(ch, tid, range_str=range)
    elif query_type == "drill-down":
        if not dim1:
            raise HTTPException(400, "dimension1 required for drill-down export")
        data = await svc.drill_down(
            ch,
            tid,
            dimension1=dim1,
            dimension2=dim2,
            metric=metric,
            range_str=range,
            limit=limit,
            filter_severity=severity,
            filter_attack_class=attack_class,
            filter_event_type=event_type,
        )
    else:
        raise HTTPException(400, "Invalid query_type")

    csv_content = svc.rows_to_csv(data)
    # Sanitize filename: only allow alphanumeric + hyphens (prevent header injection)
    safe_name = "".join(c for c in query_type if c.isalnum() or c == "-")
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="phantex-analytics-{safe_name}.csv"'},
    )

# ── PDF Export ───────────────────────────────────────────────────────────────

@router.get("/export/pdf", summary="Export analytics summary as PDF")
async def export_pdf(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: svc.ValidRange = Query("7d", alias="range"),
):
    """Generate a PDF analytics summary with KPI cards and top agents."""
    tid = current_user.tenant_id
    logger.info(
        "pdf_export requested",
        extra={"user": str(current_user.user_id), "tenant": str(tid), "range": range},
    )

    kpi = await svc.kpi_summary(ch, tid, range_str=range)
    top_agents = await svc.top_agents_risk(ch, tid, range_str=range, limit=10)
    frameworks = await svc.framework_breakdown(ch, tid, range_str=range)

    import io as _io
    from datetime import datetime

    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Phantex Analytics Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(
        0,
        6,
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}  |  Range: {range}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(6)

    # KPI cards
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Key Performance Indicators", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for label, key in [
        ("Total Events", "total_events"),
        ("Total Alerts", "total_alerts"),
        ("Active Agents", "active_agents"),
        ("Attack Classes", "attack_classes"),
        ("Critical", "critical"),
        ("High", "high"),
    ]:
        pdf.cell(0, 6, f"  {label}: {kpi.get(key, 0):,}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Top agents
    if top_agents:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Top Agents by Risk", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(60, 6, "Agent ID")
        pdf.cell(20, 6, "Events")
        pdf.cell(20, 6, "Critical")
        pdf.cell(20, 6, "High")
        pdf.cell(20, 6, "Attacks")
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        for a in top_agents[:10]:
            pdf.cell(60, 5, a["agent_id"][:36])
            pdf.cell(20, 5, f"{a['total_events']:,}")
            pdf.cell(20, 5, str(a["critical"]))
            pdf.cell(20, 5, str(a["high"]))
            pdf.cell(20, 5, str(a["attacks"]))
            pdf.ln()
    pdf.ln(4)

    # Frameworks
    if frameworks:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Framework Distribution", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for f in frameworks[:10]:
            pdf.cell(
                0, 6, f"  {f['framework']}: {f['count']:,} events ({f['agents']} agents)", new_x="LMARGIN", new_y="NEXT"
            )

    buf = _io.BytesIO()
    pdf.output(buf)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=phantex-analytics-report.pdf"},
    )
