# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — FinOps Cost & Token Monitoring Router.

Endpoints:
  GET  /api/v1/finops/summary         — Total cost summary
  GET  /api/v1/finops/by-agent        — Per-agent cost breakdown
  GET  /api/v1/finops/by-model        — Per-model cost breakdown
  GET  /api/v1/finops/trend           — Hourly cost trend
  GET  /api/v1/finops/projection      — Projected monthly spend
  GET  /api/v1/finops/anomalies       — Recent cost anomalies
  POST /api/v1/finops/anomalies/scan  — Run anomaly detection scan
  GET  /api/v1/finops/budgets         — List budget configs
  POST /api/v1/finops/budgets         — Create budget config
  GET  /api/v1/finops/budgets/status  — Evaluate all budgets

All endpoints are tenant-scoped via auth token.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.clickhouse import get_clickhouse
from app.database import get_admin_db
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.services.finops import cost_aggregator, cost_anomaly
from app.services.finops.budget_manager import BudgetConfig, BudgetManager, BudgetScope
from app.utils.logging import get_logger

logger = get_logger("phantex.finops_router")

router = APIRouter(
    prefix="/api/v1/finops",
    tags=["finops"],
    dependencies=[
        Depends(rate_limit),
        Depends(require_permission("analytics.view")),
    ],
)

_budget_mgr = BudgetManager()

async def _require_ch():
    ch = await get_clickhouse()
    if ch is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ClickHouse analytics service not configured",
        )
    return ch

# ── Cost Summary ──────────────────────────────────────────────────────────────

@router.get("/summary", summary="Cost summary for tenant")
async def get_cost_summary(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: cost_aggregator.ValidRange = Query("24h", alias="range"),
):
    return await cost_aggregator.cost_summary(ch, current_user.tenant_id, range_str=range)

# ── Per-Agent Breakdown ───────────────────────────────────────────────────────

@router.get("/by-agent", summary="Cost per agent")
async def get_cost_by_agent(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: cost_aggregator.ValidRange = Query("24h", alias="range"),
    limit: int = Query(50, ge=1, le=200),
):
    return await cost_aggregator.cost_by_agent(
        ch,
        current_user.tenant_id,
        range_str=range,
        limit=limit,
    )

# ── Per-Model Breakdown ──────────────────────────────────────────────────────

@router.get("/by-model", summary="Cost per model")
async def get_cost_by_model(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: cost_aggregator.ValidRange = Query("24h", alias="range"),
):
    return await cost_aggregator.cost_by_model(ch, current_user.tenant_id, range_str=range)

# ── Trend ─────────────────────────────────────────────────────────────────────

@router.get("/trend", summary="Hourly cost trend")
async def get_cost_trend(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: cost_aggregator.ValidRange = Query("7d", alias="range"),
):
    return await cost_aggregator.cost_trend(ch, current_user.tenant_id, range_str=range)

# ── Projection ────────────────────────────────────────────────────────────────

@router.get("/projection", summary="Projected monthly spend")
async def get_projection(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
):
    return await cost_aggregator.projected_spend(ch, current_user.tenant_id)

# ── Anomalies ─────────────────────────────────────────────────────────────────

@router.get("/anomalies", summary="Recent cost anomalies")
async def get_anomalies(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
):
    return await cost_anomaly.recent_anomalies(
        ch,
        current_user.tenant_id,
        range_hours=hours,
        limit=limit,
    )

@router.post(
    "/anomalies/scan",
    summary="Run cost anomaly detection scan",
    dependencies=[Depends(require_permission("analytics.manage"))],
)
async def run_anomaly_scan(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    db=Depends(get_admin_db),
):
    anomalies = await cost_anomaly.detect_anomalies(ch, current_user.tenant_id, db=db)
    return {"anomalies_found": len(anomalies), "anomalies": anomalies}

# ── Budgets ───────────────────────────────────────────────────────────────────

class BudgetCreateRequest(BaseModel):
    scope: BudgetScope
    scope_id: str = Field(..., min_length=1, max_length=100)
    budget_usd: float = Field(..., gt=0, le=1_000_000)
    hard_cap: bool = False

# In-memory budget store (production: PostgreSQL finops_budgets table)
_budgets: dict[uuid.UUID, list[BudgetConfig]] = {}

@router.get("/budgets", summary="List budget configs")
async def list_budgets(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    tenant_budgets = _budgets.get(current_user.tenant_id, [])
    return [
        {
            "id": str(b.id),
            "scope": b.scope.value,
            "scope_id": b.scope_id,
            "budget_usd": b.budget_usd,
            "hard_cap": b.hard_cap,
            "enabled": b.enabled,
        }
        for b in tenant_budgets
    ]

@router.post(
    "/budgets",
    summary="Create budget config",
    status_code=201,
    dependencies=[Depends(require_permission("analytics.manage"))],
)
async def create_budget(
    req: BudgetCreateRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    cfg = BudgetConfig(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        scope=req.scope,
        scope_id=req.scope_id,
        budget_usd=req.budget_usd,
        hard_cap=req.hard_cap,
    )
    _budgets.setdefault(current_user.tenant_id, []).append(cfg)
    logger.info(
        "budget_created",
        tenant_id=str(current_user.tenant_id),
        scope=cfg.scope.value,
        budget_usd=cfg.budget_usd,
    )
    return {"id": str(cfg.id), "scope": cfg.scope.value, "budget_usd": cfg.budget_usd}

@router.get("/budgets/status", summary="Evaluate all budgets")
async def evaluate_budgets(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
):
    tenant_budgets = _budgets.get(current_user.tenant_id, [])
    if not tenant_budgets:
        return []

    results = await _budget_mgr.evaluate_all(ch, tenant_budgets)
    return [
        {
            "id": str(s.config.id),
            "scope": s.config.scope.value,
            "scope_id": s.config.scope_id,
            "budget_usd": s.config.budget_usd,
            "spent_usd": s.spent_usd,
            "pct_used": s.pct_used,
            "remaining_usd": s.remaining_usd,
            "breached_thresholds": s.breached_thresholds,
            "capped": s.capped,
        }
        for s in results
    ]

# ── CSV Export ────────────────────────────────────────────────────────────────

_ALLOWED_FINOPS_QUERY_TYPES = {"summary", "by-agent", "by-model", "trend", "anomalies"}

def _rows_to_csv(rows: list[dict[str, Any]]) -> str:
    """Convert a list of dicts to CSV text."""
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()

@router.get("/export/csv", summary="Export FinOps data as CSV")
async def export_finops_csv(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    query_type: str = Query(
        ...,
        description="summary|by-agent|by-model|trend|anomalies",
        max_length=20,
    ),
    range: cost_aggregator.ValidRange = Query("24h", alias="range"),
):
    """Export FinOps query result as CSV download."""
    if query_type not in _ALLOWED_FINOPS_QUERY_TYPES:
        raise HTTPException(400, "Invalid query_type")

    tid = current_user.tenant_id
    logger.info(
        "finops_csv_export",
        extra={"user": str(current_user.user_id), "tenant": str(tid), "query_type": query_type},
    )

    if query_type == "summary":
        raw = await cost_aggregator.cost_summary(ch, tid, range_str=range)
        data = [raw] if isinstance(raw, dict) else [raw.__dict__] if hasattr(raw, "__dict__") else [{"value": raw}]
    elif query_type == "by-agent":
        data = await cost_aggregator.cost_by_agent(ch, tid, range_str=range)
    elif query_type == "by-model":
        data = await cost_aggregator.cost_by_model(ch, tid, range_str=range)
    elif query_type == "trend":
        data = await cost_aggregator.cost_trend(ch, tid, range_str=range)
    elif query_type == "anomalies":
        data = await cost_anomaly.recent_anomalies(ch, tid)
    else:
        raise HTTPException(400, "Invalid query_type")

    # Normalize to list[dict]
    rows: list[dict[str, Any]] = []
    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict):
            rows.append(item)
        elif hasattr(item, "__dict__"):
            rows.append(item.__dict__)
        else:
            rows.append({"value": item})

    csv_content = _rows_to_csv(rows)
    safe_name = "".join(c for c in query_type if c.isalnum() or c == "-")
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="phantex-finops-{safe_name}.csv"'},
    )

# ── PDF Export ────────────────────────────────────────────────────────────────

@router.get("/export/pdf", summary="Export FinOps summary as PDF")
async def export_finops_pdf(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ch=Depends(_require_ch),
    range: cost_aggregator.ValidRange = Query("24h", alias="range"),
):
    """Generate a PDF FinOps summary with cost KPIs and top agents."""
    tid = current_user.tenant_id
    logger.info(
        "finops_pdf_export",
        extra={"user": str(current_user.user_id), "tenant": str(tid), "range": range},
    )

    summary = await cost_aggregator.cost_summary(ch, tid, range_str=range)
    top_agents = await cost_aggregator.cost_by_agent(ch, tid, range_str=range, limit=10)
    top_models = await cost_aggregator.cost_by_model(ch, tid, range_str=range)

    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Phantex FinOps Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(
        0,
        6,
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}  |  Range: {range}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(6)

    # Cost summary
    s = summary if isinstance(summary, dict) else (summary.__dict__ if hasattr(summary, "__dict__") else {})
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Cost Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for label, key in [
        ("Total Cost (USD)", "total_cost_usd"),
        ("Total Tokens", "total_tokens"),
        ("Total Requests", "total_requests"),
        ("Active Agents", "unique_agents"),
    ]:
        val = s.get(key, 0)
        formatted = f"${val:,.4f}" if "cost" in key else f"{val:,}"
        pdf.cell(0, 6, f"  {label}: {formatted}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Top agents by cost
    agents_list = top_agents if isinstance(top_agents, list) else []
    if agents_list:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Top Agents by Cost", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(70, 6, "Agent ID")
        pdf.cell(30, 6, "Tokens")
        pdf.cell(30, 6, "Requests")
        pdf.cell(30, 6, "Cost (USD)")
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        for a in agents_list[:10]:
            row = a if isinstance(a, dict) else (a.__dict__ if hasattr(a, "__dict__") else {})
            pdf.cell(70, 5, str(row.get("agent_id", ""))[:36])
            pdf.cell(30, 5, f"{row.get('total_tokens', 0):,}")
            pdf.cell(30, 5, f"{row.get('requests', 0):,}")
            pdf.cell(30, 5, f"${row.get('cost_usd', 0):,.4f}")
            pdf.ln()
    pdf.ln(4)

    # Top models
    models_list = top_models if isinstance(top_models, list) else []
    if models_list:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Cost by Model", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for m in models_list[:10]:
            row = m if isinstance(m, dict) else (m.__dict__ if hasattr(m, "__dict__") else {})
            pdf.cell(
                0,
                6,
                f"  {row.get('model', 'unknown')} ({row.get('provider', '')}): "
                f"${row.get('cost_usd', 0):,.4f} — {row.get('total_tokens', 0):,} tokens",
                new_x="LMARGIN",
                new_y="NEXT",
            )

    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=phantex-finops-report.pdf"},
    )
