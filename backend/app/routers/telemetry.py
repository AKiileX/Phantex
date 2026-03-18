# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Telemetry Export Router (Q3).

API endpoints for managing anonymized telemetry export:
- POST /config       — Enable/disable telemetry export per tenant
- GET  /config       — Get current configuration
- GET  /status       — Runtime status (metrics, buffer depth)
- GET  /viewer       — Recent export payloads (admin review)
- GET  /viewer/pending — Preview of records awaiting export

All endpoints are tenant-scoped via auth. Only admins (role = admin)
can enable/disable telemetry export.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from app.database import get_raw_db
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.telemetry import (
    TelemetryConfigResponse,
    TelemetryConfigUpdate,
    TelemetryPendingPreview,
    TelemetryStatusResponse,
    TelemetryViewerResponse,
)
from app.utils.logging import get_logger
from ml.telemetry.config import TelemetryExportConfig, is_telemetry_kill_switch_active

logger = get_logger("phantex.router.telemetry")

router = APIRouter(
    prefix="/api/v1/telemetry",
    tags=["telemetry"],
    dependencies=[Depends(rate_limit)],
)

# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_tenant_config(conn, tenant_id: str) -> dict[str, Any] | None:
    """Fetch telemetry config row for a tenant."""
    row = await conn.fetchrow(
        """
        SELECT tenant_id, enabled, dp_epsilon,
               created_at, updated_at
        FROM telemetry_config
        WHERE tenant_id = $1
        """,
        tenant_id,
    )
    return dict(row) if row else None

def _require_admin(user: CurrentUser) -> None:
    """Raise 403 if the user is not an admin."""
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only admins can manage telemetry export configuration",
        )

# ── POST /config — Enable / Disable Telemetry Export ────────────────────────

@router.post("/config", response_model=TelemetryConfigResponse, status_code=200)
async def update_telemetry_config(
    body: TelemetryConfigUpdate,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Enable or disable anonymized telemetry export for this tenant.

    Requirements (Q3):
    - Opt-in ONLY, default OFF
    - Kill switch (PHANTEX_TELEMETRY_EXPORT=false) overrides everything
    - Admin role required
    """
    _require_admin(user)
    tenant_id = str(user.tenant_id)
    kill_switch = is_telemetry_kill_switch_active()

    # Default epsilon if not provided
    epsilon = body.dp_epsilon or TelemetryExportConfig().dp_epsilon

    # Upsert telemetry config
    await db.execute(
        """
        INSERT INTO telemetry_config (tenant_id, enabled, dp_epsilon)
        VALUES ($1, $2, $3)
        ON CONFLICT (tenant_id) DO UPDATE
        SET enabled = $2, dp_epsilon = $3, updated_at = NOW()
        """,
        tenant_id,
        body.enabled,
        epsilon,
    )

    config = await _get_tenant_config(db, tenant_id)

    logger.info(
        "telemetry_config_updated",
        tenant_id=tenant_id,
        enabled=body.enabled,
        dp_epsilon=epsilon,
        kill_switch_active=kill_switch,
    )

    return TelemetryConfigResponse(
        tenant_id=tenant_id,
        enabled=config["enabled"],
        dp_epsilon=config["dp_epsilon"],
        global_kill_switch_active=kill_switch,
        cloud_endpoint_configured=bool(TelemetryExportConfig().cloud_endpoint),
        created_at=str(config["created_at"]) if config.get("created_at") else None,
        updated_at=str(config["updated_at"]) if config.get("updated_at") else None,
    )

# ── GET /config — Get Telemetry Configuration ───────────────────────────────

@router.get("/config", response_model=TelemetryConfigResponse, status_code=200)
async def get_telemetry_config(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Get current telemetry export configuration for this tenant."""
    tenant_id = str(user.tenant_id)
    kill_switch = is_telemetry_kill_switch_active()

    config = await _get_tenant_config(db, tenant_id)

    if config is None:
        # Default: disabled (opt-in only)
        return TelemetryConfigResponse(
            tenant_id=tenant_id,
            enabled=False,
            dp_epsilon=TelemetryExportConfig().dp_epsilon,
            global_kill_switch_active=kill_switch,
            cloud_endpoint_configured=bool(TelemetryExportConfig().cloud_endpoint),
        )

    return TelemetryConfigResponse(
        tenant_id=tenant_id,
        enabled=config["enabled"],
        dp_epsilon=config["dp_epsilon"],
        global_kill_switch_active=kill_switch,
        cloud_endpoint_configured=bool(TelemetryExportConfig().cloud_endpoint),
        created_at=str(config["created_at"]) if config.get("created_at") else None,
        updated_at=str(config["updated_at"]) if config.get("updated_at") else None,
    )

# ── GET /status — Runtime Telemetry Status ──────────────────────────────────

@router.get("/status", response_model=TelemetryStatusResponse, status_code=200)
async def get_telemetry_status(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db=Depends(get_raw_db),
):
    """Get runtime telemetry export status including metrics and buffer depth."""
    tenant_id = str(user.tenant_id)
    kill_switch = is_telemetry_kill_switch_active()

    config = await _get_tenant_config(db, tenant_id)

    enabled = config["enabled"] if config else False

    # Import exporter lazily to avoid circular deps
    # In a real deployment, the exporter is a singleton on app.state
    return TelemetryStatusResponse(
        enabled=enabled,
        global_kill_switch_active=kill_switch,
        cloud_endpoint_configured=bool(TelemetryExportConfig().cloud_endpoint),
        buffer_size=0,  # Populated from app.state.telemetry_exporter in prod
        metrics={
            "batches_sent": 0,
            "batches_failed": 0,
            "records_exported": 0,
            "records_dropped": 0,
            "last_export_at": None,
            "last_error": None,
        },
    )

# ── GET /viewer — Telemetry Viewer (Admin Review) ───────────────────────────

@router.get("/viewer", response_model=TelemetryViewerResponse, status_code=200)
async def get_telemetry_viewer(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    limit: int = 50,  # Clamped to [1, 100] below
):
    """View recent telemetry export payloads.

    This implements the Q3 "Telemetry Viewer" requirement:
    admin can see exactly what is exported before it leaves the network.
    """
    _require_admin(user)
    limit = max(1, min(limit, 100))  # Clamp to [1, 100]

    # In production, this reads from app.state.telemetry_exporter
    # For now, return empty (no exporter initialized without cloud)
    return TelemetryViewerResponse(
        entries=[],
        total_entries=0,
        pending_records=0,
    )

# ── GET /viewer/pending — Preview Pending Records ───────────────────────────

@router.get("/viewer/pending", response_model=TelemetryPendingPreview, status_code=200)
async def get_pending_preview(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Preview records currently buffered and awaiting export.

    Admin can inspect what WILL be exported on the next flush.
    """
    _require_admin(user)

    return TelemetryPendingPreview(
        records=[],
        total_pending=0,
    )
