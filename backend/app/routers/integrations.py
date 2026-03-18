# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Integrations Router (N1).

CRUD endpoints for managing SIEM/XDR integrations per tenant.
Each tenant can configure multiple integrations (e.g., Splunk + Syslog).

Credentials are encrypted at rest and never returned in API responses
(masked with ***).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field

from app.database import get_raw_db
from app.integrations.base import IntegrationError
from app.integrations.registry import get_integration, list_platforms
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.utils.logging import get_logger

logger = get_logger("phantex.router.integrations")

router = APIRouter(
    prefix="/api/v1/integrations",
    tags=["integrations"],
    dependencies=[Depends(rate_limit)],
)

# ── Schemas ──────────────────────────────────────────────────────────────────

class IntegrationCreate(BaseModel):
    platform: str = Field(..., description="Platform name (e.g., splunk_hec, elastic_siem)")
    name: str = Field(..., min_length=1, max_length=128, description="Display name")
    config: dict[str, Any] = Field(..., description="Platform-specific config (credentials + endpoint)")
    enabled: bool = Field(True, description="Whether the integration is active")
    rate_limit_per_min: int = Field(1000, ge=1, le=10000, description="Max events/min")

class IntegrationUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    rate_limit_per_min: int | None = Field(None, ge=1, le=10000)

class IntegrationResponse(BaseModel):
    id: str
    tenant_id: str
    platform: str
    name: str
    enabled: bool
    rate_limit_per_min: int
    config_masked: dict[str, Any]  # Credentials replaced with ***
    created_at: str
    updated_at: str

# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/platforms")
async def get_platforms():
    """List all available integration platforms."""
    return {"platforms": list_platforms()}

@router.get("/")
async def list_integrations(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List all integrations for the current tenant."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    rows = await db.fetch(
        """
        SELECT id, tenant_id, platform, name, enabled, rate_limit_per_min,
               config, created_at, updated_at
        FROM integrations
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        """,
        tenant_id,
    )

    return {"integrations": [_to_response(r) for r in rows]}

@router.post("/", status_code=201)
async def create_integration(
    body: IntegrationCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create a new SIEM/XDR integration for the current tenant."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    # Validate platform exists and config is valid by attempting instantiation
    try:
        integration = get_integration(
            body.platform,
            tenant_id=str(tenant_id),
            config=body.config,
            rate_limit_per_min=body.rate_limit_per_min,
        )
        await integration.close()  # Don't keep the test instance open
    except IntegrationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    import json as _json

    row = await db.fetchrow(
        """
        INSERT INTO integrations (id, tenant_id, platform, name, config, enabled, rate_limit_per_min)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, tenant_id, platform, name, enabled, rate_limit_per_min,
                  config, created_at, updated_at
        """,
        str(uuid.uuid4()),
        tenant_id,
        body.platform,
        body.name,
        _json.dumps(body.config),
        body.enabled,
        body.rate_limit_per_min,
    )

    logger.info(
        "integration_created",
        integration_id=row["id"],
        platform=body.platform,
        tenant_id=str(tenant_id),
    )

    return _to_response(row)

@router.get("/{integration_id}")
async def get_integration_detail(
    integration_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get a single integration by ID."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM integrations WHERE id = $1 AND tenant_id = $2",
        integration_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Integration not found")
    return _to_response(row)

@router.patch("/{integration_id}")
async def update_integration(
    integration_id: Annotated[str, Path()],
    body: IntegrationUpdate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Update an existing integration."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    existing = await db.fetchrow(
        "SELECT * FROM integrations WHERE id = $1 AND tenant_id = $2",
        integration_id,
        tenant_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Integration not found")

    import json as _json

    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.rate_limit_per_min is not None:
        updates["rate_limit_per_min"] = body.rate_limit_per_min
    if body.config is not None:
        # Validate new config
        try:
            integration = get_integration(
                existing["platform"],
                tenant_id=str(tenant_id),
                config=body.config,
            )
            await integration.close()
        except IntegrationError as e:
            raise HTTPException(status_code=400, detail=str(e))
        updates["config"] = _json.dumps(body.config)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clauses = ", ".join(f"{k} = ${i + 2}" for i, k in enumerate(updates.keys()))
    values = list(updates.values())

    row = await db.fetchrow(
        f"""
        UPDATE integrations
        SET {set_clauses}, updated_at = now()
        WHERE id = $1
        RETURNING *
        """,
        integration_id,
        *values,
    )

    return _to_response(row)

@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Delete an integration."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "DELETE FROM integrations WHERE id = $1 AND tenant_id = $2",
        integration_id,
        tenant_id,
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Integration not found")

@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Test an integration's connectivity and credentials."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    row = await db.fetchrow(
        "SELECT * FROM integrations WHERE id = $1 AND tenant_id = $2",
        integration_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Integration not found")

    import json as _json

    config = _json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]

    try:
        integration = get_integration(
            row["platform"],
            tenant_id=str(tenant_id),
            config=config,
        )
        result = await integration.test_connection()
        await integration.close()
        return result
    except IntegrationError as e:
        logger.warning("integration_test_failed", error=str(e))
        return {"success": False, "message": "Connection test failed"}

# ── Helpers ──────────────────────────────────────────────────────────────────

# Fields that should be masked in API responses
_SENSITIVE_FIELDS = {
    "hec_token",
    "shared_key",
    "api_key_secret",
    "api_key_id",
    "ingest_token",
    "password",
    "secret",
    "token",
}

def _mask_config(config: dict | str | None) -> dict:
    """Mask sensitive fields in integration config for API responses."""
    if config is None:
        return {}

    import json as _json

    if isinstance(config, str):
        try:
            config = _json.loads(config)
        except (ValueError, TypeError):
            return {}

    masked = {}
    for key, value in config.items():
        if key.lower() in _SENSITIVE_FIELDS or "key" in key.lower() or "token" in key.lower():
            masked[key] = "***" if value else ""
        else:
            masked[key] = value
    return masked

def _to_response(row) -> dict:
    """Convert a DB row to an API response dict with masked config."""
    return {
        "id": row["id"],
        "tenant_id": str(row["tenant_id"]),
        "platform": row["platform"],
        "name": row["name"],
        "enabled": row["enabled"],
        "rate_limit_per_min": row["rate_limit_per_min"],
        "config_masked": _mask_config(row.get("config")),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
