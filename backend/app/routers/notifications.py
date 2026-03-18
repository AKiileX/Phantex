# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Notifications Router (N2).

CRUD endpoints for notification channels + routing rules.
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field

from app.database import get_raw_db
from app.middleware.auth import get_current_active_user
from app.notifications.base import NotificationError
from app.notifications.router import get_channel, list_channel_types
from app.utils.logging import get_logger

from app.middleware.rate_limit import rate_limit

logger = get_logger("phantex.router.notifications")

router = APIRouter(
    prefix="/api/v1/notifications",
    tags=["notifications"],
    dependencies=[Depends(rate_limit)],
)

# ── Schemas ──────────────────────────────────────────────────────────────────

class ChannelCreate(BaseModel):
    channel_type: str = Field(..., description="Channel type (slack, pagerduty, webhook, email)")
    name: str = Field(..., min_length=1, max_length=128)
    config: dict[str, Any] = Field(..., description="Channel-specific config")
    enabled: bool = True
    rate_limit_per_min: int = Field(60, ge=1, le=1000)

class ChannelUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    rate_limit_per_min: int | None = Field(None, ge=1, le=1000)

class RoutingRuleSet(BaseModel):
    rules: list[dict[str, Any]] = Field(..., description="Ordered routing rules")

# ── Channel Endpoints ────────────────────────────────────────────────────────

@router.get("/channel-types")
async def get_channel_types():
    """List available notification channel types."""
    return {"channel_types": list_channel_types()}

@router.get("/channels")
async def list_channels(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List all notification channels for the current tenant."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    rows = await db.fetch(
        """
        SELECT id, tenant_id, channel_type, name, enabled, rate_limit_per_min,
               config, created_at, updated_at
        FROM notification_channels
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    return {"channels": [_mask_channel(r) for r in rows]}

@router.post("/channels", status_code=201)
async def create_channel(
    body: ChannelCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create a notification channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    # Validate by instantiating
    try:
        channel = get_channel(
            body.channel_type,
            tenant_id=str(tenant_id),
            config=body.config,
            rate_limit_per_min=body.rate_limit_per_min,
        )
        await channel.close()
    except NotificationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    row = await db.fetchrow(
        """
        INSERT INTO notification_channels (id, tenant_id, channel_type, name, config, enabled, rate_limit_per_min)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        """,
        str(uuid.uuid4()),
        tenant_id,
        body.channel_type,
        body.name,
        json.dumps(body.config),
        body.enabled,
        body.rate_limit_per_min,
    )

    logger.info("channel_created", channel_id=row["id"], type=body.channel_type)
    return _mask_channel(row)

@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Test a notification channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM notification_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Channel not found")

    config = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
    try:
        channel = get_channel(
            row["channel_type"],
            tenant_id=str(tenant_id),
            config=config,
        )
        result = await channel.test()
        await channel.close()
        return result
    except NotificationError as e:
        logger.warning("channel_test_failed", error=str(e))
        return {"success": False, "message": "Channel test failed"}

@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Delete a notification channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "DELETE FROM notification_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Channel not found")

# ── Routing Rules ────────────────────────────────────────────────────────────

@router.get("/routing-rules")
async def get_routing_rules(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get notification routing rules for the current tenant."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    row = await db.fetchrow(
        "SELECT rules FROM notification_routing_rules WHERE tenant_id = $1",
        tenant_id,
    )
    if row:
        rules = json.loads(row["rules"]) if isinstance(row["rules"], str) else row["rules"]
        return {"rules": rules}
    return {"rules": []}

@router.put("/routing-rules")
async def set_routing_rules(
    body: RoutingRuleSet,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Set notification routing rules for the current tenant (replaces existing)."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    # Validate rule structure
    for i, rule in enumerate(body.rules):
        if "channels" not in rule:
            raise HTTPException(
                status_code=400,
                detail=f"Rule {i}: 'channels' field required",
            )
        if not isinstance(rule.get("channels", []), list):
            raise HTTPException(
                status_code=400,
                detail=f"Rule {i}: 'channels' must be a list",
            )

    rules_json = json.dumps(body.rules, default=str)

    await db.execute(
        """
        INSERT INTO notification_routing_rules (tenant_id, rules, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (tenant_id) DO UPDATE
        SET rules = $2, updated_at = now()
        """,
        tenant_id,
        rules_json,
    )

    return {"rules": body.rules, "message": "Routing rules updated"}

# ── Helpers ──────────────────────────────────────────────────────────────────

_SENSITIVE_FIELDS = {
    "webhook_url",
    "routing_key",
    "secret",
    "api_key",
    "sendgrid_api_key",
    "smtp_password",
    "token",
    "password",
}

def _mask_channel(row) -> dict:
    config = row.get("config")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except (ValueError, TypeError):
            config = {}
    elif config is None:
        config = {}

    masked = {}
    for k, v in config.items():
        if k.lower() in _SENSITIVE_FIELDS or "key" in k.lower() or "token" in k.lower() or "password" in k.lower():
            masked[k] = "***" if v else ""
        else:
            masked[k] = v

    return {
        "id": row["id"],
        "tenant_id": str(row["tenant_id"]),
        "channel_type": row["channel_type"],
        "name": row["name"],
        "enabled": row["enabled"],
        "rate_limit_per_min": row["rate_limit_per_min"],
        "config_masked": masked,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
