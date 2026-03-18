# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — PDR Exports Router (L3).

CRUD endpoints for managing PDR (Phantex Data Relay) export channels.
Each tenant can configure multiple export channels:
  - S3 drops:      gzipped OCSF JSON-L to S3 bucket
  - Webhook push:  HMAC-signed OCSF JSON POST
  - Kafka mirror:  OCSF events to customer Kafka cluster

Credentials are stored as JSON and masked in API responses.
All operations are tenant-scoped via auth.
"""

from __future__ import annotations

import json as _json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field, field_validator

from app.database import get_raw_db
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.services.agent_policy_service import compute_next_cron
from app.services.ocsf_mapper import get_supported_event_types
from app.services.pdr_schedule_runner import execute_channel_export
from app.utils.logging import get_logger

logger = get_logger("phantex.router.exports")

router = APIRouter(
    prefix="/api/v1/exports",
    tags=["exports"],
    dependencies=[Depends(rate_limit)],
)

_VALID_CHANNEL_TYPES = {"s3", "webhook", "kafka_mirror"}

# ── Schemas ──────────────────────────────────────────────────────────────────

class PDRChannelCreate(BaseModel):
    """Create a new PDR export channel."""

    name: str = Field(..., min_length=1, max_length=128, description="Display name")
    channel_type: str = Field(..., description="Channel type: s3 | webhook | kafka_mirror")
    config: dict[str, Any] = Field(..., description="Channel-specific config")
    pii_fields: list[str] | None = Field(None, description="PII fields to redact before export")
    enabled: bool = Field(True, description="Whether channel is active")

    @field_validator("channel_type")
    @classmethod
    def validate_channel_type(cls, v: str) -> str:
        if v not in _VALID_CHANNEL_TYPES:
            raise ValueError(f"channel_type must be one of {sorted(_VALID_CHANNEL_TYPES)}")
        return v

class PDRChannelUpdate(BaseModel):
    """Update an existing PDR export channel."""

    name: str | None = Field(None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    pii_fields: list[str] | None = None
    enabled: bool | None = None

class PDRChannelResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    channel_type: str
    config_masked: dict[str, Any]
    pii_fields: list[str] | None
    enabled: bool
    created_at: str
    updated_at: str

class PDRExportRunRequest(BaseModel):
    """Execute an immediate export through an existing channel."""

    lookback_minutes: int = Field(60, ge=1, le=10080)
    event_types: list[str] | None = None
    max_events: int = Field(1000, ge=1, le=10000)

class PDRScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    channel_id: str = Field(..., min_length=1, max_length=128)
    cron_schedule: str = Field(..., min_length=9, max_length=64)
    lookback_minutes: int = Field(60, ge=1, le=10080)
    event_types: list[str] | None = None
    max_events: int = Field(1000, ge=1, le=10000)
    enabled: bool = True

    @field_validator("cron_schedule")
    @classmethod
    def validate_cron_schedule(cls, value: str) -> str:
        if compute_next_cron(value) is None:
            raise ValueError("cron_schedule must be a valid 5-field cron expression")
        return value

class PDRScheduleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    cron_schedule: str | None = Field(None, min_length=9, max_length=64)
    lookback_minutes: int | None = Field(None, ge=1, le=10080)
    event_types: list[str] | None = None
    max_events: int | None = Field(None, ge=1, le=10000)
    enabled: bool | None = None

    @field_validator("cron_schedule")
    @classmethod
    def validate_optional_cron_schedule(cls, value: str | None) -> str | None:
        if value is not None and compute_next_cron(value) is None:
            raise ValueError("cron_schedule must be a valid 5-field cron expression")
        return value

class PDRScheduleResponse(BaseModel):
    id: str
    tenant_id: str
    channel_id: str
    name: str
    cron_schedule: str
    lookback_minutes: int
    event_types: list[str] | None
    max_events: int
    enabled: bool
    next_run_at: str | None
    last_run_at: str | None
    last_run_status: str | None
    last_run_message: str | None
    created_at: str
    updated_at: str

# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/channel-types")
async def get_channel_types():
    """List available PDR export channel types."""
    return {
        "channel_types": [
            {
                "type": "s3",
                "name": "S3 Drops",
                "description": "Gzipped OCSF JSON-L files to an S3 bucket, partitioned by date/tenant",
                "config_fields": ["s3_bucket", "s3_region", "s3_prefix", "s3_iam_role", "access_key", "secret_key"],
            },
            {
                "type": "webhook",
                "name": "Webhook Push",
                "description": "POST OCSF JSON to a webhook URL with HMAC-SHA256 signature",
                "config_fields": ["webhook_url", "webhook_secret", "custom_headers"],
            },
            {
                "type": "kafka_mirror",
                "name": "Kafka Mirror",
                "description": "Mirror OCSF events to a customer Kafka cluster",
                "config_fields": [
                    "kafka_bootstrap",
                    "kafka_topic",
                    "kafka_sasl_mechanism",
                    "kafka_sasl_username",
                    "kafka_sasl_password",
                ],
            },
        ],
        "ocsf_event_types": get_supported_event_types(),
    }

@router.get("/")
async def list_channels(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List all PDR export channels for the current tenant."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    rows = await db.fetch(
        """
        SELECT id, tenant_id, name, channel_type, config, pii_fields,
               enabled, created_at, updated_at
        FROM pdr_channels
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        """,
        tenant_id,
    )

    return {"channels": [_to_response(r) for r in rows]}

@router.post("/", status_code=201)
async def create_channel(
    body: PDRChannelCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create a new PDR export channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    # Validate config for the channel type
    _validate_config(body.channel_type, body.config)

    channel_id = str(uuid.uuid4())

    row = await db.fetchrow(
        """
        INSERT INTO pdr_channels
            (id, tenant_id, name, channel_type, config, pii_fields, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, tenant_id, name, channel_type, config, pii_fields,
                  enabled, created_at, updated_at
        """,
        channel_id,
        tenant_id,
        body.name,
        body.channel_type,
        _json.dumps(body.config),
        _json.dumps(body.pii_fields) if body.pii_fields else None,
        body.enabled,
    )

    logger.info(
        "pdr_channel_created",
        channel_id=channel_id,
        channel_type=body.channel_type,
        tenant_id=str(tenant_id),
    )

    return _to_response(row)

@router.get("/schedules")
async def list_schedules(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List scheduled exports for the current tenant."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    rows = await db.fetch(
        """
        SELECT id, tenant_id, channel_id, name, cron_schedule, lookback_minutes,
               event_types, max_events, enabled, next_run_at, last_run_at,
               last_run_status, last_run_message, created_at, updated_at
        FROM pdr_export_schedules
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    return {"schedules": [_schedule_to_response(r) for r in rows]}

@router.post("/schedules", status_code=201)
async def create_schedule(
    body: PDRScheduleCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create a scheduled export tied to an existing channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    channel = await db.fetchrow(
        "SELECT id, enabled FROM pdr_channels WHERE id = $1 AND tenant_id = $2",
        body.channel_id,
        tenant_id,
    )
    if not channel:
        raise HTTPException(status_code=404, detail="PDR channel not found")

    schedule_id = str(uuid.uuid4())
    next_run_at = compute_next_cron(body.cron_schedule, after=datetime.now(UTC))
    row = await db.fetchrow(
        """
        INSERT INTO pdr_export_schedules (
            id, tenant_id, channel_id, name, cron_schedule, lookback_minutes,
            event_types, max_events, enabled, next_run_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        """,
        schedule_id,
        tenant_id,
        body.channel_id,
        body.name,
        body.cron_schedule,
        body.lookback_minutes,
        _json.dumps(body.event_types) if body.event_types is not None else None,
        body.max_events,
        body.enabled,
        next_run_at,
    )
    logger.info("pdr_schedule_created", schedule_id=schedule_id, tenant_id=str(tenant_id))
    return _schedule_to_response(row)

@router.get("/schedules/{schedule_id}")
async def get_schedule(
    schedule_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get a scheduled export by ID."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM pdr_export_schedules WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        schedule_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled export not found")
    return _schedule_to_response(row)

@router.patch("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: Annotated[str, Path()],
    body: PDRScheduleUpdate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Update a scheduled export."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    existing = await db.fetchrow(
        "SELECT * FROM pdr_export_schedules WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        schedule_id,
        tenant_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Scheduled export not found")

    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.cron_schedule is not None:
        updates["cron_schedule"] = body.cron_schedule
        updates["next_run_at"] = compute_next_cron(body.cron_schedule, after=datetime.now(UTC))
    if body.lookback_minutes is not None:
        updates["lookback_minutes"] = body.lookback_minutes
    if body.event_types is not None:
        updates["event_types"] = _json.dumps(body.event_types)
    if body.max_events is not None:
        updates["max_events"] = body.max_events
    if body.enabled is not None:
        updates["enabled"] = body.enabled

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    allowed = {"name", "cron_schedule", "next_run_at", "lookback_minutes", "event_types", "max_events", "enabled"}
    if not all(key in allowed for key in updates):
        raise HTTPException(status_code=400, detail="Invalid update fields")

    set_clauses = ", ".join(f"{key} = ${i + 3}" for i, key in enumerate(updates.keys()))
    row = await db.fetchrow(
        f"""
        UPDATE pdr_export_schedules
        SET {set_clauses}, updated_at = now()
        WHERE id = $1 AND tenant_id = $2
        RETURNING *
        """,
        schedule_id,
        tenant_id,
        *list(updates.values()),
    )
    return _schedule_to_response(row)

@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Soft-delete a scheduled export."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "UPDATE pdr_export_schedules SET deleted_at = now() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        schedule_id,
        tenant_id,
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Scheduled export not found")

@router.post("/schedules/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Run a scheduled export immediately without waiting for the cron window."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        """
        SELECT s.*, c.channel_type, c.config, c.pii_fields
        FROM pdr_export_schedules s
        JOIN pdr_channels c ON c.id = s.channel_id AND c.tenant_id = s.tenant_id
        WHERE s.id = $1 AND s.tenant_id = $2
        """,
        schedule_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled export not found")

    event_types = row.get("event_types")
    if isinstance(event_types, str):
        try:
            event_types = _json.loads(event_types)
        except (TypeError, ValueError):
            event_types = None
    result = await execute_channel_export(
        tenant_id=str(tenant_id),
        channel_row=dict(row),
        lookback_minutes=int(row.get("lookback_minutes") or 60),
        event_types=event_types,
        max_events=int(row.get("max_events") or 1000),
    )
    return {"success": True, **result}

@router.get("/{channel_id}")
async def get_channel(
    channel_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get a single PDR export channel by ID."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM pdr_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="PDR channel not found")
    return _to_response(row)

@router.patch("/{channel_id}")
async def update_channel(
    channel_id: Annotated[str, Path()],
    body: PDRChannelUpdate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Update an existing PDR export channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    existing = await db.fetchrow(
        "SELECT * FROM pdr_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="PDR channel not found")

    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.pii_fields is not None:
        updates["pii_fields"] = _json.dumps(body.pii_fields)
    if body.config is not None:
        channel_type = existing["channel_type"]
        _validate_config(channel_type, body.config)
        updates["config"] = _json.dumps(body.config)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Allowlist guard — only these columns may appear in SET
    _ALLOWED_UPDATE_COLS = {"name", "enabled", "pii_fields", "config"}
    if not all(k in _ALLOWED_UPDATE_COLS for k in updates):
        raise HTTPException(status_code=400, detail="Invalid update fields")

    set_clauses = ", ".join(f"{k} = ${i + 3}" for i, k in enumerate(updates.keys()))
    values = list(updates.values())

    row = await db.fetchrow(
        f"""
        UPDATE pdr_channels
        SET {set_clauses}, updated_at = now()
        WHERE id = $1 AND tenant_id = $2
        RETURNING *
        """,
        channel_id,
        tenant_id,
        *values,
    )

    logger.info(
        "pdr_channel_updated",
        channel_id=channel_id,
        tenant_id=str(tenant_id),
    )

    return _to_response(row)

@router.delete("/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Delete a PDR export channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "DELETE FROM pdr_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="PDR channel not found")

    logger.info(
        "pdr_channel_deleted",
        channel_id=channel_id,
        tenant_id=str(tenant_id),
    )

@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Test a PDR channel's connectivity (dry-run with a sample OCSF event)."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    row = await db.fetchrow(
        "SELECT * FROM pdr_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="PDR channel not found")

    config = _json.loads(row["config"]) if isinstance(row["config"], str) else (row["config"] or {})
    channel_type = row["channel_type"]

    try:
        from app.services.pdr_service import create_channel as _factory

        ch = _factory(channel_type, config)

        # Send a minimal test event
        test_event = {
            "event_type": "PROCESS_EXEC",
            "timestamp": "2025-01-01T00:00:00Z",
            "agent_id": "test-agent",
            "sensor_id": "test-sensor",
            "data": {"process_name": "phantex-test", "pid": 0},
        }
        result = await ch.export_batch([test_event], str(tenant_id), pii_fields=None)
        await ch.close()

        return {"success": True, "result": result}
    except Exception as exc:
        logger.warning(
            "pdr_channel_test_failed",
            channel_id=channel_id,
            error=str(exc)[:500],
        )
        return {"success": False, "message": "Channel connectivity test failed"}

@router.post("/{channel_id}/run")
async def run_channel_export_now(
    channel_id: Annotated[str, Path()],
    body: PDRExportRunRequest,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Run an on-demand export of recent events through an existing channel."""
    tenant_id = user.tenant_id
    await db.set_tenant(str(tenant_id))

    row = await db.fetchrow(
        "SELECT * FROM pdr_channels WHERE id = $1 AND tenant_id = $2",
        channel_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="PDR channel not found")

    result = await execute_channel_export(
        tenant_id=str(tenant_id),
        channel_row=dict(row),
        lookback_minutes=body.lookback_minutes,
        event_types=body.event_types,
        max_events=body.max_events,
    )
    return {"success": True, **result}

# ── Helpers ──────────────────────────────────────────────────────────────────

_SENSITIVE_CONFIG_FIELDS = {
    "secret_key",
    "access_key",
    "webhook_secret",
    "kafka_sasl_password",
    "s3_iam_role",
}

def _mask_config(config: dict | str | None) -> dict:
    """Mask sensitive fields in channel config for API responses."""
    if config is None:
        return {}

    if isinstance(config, str):
        try:
            config = _json.loads(config)
        except (ValueError, TypeError):
            return {}

    masked: dict[str, Any] = {}
    for key, value in config.items():
        if key.lower() in _SENSITIVE_CONFIG_FIELDS or "secret" in key.lower() or "password" in key.lower():
            masked[key] = "***" if value else ""
        else:
            masked[key] = value
    return masked

def _to_response(row) -> dict:
    """Convert a DB row to an API response dict with masked config."""
    pii_raw = row.get("pii_fields")
    if isinstance(pii_raw, str):
        try:
            pii_fields = _json.loads(pii_raw)
        except (ValueError, TypeError):
            pii_fields = None
    else:
        pii_fields = pii_raw

    return {
        "id": row["id"],
        "tenant_id": str(row["tenant_id"]),
        "name": row["name"],
        "channel_type": row["channel_type"],
        "config_masked": _mask_config(row.get("config")),
        "pii_fields": pii_fields,
        "enabled": row["enabled"],
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }

def _schedule_to_response(row) -> dict:
    event_types = row.get("event_types")
    if isinstance(event_types, str):
        try:
            event_types = _json.loads(event_types)
        except (TypeError, ValueError):
            event_types = None

    return {
        "id": row["id"],
        "tenant_id": str(row["tenant_id"]),
        "channel_id": row["channel_id"],
        "name": row["name"],
        "cron_schedule": row["cron_schedule"],
        "lookback_minutes": row["lookback_minutes"],
        "event_types": event_types,
        "max_events": row["max_events"],
        "enabled": row["enabled"],
        "next_run_at": str(row["next_run_at"]) if row.get("next_run_at") else None,
        "last_run_at": str(row["last_run_at"]) if row.get("last_run_at") else None,
        "last_run_status": row.get("last_run_status"),
        "last_run_message": row.get("last_run_message"),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }

def _validate_webhook_host(hostname: str) -> None:
    """Block webhook URLs that resolve to private/internal IPs (SSRF protection).

    Delegates to the canonical implementation in pdr_service and converts
    ValueError → HTTPException so the router speaks the right error type.
    """
    from app.services.pdr_service import _validate_webhook_host as _svc_validate

    try:
        _svc_validate(hostname)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

def _validate_config(channel_type: str, config: dict[str, Any]) -> None:
    """Validate that the config dict has the minimum required fields for the channel type."""
    if channel_type == "s3":
        if not config.get("s3_bucket"):
            raise HTTPException(status_code=400, detail="s3_bucket is required for S3 channels")
    elif channel_type == "webhook":
        url = config.get("webhook_url", "")
        if not url:
            raise HTTPException(status_code=400, detail="webhook_url is required for webhook channels")
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise HTTPException(status_code=400, detail="webhook_url must use HTTPS")
        if parsed.hostname:
            _validate_webhook_host(parsed.hostname)
    elif channel_type == "kafka_mirror" and not config.get("kafka_bootstrap"):
        raise HTTPException(
            status_code=400,
            detail="kafka_bootstrap is required for Kafka mirror channels",
        )
