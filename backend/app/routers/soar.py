# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SOAR Bidirectional API Router

Endpoints are split into two auth domains:

1. **User-JWT endpoints** (admin manages SOAR config):
   /api/v1/soar/api-keys/*     — CRUD for SOAR API keys
   /api/v1/soar/webhooks/*     — CRUD for outbound webhook subscriptions
   /api/v1/soar/integrations/* — CRUD for SOAR platform integrations

2. **API-Key endpoints** (SOAR platforms call):
   /api/v1/soar/ext/alerts     — Query alerts (read access)
   /api/v1/soar/ext/alerts/{id}/enrich  — Full enrichment for a single alert
   /api/v1/soar/ext/actions    — Execute response actions
   /api/v1/soar/ext/action-log — Audit trail of executed actions

Security:
  - RLS tenant isolation on every query
  - Scope-based authorization on API key endpoints
  - audit_service.log_action for all write operations
  - Rate limiting (shared)
  - Input validation via Pydantic schemas
  - SHA-256 hashed API key storage (raw key shown once)
  - Secrets masked in webhook responses (never returned)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.soar_auth import SOARIdentity, generate_api_key, get_soar_identity
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.schemas.soar import (
    AlertEnrichmentResponse,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    CreateApiKeyRequest,
    CreateIntegrationRequest,
    CreateWebhookRequest,
    IntegrationResponse,
    SOARActionLogResponse,
    SOARActionRequest,
    SOARActionResponse,
    UpdateIntegrationRequest,
    UpdateWebhookRequest,
    WebhookLogEntry,
    WebhookLogResponse,
    WebhookResponse,
)
from app.services import audit_service
from app.services.soar.webhook_service import WebhookDeliveryService

logger = structlog.get_logger("phantex.soar.router")

# ── User-facing router (admin manages SOAR config via JWT) ────────────────────

router = APIRouter(
    prefix="/api/v1/soar",
    tags=["soar"],
    dependencies=[Depends(rate_limit)],
)

# ═══════════════════════════════════════════════════════════════════════════════
#  API KEY MANAGEMENT  (requires soar.manage permission)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/api-keys",
    response_model=ApiKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create SOAR API key",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def create_api_key(
    body: CreateApiKeyRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Create a new API key for SOAR integration. The raw key is returned ONCE."""
    raw_key, key_hash, key_prefix = generate_api_key()

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    result = await db.execute(
        text("""
            INSERT INTO soar_api_keys
                (tenant_id, name, key_hash, key_prefix, scopes, expires_at, created_by)
            VALUES
                (CAST(:tid AS UUID), :name, :hash, :prefix, :scopes,
                 :exp, CAST(:uid AS UUID))
            RETURNING id, tenant_id, name, key_prefix, scopes,
                      expires_at, last_used_at, created_at, revoked_at
        """),
        {
            "tid": str(current_user.tenant_id),
            "name": body.name,
            "hash": key_hash,
            "prefix": key_prefix,
            "scopes": body.scopes,
            "exp": expires_at,
            "uid": str(current_user.user_id),
        },
    )
    row = result.mappings().first()
    await db.commit()

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="soar.api_key.created",
        resource_type="soar_api_key",
        resource_id=row["id"],
        details={"name": body.name, "scopes": body.scopes, "prefix": key_prefix},
    )
    await db.commit()

    return ApiKeyCreatedResponse(
        id=row["id"],
        name=row["name"],
        key_prefix=row["key_prefix"],
        scopes=row["scopes"],
        expires_at=row["expires_at"],
        last_used_at=row["last_used_at"],
        created_at=row["created_at"],
        revoked=row["revoked_at"] is not None,
        raw_key=raw_key,
    )

@router.get(
    "/api-keys",
    response_model=list[ApiKeyResponse],
    summary="List SOAR API keys",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def list_api_keys(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """List all API keys for the current tenant (secrets are never returned)."""
    result = await db.execute(
        text("""
            SELECT id, name, key_prefix, scopes, expires_at,
                   last_used_at, created_at, revoked_at
            FROM soar_api_keys
            WHERE tenant_id = CAST(:tid AS UUID)
            ORDER BY created_at DESC
        """),
        {"tid": str(current_user.tenant_id)},
    )
    return [
        ApiKeyResponse(
            id=r["id"],
            name=r["name"],
            key_prefix=r["key_prefix"],
            scopes=r["scopes"],
            expires_at=r["expires_at"],
            last_used_at=r["last_used_at"],
            created_at=r["created_at"],
            revoked=r["revoked_at"] is not None,
        )
        for r in result.mappings().all()
    ]

@router.delete(
    "/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke SOAR API key",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def revoke_api_key(
    key_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Revoke an API key (soft-delete — keeps audit trail)."""
    result = await db.execute(
        text("""
            UPDATE soar_api_keys
            SET revoked_at = now()
            WHERE id = CAST(:kid AS UUID)
              AND tenant_id = CAST(:tid AS UUID)
              AND revoked_at IS NULL
            RETURNING id
        """),
        {"kid": str(key_id), "tid": str(current_user.tenant_id)},
    )
    if not result.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found or already revoked")

    await db.commit()

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="soar.api_key.revoked",
        resource_type="soar_api_key",
        resource_id=key_id,
    )
    await db.commit()

# ═══════════════════════════════════════════════════════════════════════════════
#  WEBHOOK SUBSCRIPTION MANAGEMENT  (requires soar.manage)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/webhooks",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create webhook subscription",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def create_webhook(
    body: CreateWebhookRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Create a new outbound webhook subscription for SOAR event delivery."""
    result = await db.execute(
        text("""
            INSERT INTO soar_webhook_subs
                (tenant_id, name, url, secret, event_types, severity_filter,
                 retry_count, retry_delay_sec, timeout_sec, created_by)
            VALUES
                (CAST(:tid AS UUID), :name, :url, :secret, :events, :sev,
                 :retry, :delay, :timeout, CAST(:uid AS UUID))
            RETURNING id, name, url, event_types, severity_filter, enabled,
                      retry_count, retry_delay_sec, timeout_sec,
                      created_at, updated_at
        """),
        {
            "tid": str(current_user.tenant_id),
            "name": body.name,
            "url": body.url,
            "secret": body.secret,
            "events": body.event_types,
            "sev": body.severity_filter,
            "retry": body.retry_count,
            "delay": body.retry_delay_sec,
            "timeout": body.timeout_sec,
            "uid": str(current_user.user_id),
        },
    )
    row = result.mappings().first()
    await db.commit()

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="soar.webhook.created",
        resource_type="soar_webhook",
        resource_id=row["id"],
        details={"name": body.name, "url": body.url, "events": body.event_types},
    )
    await db.commit()

    return _webhook_row_to_response(row)

@router.get(
    "/webhooks",
    response_model=list[WebhookResponse],
    summary="List webhook subscriptions",
    dependencies=[Depends(require_permission("soar.view"))],
)
async def list_webhooks(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    result = await db.execute(
        text("""
            SELECT id, name, url, event_types, severity_filter, enabled,
                   retry_count, retry_delay_sec, timeout_sec,
                   created_at, updated_at
            FROM soar_webhook_subs
            WHERE tenant_id = CAST(:tid AS UUID)
              AND deleted_at IS NULL
            ORDER BY created_at DESC
        """),
        {"tid": str(current_user.tenant_id)},
    )
    return [_webhook_row_to_response(r) for r in result.mappings().all()]

@router.patch(
    "/webhooks/{webhook_id}",
    response_model=WebhookResponse,
    summary="Update webhook subscription",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def update_webhook(
    webhook_id: uuid.UUID,
    body: UpdateWebhookRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Update a webhook subscription's config."""
    # Build SET clause dynamically (only non-null fields)
    _WEBHOOK_ALLOWED_COLS = frozenset({
        "name", "url", "secret", "event_types", "severity_filter",
        "enabled", "retry_count", "retry_delay_sec", "timeout_sec",
    })
    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.url is not None:
        updates["url"] = body.url
    if body.secret is not None:
        updates["secret"] = body.secret
    if body.event_types is not None:
        updates["event_types"] = body.event_types
    if body.severity_filter is not None:
        updates["severity_filter"] = body.severity_filter
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.retry_count is not None:
        updates["retry_count"] = body.retry_count
    if body.retry_delay_sec is not None:
        updates["retry_delay_sec"] = body.retry_delay_sec
    if body.timeout_sec is not None:
        updates["timeout_sec"] = body.timeout_sec

    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    set_clauses = []
    params: dict[str, Any] = {
        "wid": str(webhook_id),
        "tid": str(current_user.tenant_id),
    }
    for i, (col, val) in enumerate(updates.items()):
        if col not in _WEBHOOK_ALLOWED_COLS:
            raise HTTPException(status_code=400, detail=f"Invalid field: {col}")
        param_name = f"v{i}"
        set_clauses.append(f"{col} = :{param_name}")
        params[param_name] = val
    set_clauses.append("updated_at = now()")
    set_sql = ", ".join(set_clauses)

    result = await db.execute(
        text(f"""
            UPDATE soar_webhook_subs
            SET {set_sql}
            WHERE id = CAST(:wid AS UUID)
              AND tenant_id = CAST(:tid AS UUID)
            RETURNING id, name, url, event_types, severity_filter, enabled,
                      retry_count, retry_delay_sec, timeout_sec,
                      created_at, updated_at
        """),
        params,
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    await db.commit()
    return _webhook_row_to_response(row)

@router.delete(
    "/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete webhook subscription",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def delete_webhook(
    webhook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    result = await db.execute(
        text("""
            UPDATE soar_webhook_subs
            SET deleted_at = now()
            WHERE id = CAST(:wid AS UUID)
              AND tenant_id = CAST(:tid AS UUID)
              AND deleted_at IS NULL
            RETURNING id
        """),
        {"wid": str(webhook_id), "tid": str(current_user.tenant_id)},
    )
    if not result.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    await db.commit()

@router.post(
    "/webhooks/{webhook_id}/test",
    summary="Test webhook delivery",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def test_webhook(
    webhook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Send a test event to verify webhook connectivity."""
    result = await db.execute(
        text("""
            SELECT url, secret
            FROM soar_webhook_subs
            WHERE id = CAST(:wid AS UUID)
              AND tenant_id = CAST(:tid AS UUID)
        """),
        {"wid": str(webhook_id), "tid": str(current_user.tenant_id)},
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    svc = WebhookDeliveryService(db)
    try:
        test_result = await svc.test_webhook(row["url"], row["secret"])
    except Exception as exc:
        logger.warning("webhook_test_failed", error=str(exc), webhook_id=str(webhook_id))
        return {"success": False, "message": "Webhook test failed"}
    return test_result

@router.get(
    "/webhooks/{webhook_id}/logs",
    response_model=WebhookLogResponse,
    summary="Get webhook delivery logs",
    dependencies=[Depends(require_permission("soar.view"))],
)
async def get_webhook_logs(
    webhook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Get delivery logs for a webhook subscription (most recent first)."""
    # Verify ownership
    ownership = await db.execute(
        text("""
            SELECT 1 FROM soar_webhook_subs
            WHERE id = CAST(:wid AS UUID)
              AND tenant_id = CAST(:tid AS UUID)
        """),
        {"wid": str(webhook_id), "tid": str(current_user.tenant_id)},
    )
    if not ownership.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    count_result = await db.execute(
        text("SELECT COUNT(*) FROM soar_webhook_logs WHERE subscription_id = CAST(:wid AS UUID)"),
        {"wid": str(webhook_id)},
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        text("""
            SELECT id, subscription_id, event_type, event_id,
                   status_code, response_ms, attempt, success, error, created_at
            FROM soar_webhook_logs
            WHERE subscription_id = CAST(:wid AS UUID)
            ORDER BY created_at DESC
            LIMIT :lim OFFSET :off
        """),
        {"wid": str(webhook_id), "lim": limit, "off": offset},
    )
    entries = [
        WebhookLogEntry(
            id=r["id"],
            subscription_id=r["subscription_id"],
            event_type=r["event_type"],
            event_id=r["event_id"],
            status_code=r["status_code"],
            response_ms=r["response_ms"],
            attempt=r["attempt"],
            success=r["success"],
            error=r["error"],
            created_at=r["created_at"],
        )
        for r in result.mappings().all()
    ]
    return WebhookLogResponse(total=total, entries=entries)

# ═══════════════════════════════════════════════════════════════════════════════
#  INTEGRATION MANAGEMENT  (requires soar.manage)
# ═══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/integrations",
    response_model=IntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create SOAR integration",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def create_integration(
    body: CreateIntegrationRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Register a SOAR platform integration (xsoar, phantom, tines, generic)."""
    result = await db.execute(
        text("""
            INSERT INTO soar_integrations
                (tenant_id, platform, name, config, enabled, created_by)
            VALUES
                (CAST(:tid AS UUID), :platform, :name,
                 CAST(:config AS JSONB), :enabled, CAST(:uid AS UUID))
            RETURNING id, platform, name, config, enabled,
                      last_sync_at, last_error, created_at, updated_at
        """),
        {
            "tid": str(current_user.tenant_id),
            "platform": body.platform,
            "name": body.name,
            "config": _jsonb(body.config),
            "enabled": body.enabled,
            "uid": str(current_user.user_id),
        },
    )
    row = result.mappings().first()
    await db.commit()

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="soar.integration.created",
        resource_type="soar_integration",
        resource_id=row["id"],
        details={"platform": body.platform, "name": body.name},
    )
    await db.commit()

    return _integration_row_to_response(row)

@router.get(
    "/integrations",
    response_model=list[IntegrationResponse],
    summary="List SOAR integrations",
    dependencies=[Depends(require_permission("soar.view"))],
)
async def list_integrations(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    result = await db.execute(
        text("""
            SELECT id, platform, name, config, enabled,
                   last_sync_at, last_error, created_at, updated_at
            FROM soar_integrations
            WHERE tenant_id = CAST(:tid AS UUID)
              AND deleted_at IS NULL
            ORDER BY created_at DESC
        """),
        {"tid": str(current_user.tenant_id)},
    )
    return [_integration_row_to_response(r) for r in result.mappings().all()]

@router.patch(
    "/integrations/{integration_id}",
    response_model=IntegrationResponse,
    summary="Update SOAR integration",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def update_integration(
    integration_id: uuid.UUID,
    body: UpdateIntegrationRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    _INTEGRATION_ALLOWED_COLS = {"name", "config", "enabled"}

    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.config is not None:
        updates["config"] = _jsonb(body.config)
    if body.enabled is not None:
        updates["enabled"] = body.enabled

    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    set_clauses = []
    params: dict[str, Any] = {
        "iid": str(integration_id),
        "tid": str(current_user.tenant_id),
    }
    for i, (col, val) in enumerate(updates.items()):
        if col not in _INTEGRATION_ALLOWED_COLS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid field: {col}")
        pn = f"v{i}"
        if col == "config":
            set_clauses.append(f"config = CAST(:{pn} AS JSONB)")
        else:
            set_clauses.append(f"{col} = :{pn}")
        params[pn] = val
    set_clauses.append("updated_at = now()")
    set_sql = ", ".join(set_clauses)

    result = await db.execute(
        text(f"""
            UPDATE soar_integrations
            SET {set_sql}
            WHERE id = CAST(:iid AS UUID)
              AND tenant_id = CAST(:tid AS UUID)
            RETURNING id, platform, name, config, enabled,
                      last_sync_at, last_error, created_at, updated_at
        """),
        params,
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")

    await db.commit()
    return _integration_row_to_response(row)

@router.delete(
    "/integrations/{integration_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete SOAR integration",
    dependencies=[Depends(require_permission("soar.manage"))],
)
async def delete_integration(
    integration_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    result = await db.execute(
        text("""
            UPDATE soar_integrations
            SET deleted_at = now()
            WHERE id = CAST(:iid AS UUID) AND tenant_id = CAST(:tid AS UUID)
              AND deleted_at IS NULL
            RETURNING id
        """),
        {"iid": str(integration_id), "tid": str(current_user.tenant_id)},
    )
    if not result.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    await db.commit()

# ═══════════════════════════════════════════════════════════════════════════════
#  EXTERNAL API  (SOAR platforms call via API key)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/ext/alerts",
    summary="Query alerts (API key)",
)
async def ext_list_alerts(
    identity: Annotated[SOARIdentity, Depends(get_soar_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
    alert_status: str | None = Query(None, alias="status"),
    severity: str | None = None,
    since: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    Query alerts for SOAR ingestion.
    Requires API key scope: alerts.read
    """
    identity.require_scope("alerts.read")

    conditions = ["tenant_id = CAST(:tid AS UUID)"]
    params: dict[str, Any] = {"tid": str(identity.tenant_id), "lim": limit, "off": offset}

    _VALID_STATUSES = frozenset({"open", "acknowledged", "resolved", "false_positive"})
    _VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical", "info"})
    if alert_status:
        if alert_status not in _VALID_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status filter")
        conditions.append("status = :st")
        params["st"] = alert_status
    if severity:
        if severity not in _VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail="Invalid severity filter")
        conditions.append("severity = :sev")
        params["sev"] = severity
    if since:
        conditions.append("created_at >= :since")
        params["since"] = since

    where = " AND ".join(conditions)

    count_result = await db.execute(text(f"SELECT COUNT(*) FROM alerts WHERE {where}"), params)
    total = count_result.scalar() or 0

    result = await db.execute(
        text(f"""
            SELECT id, title, severity, status, description,
                   agent_id, rule_id, context, created_at, updated_at
            FROM alerts
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT :lim OFFSET :off
        """),
        params,
    )

    rows = result.mappings().all()
    alerts = []
    for r in rows:
        a = dict(r)
        # Convert UUIDs to strings for JSON serialization
        for k in ("id", "agent_id", "rule_id"):
            if a.get(k) is not None:
                a[k] = str(a[k])
        alerts.append(a)

    return {
        "total": total,
        "alerts": alerts,
    }

@router.get(
    "/ext/alerts/{alert_id}/enrich",
    response_model=AlertEnrichmentResponse,
    summary="Get alert enrichment (API key)",
)
async def ext_enrich_alert(
    alert_id: uuid.UUID,
    identity: Annotated[SOARIdentity, Depends(get_soar_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Full enrichment for a single alert — metadata, agent context,
    timeline of related events, and similar alerts.
    Requires API key scope: enrichment.read
    """
    identity.require_scope("enrichment.read")

    # Core alert data
    result = await db.execute(
        text("""
            SELECT a.id, a.severity, a.status, a.title, a.description,
                   a.agent_id, a.rule_id, a.context, a.created_at, a.updated_at
            FROM alerts a
            WHERE a.id = CAST(:aid AS UUID)
              AND a.tenant_id = CAST(:tid AS UUID)
        """),
        {"aid": str(alert_id), "tid": str(identity.tenant_id)},
    )
    alert = result.mappings().first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # Agent context
    agent_hostname = None
    agent_trust_score = None
    if alert["agent_id"]:
        agent_result = await db.execute(
            text("""
                SELECT name, host_id, metadata
                FROM agents
                WHERE paid = :aid AND tenant_id = CAST(:tid AS UUID)
            """),
            {"aid": str(alert["agent_id"]), "tid": str(identity.tenant_id)},
        )
        agent_row = agent_result.mappings().first()
        if agent_row:
            agent_hostname = agent_row["name"] or agent_row["host_id"]
            # Trust score may be in metadata
            meta = agent_row.get("metadata") or {}
            if isinstance(meta, dict):
                agent_trust_score = meta.get("trust_score")

    # Timeline — recent alerts from same agent (related context)
    timeline: list[dict[str, Any]] = []
    if alert["agent_id"]:
        tl_result = await db.execute(
            text("""
                SELECT id, title, severity, created_at
                FROM alerts
                WHERE agent_id = :aid
                  AND tenant_id = CAST(:tid AS UUID)
                  AND id != CAST(:self_id AS UUID)
                ORDER BY created_at DESC
                LIMIT 10
            """),
            {
                "aid": str(alert["agent_id"]),
                "tid": str(identity.tenant_id),
                "self_id": str(alert_id),
            },
        )
        for r in tl_result.mappings().all():
            timeline.append(
                {"id": str(r["id"]), "title": r["title"], "severity": r["severity"], "created_at": str(r["created_at"])}
            )

    # Related alerts — same severity in last 24 hours
    related: list[dict[str, Any]] = []
    rel_result = await db.execute(
        text("""
            SELECT id, title, severity, agent_id, created_at
            FROM alerts
            WHERE severity = :sev
              AND tenant_id = CAST(:tid AS UUID)
              AND id != CAST(:self_id AS UUID)
              AND created_at > now() - interval '24 hours'
            ORDER BY created_at DESC
            LIMIT 10
        """),
        {
            "sev": alert["severity"],
            "tid": str(identity.tenant_id),
            "self_id": str(alert_id),
        },
    )
    for r in rel_result.mappings().all():
        related.append(
            {
                "id": str(r["id"]),
                "title": r["title"],
                "severity": r["severity"],
                "agent_id": str(r["agent_id"]) if r["agent_id"] else None,
                "created_at": str(r["created_at"]),
            }
        )

    # Extract ATLAS mapping from context if available
    atlas_mapping = None
    ctx = alert.get("context") or {}
    if isinstance(ctx, dict):
        atlas_mapping = ctx.get("atlas_mapping")

    return AlertEnrichmentResponse(
        alert_id=alert["id"],
        severity=alert["severity"],
        status=alert["status"],
        rule_name=alert["title"],
        event_type=ctx.get("event_type") if isinstance(ctx, dict) else None,
        agent_id=alert["agent_id"],
        agent_hostname=agent_hostname,
        agent_trust_score=agent_trust_score,
        atlas_mapping=atlas_mapping,
        timeline=timeline,
        related_alerts=related,
    )

@router.post(
    "/ext/actions",
    response_model=SOARActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute response action (API key)",
)
async def ext_execute_action(
    body: SOARActionRequest,
    identity: Annotated[SOARIdentity, Depends(get_soar_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Execute a response action on behalf of a SOAR platform.
    Requires API key scope: actions.execute

    The action is validated, logged in the immutable soar_action_log,
    and dispatched to the appropriate enforcement subsystem.
    """
    identity.require_scope("actions.execute")

    # Dispatch the action
    result_str = "success"
    error_str: str | None = None

    try:
        await _dispatch_soar_action(
            db,
            tenant_id=identity.tenant_id,
            action=body.action,
            target_type=body.target_type,
            target_id=body.target_id,
            params=body.params,
            reason=body.reason,
            api_key_id=identity.key_id,
            source_ip=identity.source_ip,
        )
    except HTTPException:
        raise
    except Exception as exc:
        result_str = "error"
        error_str = str(exc)[:500]
        logger.error(
            "soar_action_dispatch_error",
            action=body.action,
            target_id=str(body.target_id),
            error=str(exc),
        )

    # Log to immutable soar_action_log
    log_result = await db.execute(
        text("""
            INSERT INTO soar_action_log
                (tenant_id, api_key_id, action, target_type, target_id,
                 params, reason, result, error, source_ip, user_agent)
            VALUES
                (CAST(:tid AS UUID), CAST(:kid AS UUID), :action, :ttype,
                 CAST(:target AS UUID), CAST(:params AS JSONB),
                 :reason, :result, :err, :ip, :ua)
            RETURNING id, action, target_type, target_id, result, error, created_at
        """),
        {
            "tid": str(identity.tenant_id),
            "kid": str(identity.key_id),
            "action": body.action,
            "ttype": body.target_type,
            "target": str(body.target_id),
            "params": _jsonb(body.params),
            "reason": body.reason,
            "result": result_str,
            "err": error_str,
            "ip": identity.source_ip,
            "ua": identity.user_agent,
        },
    )
    row = log_result.mappings().first()
    await db.commit()

    # Fire webhook for action.executed event
    try:
        svc = WebhookDeliveryService(db)
        await svc.deliver_event(
            "action.executed",
            {
                "action_id": str(row["id"]),
                "action": body.action,
                "target_type": body.target_type,
                "target_id": str(body.target_id),
                "result": result_str,
                "triggered_by": "soar_api",
                "api_key_name": identity.name,
            },
            identity.tenant_id,
            event_id=row["id"],
        )
    except Exception as exc:
        logger.warning("soar_action_webhook_delivery_failed", error=str(exc))

    return SOARActionResponse(
        id=row["id"],
        action=row["action"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        result=row["result"],
        error=row["error"],
        created_at=row["created_at"],
    )

@router.get(
    "/ext/action-log",
    response_model=SOARActionLogResponse,
    summary="Get action audit log (API key)",
)
async def ext_action_log(
    identity: Annotated[SOARIdentity, Depends(get_soar_identity)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    Get the audit trail of SOAR-initiated actions.
    Requires API key scope: alerts.read
    """
    identity.require_scope("alerts.read")

    count_result = await db.execute(
        text("SELECT COUNT(*) FROM soar_action_log WHERE tenant_id = CAST(:tid AS UUID)"),
        {"tid": str(identity.tenant_id)},
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        text("""
            SELECT id, action, target_type, target_id, result, error, created_at
            FROM soar_action_log
            WHERE tenant_id = CAST(:tid AS UUID)
            ORDER BY created_at DESC
            LIMIT :lim OFFSET :off
        """),
        {"tid": str(identity.tenant_id), "lim": limit, "off": offset},
    )
    entries = [
        SOARActionResponse(
            id=r["id"],
            action=r["action"],
            target_type=r["target_type"],
            target_id=r["target_id"],
            result=r["result"],
            error=r["error"],
            created_at=r["created_at"],
        )
        for r in result.mappings().all()
    ]

    return SOARActionLogResponse(total=total, entries=entries)

# ─── Admin-facing action log (JWT, not API key) ──────────────────────────────

@router.get(
    "/action-log-admin",
    response_model=list[SOARActionResponse],
    summary="Get action audit log (admin JWT)",
    dependencies=[Depends(require_permission("soar.view"))],
)
async def admin_action_log(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Admin-facing action log for the dashboard. Uses standard JWT auth.
    """
    result = await db.execute(
        text("""
            SELECT id, action, target_type, target_id, result, error, created_at
            FROM soar_action_log
            WHERE tenant_id = CAST(:tid AS UUID)
            ORDER BY created_at DESC
            LIMIT :lim OFFSET :off
        """),
        {"tid": str(user.tenant_id), "lim": limit, "off": offset},
    )
    return [
        SOARActionResponse(
            id=r["id"],
            action=r["action"],
            target_type=r["target_type"],
            target_id=r["target_id"],
            result=r["result"],
            error=r["error"],
            created_at=r["created_at"],
        )
        for r in result.mappings().all()
    ]

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _webhook_row_to_response(row: Any) -> WebhookResponse:
    """Convert a DB row to WebhookResponse (secrets are never returned)."""
    return WebhookResponse(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        event_types=row["event_types"],
        severity_filter=row["severity_filter"],
        enabled=row["enabled"],
        retry_count=row["retry_count"],
        retry_delay_sec=row["retry_delay_sec"],
        timeout_sec=row["timeout_sec"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )

def _integration_row_to_response(row: Any) -> IntegrationResponse:
    """Convert a DB row to IntegrationResponse with secrets masked."""
    config = dict(row["config"]) if row["config"] else {}
    # Mask any secret fields in config
    for key in list(config.keys()):
        if any(s in key.lower() for s in ("secret", "password", "token", "key", "credential")):
            config[key] = "********"
    return IntegrationResponse(
        id=row["id"],
        platform=row["platform"],
        name=row["name"],
        config=config,
        enabled=row["enabled"],
        last_sync_at=row["last_sync_at"],
        last_error=row["last_error"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )

import json as _json

def _jsonb(obj: Any) -> str:
    """Serialize to JSONB-compatible string."""
    return _json.dumps(obj, default=str)

async def _dispatch_soar_action(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: str,
    target_type: str,
    target_id: uuid.UUID,
    params: dict[str, Any],
    reason: str,
    api_key_id: uuid.UUID,
    source_ip: str | None,
) -> None:
    """
    Route a SOAR-initiated action to the correct enforcement backend.

    Re-uses the existing response dispatcher infrastructure but bypasses
    policy matching (the SOAR platform IS the policy decision point).
    """
    from app.services.response.policy_engine import ALLOWED_ACTIONS

    if action not in ALLOWED_ACTIONS and action not in {
        "dismiss_alert",
        "acknowledge_alert",
        "resolve_alert",
        "escalate_alert",
        "add_tag",
        "create_rule",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown action: {action}",
        )

    # Alert-targeted actions
    if target_type == "alert":
        if action in ("acknowledge_alert", "resolve_alert", "dismiss_alert"):
            new_status = {
                "acknowledge_alert": "acknowledged",
                "resolve_alert": "resolved",
                "dismiss_alert": "false_positive",
            }[action]
            result = await db.execute(
                text("""
                    UPDATE alerts
                    SET status = :st, updated_at = now()
                    WHERE id = CAST(:aid AS UUID)
                      AND tenant_id = CAST(:tid AS UUID)
                    RETURNING id
                """),
                {"st": new_status, "aid": str(target_id), "tid": str(tenant_id)},
            )
            if not result.first():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
            return

        if action == "escalate_alert":
            result = await db.execute(
                text("""
                    UPDATE alerts
                    SET severity = 'critical', updated_at = now()
                    WHERE id = CAST(:aid AS UUID)
                      AND tenant_id = CAST(:tid AS UUID)
                    RETURNING id
                """),
                {"aid": str(target_id), "tid": str(tenant_id)},
            )
            if not result.first():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
            return

    # Agent-targeted actions
    if target_type == "agent":
        if action == "isolate_agent":
            try:
                from app.services.agent_command_service import queue_command

                await queue_command(
                    db,
                    tenant_id=tenant_id,
                    agent_id=str(target_id),
                    alert_id=None,
                    action="isolate_agent",
                    parameters=params,
                    issued_by=None,
                    reason=f"SOAR action via API key {api_key_id}: {reason}",
                )
            except Exception as exc:
                logger.error("soar_agent_dispatch_failed", error=str(exc), agent_id=str(target_id))
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Agent command dispatch failed",
                )
            return

        if action == "trust_penalty":
            try:
                from app.services.trust_client import get_trust_client

                client = get_trust_client()
                await client.update_event(
                    tenant_id=str(tenant_id),
                    source_id=str(target_id),
                    source_type="agent",
                    target_id=str(target_id),
                    target_type="agent",
                    event_type="trust_penalty",
                    severity="critical",
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Trust penalty failed: {str(exc)[:200]}",
                )
            return

        if action == "collect_forensics":
            try:
                from app.services.agent_command_service import queue_command

                await queue_command(
                    db,
                    tenant_id=tenant_id,
                    agent_id=str(target_id),
                    alert_id=None,
                    action="collect_forensics",
                    parameters=params,
                    issued_by=None,
                    reason=f"SOAR forensics via API key {api_key_id}: {reason}",
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Forensics dispatch failed: {str(exc)[:200]}",
                )
            return

    # Catch-all for unhandled combinations
    logger.warning(
        "soar_action_no_handler",
        action=action,
        target_type=target_type,
        target_id=str(target_id),
    )
