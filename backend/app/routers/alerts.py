# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Alerts Router.

GET   /api/v1/alerts               — List alerts (paginated, filterable)
GET   /api/v1/alerts/{id}          — Get alert details
PATCH /api/v1/alerts/{id}          — Update alert status (acknowledge/resolve)
POST  /api/v1/alerts/{id}/actions  — Execute response action (isolate, block, quarantine)
POST  /api/v1/alerts/bulk-acknowledge — Acknowledge all open alerts in one call
"""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.alert import AlertFilter, AlertResponse, AlertSummary, AlertUpdate
from app.schemas.auth import CurrentUser
from app.schemas.common import CursorPage
from app.services import agent_command_service, alert_service, audit_service
from app.utils.validators import validate_agent_id

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"], dependencies=[Depends(rate_limit)])

@router.get(
    "",
    response_model=CursorPage[AlertSummary],
    summary="List alerts",
)
async def list_alerts(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    alert_status: str | None = Query(None, alias="status"),
    severity: str | None = None,
    agent_id: str | None = Query(None, max_length=128),
    since: datetime | None = None,
    search: str | None = Query(None, max_length=200, description="Keyword search in title/description"),
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=100),
):
    """List security alerts for the current tenant."""
    if agent_id:
        validate_agent_id(agent_id)
    filters = AlertFilter(
        status=alert_status,
        severity=severity,
        agent_id=agent_id,
        since=since,
        search=search,
    )
    page = await alert_service.list_alerts(db, filters, cursor=cursor, limit=limit)

    return CursorPage(
        items=[AlertSummary.model_validate(a) for a in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )

@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert details",
)
async def get_alert(
    alert_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get full details of a specific alert."""
    alert = await alert_service.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert

@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert status",
    dependencies=[Depends(require_permission("alerts.acknowledge"))],
)
async def update_alert(
    alert_id: uuid.UUID,
    body: AlertUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Update an alert's status (acknowledge, resolve, mark false positive).
    Requires admin or analyst role.
    """
    alert = await alert_service.update_alert(db, alert_id, body, user_id=current_user.user_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # Audit log
    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action=f"alert.{body.status}",
        resource_type="alert",
        resource_id=alert_id,
        details={"new_status": body.status},
    )

    return alert

@router.post(
    "/bulk-acknowledge",
    summary="Acknowledge all open alerts",
    dependencies=[Depends(require_permission("alerts.acknowledge"))],
)
async def bulk_acknowledge(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Acknowledge every open alert for the current tenant in a single
    UPDATE statement.  Returns {"acknowledged": <count>}.
    """
    count = await alert_service.bulk_acknowledge(db, user_id=current_user.user_id)

    if count > 0:
        await audit_service.log_action(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            action="alert.bulk_acknowledge",
            resource_type="alert",
            resource_id=None,
            details={"count": count},
        )

    return {"acknowledged": count}

class BulkUpdateRequest(BaseModel):
    """Bulk update status for a set of alerts."""

    alert_ids: list[str] = Field(..., min_length=1, max_length=500)
    status: Literal["acknowledged", "resolved", "false_positive"]

@router.post(
    "/bulk-update",
    summary="Bulk update status for selected alerts",
    dependencies=[Depends(require_permission("alerts.acknowledge"))],
)
async def bulk_update_status(
    body: BulkUpdateRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Update status for a set of alert IDs at once
    (e.g., mark 10 selected alerts as acknowledged).
    """
    from sqlalchemy import text as sa_text

    valid_ids = []
    invalid_ids = []
    for aid in body.alert_ids:
        try:
            uuid.UUID(aid)
            valid_ids.append(aid)
        except ValueError:
            invalid_ids.append(aid)

    if not valid_ids:
        return {"updated": 0, "invalid_ids": invalid_ids[:10]}

    # Build dynamic placeholders for individual UUIDs (asyncpg-safe)
    placeholders = ", ".join(f":id_{i}" for i in range(len(valid_ids)))
    params = {
        "status": body.status,
        "uid": str(current_user.user_id),
        "tid": str(current_user.tenant_id),
    }
    for i, aid in enumerate(valid_ids):
        params[f"id_{i}"] = aid

    # Defense-in-depth: explicit tenant_id check alongside RLS
    result = await db.execute(
        sa_text(f"""
            UPDATE alerts
            SET status = :status,
                updated_at = now(),
                resolved_by = CASE WHEN :status IN ('resolved', 'false_positive') THEN CAST(:uid AS uuid) ELSE resolved_by END,
                resolved_at = CASE WHEN :status IN ('resolved', 'false_positive') THEN now() ELSE resolved_at END
            WHERE id IN ({placeholders})
              AND tenant_id = CAST(:tid AS uuid)
        """),
        params,
    )
    count = result.rowcount

    if count > 0:
        await audit_service.log_action(
            db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            action=f"alert.bulk_{body.status}",
            resource_type="alert",
            resource_id=None,
            details={"count": count, "alert_ids": valid_ids[:20]},
        )
        await db.commit()

    return {"updated": count, "status": body.status}

# ── Response Actions ──────────────────────────────────────────────────────────

# Valid response actions — these map to real SOC workflows.
# In production, each would trigger an actual integration (EDR, firewall, etc.)
VALID_RESPONSE_ACTIONS = {
    "isolate_agent": "Isolate the agent from the network (EDR command)",
    "block_ip": "Block source/destination IP at the firewall",
    "quarantine_file": "Quarantine the suspicious file on the agent",
    "kill_process": "Terminate the suspicious process on the agent",
    "disable_user": "Disable the associated user account",
    "collect_forensics": "Trigger forensic data collection on the agent",
}

# High-impact actions that require mandatory reason and separate permission
_HIGH_IMPACT_ACTIONS = {"isolate_agent", "kill_process", "quarantine_file"}

class ResponseActionRequest(BaseModel):
    """Execute a response action on an alert."""

    action: Literal[
        "isolate_agent",
        "block_ip",
        "quarantine_file",
        "kill_process",
        "disable_user",
        "collect_forensics",
    ]
    parameters: dict = Field(
        default_factory=dict,
        description="Action-specific parameters (e.g. IP to block)",
        json_schema_extra={"maxProperties": 20},
    )
    reason: str = Field("", max_length=500, description="Analyst justification for the action")

class ResponseActionResponse(BaseModel):
    """Response action result."""

    alert_id: str
    action: str
    status: str  # "queued", "executed", "simulated"
    message: str
    action_id: str  # For tracking

@router.post(
    "/{alert_id}/actions",
    response_model=ResponseActionResponse,
    summary="Execute a response action",
    dependencies=[Depends(require_permission("alerts.execute_action"))],
)
async def execute_response_action(
    alert_id: uuid.UUID,
    body: ResponseActionRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Execute a response action on an alert (isolate, block, quarantine, etc.).

    Actions are logged to the immutable audit trail and recorded as ML training
    signals (analyst-action pairs). In production, each action triggers the
    corresponding integration (EDR API, firewall rule, etc.). In dev mode,
    actions are simulated and recorded.
    """
    alert = await alert_service.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if body.action not in VALID_RESPONSE_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown action: {body.action}")

    # High-impact actions MUST include a reason (isolate, kill, quarantine)
    if body.action in _HIGH_IMPACT_ACTIONS and not body.reason.strip():
        raise HTTPException(
            status_code=400,
            detail=f"Action '{body.action}' is high-impact and requires a mandatory reason.",
        )

    # Bound parameters dict depth/size
    import json as _json

    params_json = _json.dumps(body.parameters)
    if len(params_json) > 8192:
        raise HTTPException(status_code=400, detail="Parameters too large (max 8KB)")

    action_desc = VALID_RESPONSE_ACTIONS[body.action]

    # ── Queue real command for the sensor ──────────────────────────────
    agent_id_str = str(alert.agent_id) if alert.agent_id else None

    if agent_id_str:
        # Real command — queued for agent pickup via gateway heartbeat
        cmd = await agent_command_service.queue_command(
            db,
            tenant_id=current_user.tenant_id,
            agent_id=agent_id_str,
            alert_id=str(alert_id),
            action=body.action,
            parameters=body.parameters,
            issued_by=current_user.user_id,
            reason=body.reason or f"Response to alert: {alert.title}",
        )
        action_id = cmd.id
        status_str = "queued"
        message = (
            f"{action_desc} — command queued for dispatch to agent "
            f"{agent_id_str[:12]}…  Command will execute when the agent "
            f"checks in via heartbeat. If no sensor is deployed for this "
            f"agent, the command will remain queued until one connects."
        )
    else:
        # No agent associated — record-only action (disable_user, etc.)
        action_id = str(uuid.uuid4())
        status_str = "recorded"
        message = f"{action_desc} — action recorded (no agent associated with this alert)."

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action=f"alert.response_action.{body.action}",
        resource_type="alert",
        resource_id=alert_id,
        details={
            "action_id": action_id,
            "action": body.action,
            "parameters": body.parameters,
            "reason": body.reason,
            "alert_severity": alert.severity,
            "alert_title": alert.title,
            "agent_id": agent_id_str,
            "status": status_str,
        },
    )

    return ResponseActionResponse(
        alert_id=str(alert_id),
        action=body.action,
        status=status_str,
        message=message,
        action_id=action_id,
    )

# ── ML Feedback ──────────────────────────────────────────────────────────────

class AnalystFeedbackRequest(BaseModel):
    """Record analyst verdict as ML training signal."""

    verdict: Literal["true_positive", "false_positive", "benign", "needs_tuning"]
    confidence: float = Field(0.8, ge=0.0, le=1.0, description="Analyst confidence in the verdict")
    notes: str = Field("", max_length=1000, description="Optional notes for the ML pipeline")

@router.post(
    "/{alert_id}/feedback",
    summary="Record analyst verdict (ML feedback)",
    dependencies=[Depends(require_permission("alerts.acknowledge"))],
)
async def record_analyst_feedback(
    alert_id: uuid.UUID,
    body: AnalystFeedbackRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """
    Record analyst verdict on an alert as a labeled training signal.

    This data feeds back into the ML pipeline:
    - True positive → reinforces the detection model
    - False positive → tunes thresholds and reduces noise
    - Needs tuning → flags the rule for review

    Stored in the immutable audit log for compliance and batch ML training.
    """
    alert = await alert_service.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action=f"alert.ml_feedback.{body.verdict}",
        resource_type="alert",
        resource_id=alert_id,
        details={
            "verdict": body.verdict,
            "confidence": body.confidence,
            "notes": body.notes,
            "alert_severity": alert.severity,
            "alert_title": alert.title,
            "rule_id": str(alert.rule_id) if alert.rule_id else None,
            "agent_id": str(alert.agent_id) if alert.agent_id else None,
        },
    )

    return {
        "status": "recorded",
        "alert_id": str(alert_id),
        "verdict": body.verdict,
        "message": "Feedback recorded — ML pipeline will incorporate this signal in the next training cycle.",
    }
