# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Drift Approval Workflow

Provides approve/reject/escalate workflow for drift events:
  - Approve: Accept a config change as intentional.
  - Reject:  Flag a config change as unauthorized → open for remediation.
  - Escalate: Forward to a senior analyst.
  - Auto-revert: If policy has auto_revert_enabled, reject + log.

All actions are recorded in the immutable drift_approval_log table (append-only).

Security:
  - Tenant-scoped (RLS enforced)
  - drift_approval_log is INSERT-only (no update/delete)
  - Audit trail includes user_id, reason, and metadata
  - Parameterised SQL
"""

from __future__ import annotations

import json as _json
import uuid
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.service.drift.workflow")

# ── Actions ───────────────────────────────────────────────────────────────────

async def approve_drift(
    db: Any,
    tenant_id: Any,
    drift_event_id: str,
    user_id: str,
    reason: str,
    metadata: dict | None = None,
) -> dict:
    """
    Approve a drift event — marks the config change as intentional.

    Updates the drift event status and appends to the audit log.
    """
    return await _resolve_drift(
        db,
        tenant_id,
        drift_event_id,
        user_id,
        action="approved",
        reason=reason,
        metadata=metadata,
    )

async def reject_drift(
    db: Any,
    tenant_id: Any,
    drift_event_id: str,
    user_id: str,
    reason: str,
    metadata: dict | None = None,
) -> dict:
    """
    Reject a drift event — flags the config change as unauthorized.

    Updates status and appends to audit log.
    """
    return await _resolve_drift(
        db,
        tenant_id,
        drift_event_id,
        user_id,
        action="rejected",
        reason=reason,
        metadata=metadata,
    )

async def escalate_drift(
    db: Any,
    tenant_id: Any,
    drift_event_id: str,
    user_id: str,
    reason: str,
    metadata: dict | None = None,
) -> dict:
    """
    Escalate a drift event to a senior analyst.

    Appends to audit log but does NOT change event status (remains open).
    """
    await db.set_tenant(str(tenant_id))

    # Verify event exists
    event = await db.fetchrow(
        "SELECT * FROM agent_drift_events WHERE id = $1 AND tenant_id = $2",
        drift_event_id,
        tenant_id,
    )
    if not event:
        raise ValueError(f"Drift event {drift_event_id} not found")

    # Append to audit log
    log_entry = await _append_log(db, tenant_id, drift_event_id, user_id, "escalated", reason, metadata)

    logger.info(
        "drift_escalated",
        drift_event_id=drift_event_id,
        user_id=user_id,
        tenant_id=str(tenant_id),
    )

    return {
        "drift_event": _drift_event_to_dict(event),
        "log_entry": log_entry,
    }

async def auto_revert_drift(
    db: Any,
    tenant_id: Any,
    drift_event_id: str,
    reason: str = "Auto-reverted by drift policy",
) -> dict:
    """
    Auto-revert a drift event (triggered by policy engine).

    Uses a system user ID. Records the action in the audit trail.
    """
    system_user_id = "00000000-0000-0000-0000-000000000000"
    return await _resolve_drift(
        db,
        tenant_id,
        drift_event_id,
        system_user_id,
        action="auto_reverted",
        reason=reason,
        metadata={"automated": True, "trigger": "drift_policy"},
    )

# ── Audit Log Queries ─────────────────────────────────────────────────────────

async def list_approval_log(
    db: Any,
    tenant_id: Any,
    drift_event_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """List audit log entries with optional drift event filter."""
    await db.set_tenant(str(tenant_id))

    where = ["tenant_id = $1"]
    params: list[Any] = [tenant_id]
    idx = 2

    if drift_event_id:
        where.append(f"drift_event_id = ${idx}")
        params.append(drift_event_id)
        idx += 1

    where_sql = " AND ".join(where)

    count_row = await db.fetchrow(
        f"SELECT count(*) AS cnt FROM drift_approval_log WHERE {where_sql}",
        *params,
    )
    total = count_row["cnt"] if count_row else 0

    rows = await db.fetch(
        f"""
        SELECT * FROM drift_approval_log
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )

    return [_log_to_dict(r) for r in rows], total

async def get_pending_approvals(
    db: Any,
    tenant_id: Any,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """
    Get all open drift events waiting for approval.

    Returns events with status='open', ordered by severity (critical first).
    """
    await db.set_tenant(str(tenant_id))

    count_row = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_drift_events WHERE tenant_id = $1 AND status = 'open'",
        tenant_id,
    )
    total = count_row["cnt"] if count_row else 0

    rows = await db.fetch(
        """
        SELECT * FROM agent_drift_events
        WHERE tenant_id = $1 AND status = 'open'
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC
        LIMIT $2 OFFSET $3
        """,
        tenant_id,
        limit,
        offset,
    )

    return [_drift_event_to_dict(r) for r in rows], total

# ── Internal ──────────────────────────────────────────────────────────────────

async def _resolve_drift(
    db: Any,
    tenant_id: Any,
    drift_event_id: str,
    user_id: str,
    action: str,
    reason: str,
    metadata: dict | None = None,
) -> dict:
    """Generic resolve: update event status + append audit log."""
    await db.set_tenant(str(tenant_id))

    # Verify event exists and is open
    event = await db.fetchrow(
        "SELECT * FROM agent_drift_events WHERE id = $1 AND tenant_id = $2",
        drift_event_id,
        tenant_id,
    )
    if not event:
        raise ValueError(f"Drift event {drift_event_id} not found")
    if event["status"] != "open":
        raise ValueError(f"Drift event already resolved with status '{event['status']}'")

    # Update event status
    new_status = action  # approved, rejected, auto_reverted
    updated = await db.fetchrow(
        """
        UPDATE agent_drift_events
        SET status = $3, resolved_by = $4, resolved_at = now(), resolution_reason = $5
        WHERE id = $1 AND tenant_id = $2
        RETURNING *
        """,
        drift_event_id,
        tenant_id,
        new_status,
        uuid.UUID(user_id),
        reason,
    )

    # Append to immutable audit log
    log_entry = await _append_log(db, tenant_id, drift_event_id, user_id, action, reason, metadata)

    logger.info(
        "drift_resolved",
        drift_event_id=drift_event_id,
        action=action,
        user_id=user_id,
        tenant_id=str(tenant_id),
    )

    return {
        "drift_event": _drift_event_to_dict(updated),
        "log_entry": log_entry,
    }

async def _append_log(
    db: Any,
    tenant_id: Any,
    drift_event_id: str,
    user_id: str,
    action: str,
    reason: str,
    metadata: dict | None = None,
) -> dict:
    """Append an entry to the immutable audit log."""
    log_id = str(uuid.uuid4())
    row = await db.fetchrow(
        """
        INSERT INTO drift_approval_log (
            id, tenant_id, drift_event_id, action, user_id, reason, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        """,
        log_id,
        tenant_id,
        drift_event_id,
        action,
        uuid.UUID(user_id),
        reason,
        _json.dumps(metadata or {}),
    )
    return _log_to_dict(row)

# ── Row converters ────────────────────────────────────────────────────────────

def _parse_json(val: Any) -> Any:
    """Parse JSON string or return as-is."""
    if val is None:
        return {}
    if isinstance(val, dict | list):
        return val
    try:
        return _json.loads(val)
    except (ValueError, TypeError):
        return {}

def _drift_event_to_dict(row: Any) -> dict:
    """Convert drift event row to dict."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "agent_id": row["agent_id"],
        "drift_type": row["drift_type"],
        "severity": row["severity"],
        "field_name": row["field_name"],
        "old_value": row.get("old_value"),
        "new_value": row.get("new_value"),
        "baseline_snapshot_id": str(row["baseline_snapshot_id"]),
        "current_snapshot_id": str(row["current_snapshot_id"]),
        "status": row["status"],
        "resolved_by": str(row["resolved_by"]) if row.get("resolved_by") else None,
        "resolved_at": str(row["resolved_at"]) if row.get("resolved_at") else None,
        "resolution_reason": row.get("resolution_reason"),
        "created_at": str(row["created_at"]),
    }

def _log_to_dict(row: Any) -> dict:
    """Convert approval log row to dict."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "drift_event_id": str(row["drift_event_id"]),
        "action": row["action"],
        "user_id": str(row["user_id"]),
        "reason": row["reason"],
        "metadata": _parse_json(row.get("metadata")),
        "created_at": str(row["created_at"]),
    }
