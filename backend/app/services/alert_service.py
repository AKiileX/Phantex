# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Alert Service.

Business logic for creating, listing, retrieving, and updating security alerts.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.schemas.alert import AlertFilter, AlertUpdate
from app.schemas.common import PageResult
from app.utils.pagination import decode_cursor, encode_cursor

async def create_alert(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    rule_id: uuid.UUID | None = None,
    event_id: uuid.UUID | None = None,
    agent_id: str | None = None,
    severity: str = "medium",
    title: str,
    description: str | None = None,
    context: dict[str, Any] | None = None,
) -> Alert:
    """
    Create a new alert. Used by the PRL rule engine when a rule matches.

    The caller must ensure RLS context (tenant) is already set on the session.
    """
    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        agent_id=agent_id,
        event_id=event_id,
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        status="open",
        context=context or {},
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)
    return alert

async def list_alerts(
    db: AsyncSession,
    filters: AlertFilter,
    cursor: str | None = None,
    limit: int = 50,
) -> PageResult:
    """
    List alerts with filters and cursor pagination.
    RLS filters by tenant automatically.
    """
    limit = max(1, min(limit, 100))
    query = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())

    if filters.status:
        query = query.where(Alert.status == filters.status)
    if filters.severity:
        query = query.where(Alert.severity == filters.severity)
    if filters.agent_id:
        query = query.where(Alert.agent_id == filters.agent_id)
    if filters.since:
        query = query.where(Alert.created_at >= filters.since)
    if filters.search:
        escaped = filters.search.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.where(Alert.title.ilike(pattern) | Alert.description.ilike(pattern))

    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            ts, uid = decoded
            query = query.where((Alert.created_at < ts) | ((Alert.created_at == ts) & (Alert.id < uid)))

    result = await db.execute(query.limit(limit + 1))
    alerts = list(result.scalars().all())

    has_more = len(alerts) > limit
    items = alerts[:limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.id)

    return PageResult(items=items, next_cursor=next_cursor, has_more=has_more)

async def get_alert(db: AsyncSession, alert_id: uuid.UUID) -> Alert | None:
    """Get a single alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one_or_none()

async def update_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    data: AlertUpdate,
    user_id: uuid.UUID | None = None,
) -> Alert | None:
    """
    Update an alert's status. Sets resolved_at + resolved_by when resolving.
    """
    alert = await get_alert(db, alert_id)
    if alert is None:
        return None

    alert.status = data.status

    if data.status in ("resolved", "false_positive"):
        alert.resolved_at = datetime.now(UTC)
        alert.resolved_by = user_id

    await db.flush()
    await db.refresh(alert)
    return alert

async def bulk_acknowledge(
    db: AsyncSession,
    user_id: uuid.UUID | None = None,
) -> int:
    """
    Acknowledge all open alerts for the current tenant in one UPDATE.
    Returns the number of rows affected.
    """
    result = await db.execute(update(Alert).where(Alert.status == "open").values(status="acknowledged"))
    await db.flush()
    return result.rowcount  # type: ignore[return-value]

async def count_alerts(db: AsyncSession) -> tuple[int, int, int]:
    """Return (total_alerts, open_alerts, critical_alerts) for the current tenant."""
    total_result = await db.execute(select(func.count(Alert.id)))
    open_result = await db.execute(select(func.count(Alert.id)).where(Alert.status == "open"))
    critical_result = await db.execute(select(func.count(Alert.id)).where(Alert.severity == "critical"))
    return total_result.scalar_one(), open_result.scalar_one(), critical_result.scalar_one()
