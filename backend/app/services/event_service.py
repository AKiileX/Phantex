# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Event Service.

Business logic for listing and retrieving security events.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.schemas.common import PageResult
from app.schemas.event import EventFilter
from app.utils.pagination import decode_cursor, encode_cursor

async def list_events(
    db: AsyncSession,
    filters: EventFilter,
    cursor: str | None = None,
    limit: int = 50,
) -> PageResult:
    """
    List events with filters and cursor-based pagination.
    RLS automatically filters by tenant.
    Events are ordered by timestamp DESC (most recent first).
    """
    limit = max(1, min(limit, 100))
    query = select(Event).order_by(Event.timestamp.desc(), Event.id.desc())

    # Apply filters
    if filters.agent_only and not filters.agent_id:
        query = query.where(Event.agent_id.is_not(None))
    if filters.agent_id:
        query = query.where(Event.agent_id == filters.agent_id)
    if filters.event_type:
        types = [t.strip() for t in filters.event_type.split(",") if t.strip()]
        if len(types) == 1:
            query = query.where(Event.event_type == types[0])
        else:
            query = query.where(Event.event_type.in_(types))
    if filters.severity:
        sevs = [s.strip() for s in filters.severity.split(",") if s.strip()]
        if len(sevs) == 1:
            query = query.where(Event.severity == sevs[0])
        else:
            query = query.where(Event.severity.in_(sevs))
    if filters.since:
        query = query.where(Event.timestamp >= filters.since)
    if filters.until:
        query = query.where(Event.timestamp <= filters.until)

    # Apply cursor (seek pagination on timestamp + id)
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            ts, uid = decoded
            query = query.where((Event.timestamp < ts) | ((Event.timestamp == ts) & (Event.id < uid)))

    result = await db.execute(query.limit(limit + 1))
    events = list(result.scalars().all())

    has_more = len(events) > limit
    items = events[:limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.timestamp, last.id)

    return PageResult(items=items, next_cursor=next_cursor, has_more=has_more)

async def get_event(db: AsyncSession, event_id: uuid.UUID) -> Event | None:
    """Get a single event by ID. RLS filters by tenant."""
    result = await db.execute(select(Event).where(Event.id == event_id))
    return result.scalar_one_or_none()

async def count_events_simple(db: AsyncSession) -> int:
    """Return total event count for the current tenant."""
    result = await db.execute(
        select(func.count(Event.id))
    )
    return result.scalar_one()

async def count_events_last_24h(db: AsyncSession) -> int:
    """Return event count in the last 24 hours."""
    from sqlalchemy import text

    result = await db.execute(
        select(func.count(Event.id)).where(
            Event.timestamp >= func.now() - text("interval '24 hours'"),
        )
    )
    return result.scalar_one()
