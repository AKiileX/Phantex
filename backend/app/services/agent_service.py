# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Service.

Business logic for listing, retrieving, and updating agents.
All queries go through the RLS-enabled session.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.sensor import Sensor
from app.schemas.agent import AgentFilter, AgentUpdate

# Thresholds for auto-status computation.
# Agents are passive (no heartbeat) — they go stale only if truly idle for a long
# time. A querying AI agent that happens to be idle between prompts should remain
# active. 30 min stale / 60 min offline gives realistic window.
_STALE_THRESHOLD = timedelta(minutes=30)
_OFFLINE_THRESHOLD = timedelta(minutes=60)
from app.schemas.common import PageResult
from app.utils.pagination import decode_cursor, encode_cursor

async def list_agents(
    db: AsyncSession,
    filters: AgentFilter,
    cursor: str | None = None,
    limit: int = 50,
) -> PageResult:
    """
    List agents with optional filters and cursor-based pagination.
    RLS automatically filters by tenant.
    """
    limit = max(1, min(limit, 100))
    query = select(Agent).order_by(Agent.last_seen.desc(), Agent.id.desc())

    # Apply filters
    if filters.status:
        query = query.where(Agent.status == filters.status)
    if filters.framework:
        query = query.where(Agent.framework == filters.framework)
    if filters.search:
        escaped = filters.search.replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.where(or_(Agent.name.ilike(pattern), Agent.paid.ilike(pattern)))

    # Apply cursor
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            ts, uid = decoded
            query = query.where((Agent.last_seen < ts) | ((Agent.last_seen == ts) & (Agent.id < uid)))

    # Fetch limit + 1 to check if there are more
    result = await db.execute(query.limit(limit + 1))
    agents = list(result.scalars().all())

    has_more = len(agents) > limit
    items = agents[:limit]

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.last_seen, last.id)

    return PageResult(items=items, next_cursor=next_cursor, has_more=has_more)

async def get_agent(db: AsyncSession, agent_id: uuid.UUID) -> Agent | None:
    """Get a single agent by ID. RLS filters by tenant.

    If the agent has a linked sensor, inherit hostname / ip / os fields
    that the sensor heartbeat provides but the agent-discover event may not.
    """
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None or not agent.sensor_id:
        return agent

    # Inherit missing fields from the linked sensor record
    sensor_result = await db.execute(
        select(Sensor).where(Sensor.sensor_id == agent.sensor_id)
    )
    sensor = sensor_result.scalar_one_or_none()
    if sensor is None:
        return agent

    _inherit = [
        ("hostname",  "hostname"),
        ("ip_address", "ip_address"),
        ("os_type",   "os_type"),
        ("os_version", "kernel"),
        ("host_id",   "sensor_id"),
    ]
    dirty = False
    for agent_attr, sensor_attr in _inherit:
        if not getattr(agent, agent_attr) and getattr(sensor, sensor_attr, None):
            setattr(agent, agent_attr, getattr(sensor, sensor_attr))
            dirty = True

    # Numeric fields from sensor health metrics
    if agent.cpu_usage_pct is None and sensor.cpu_percent is not None:
        agent.cpu_usage_pct = round(sensor.cpu_percent, 2)
        dirty = True
    if agent.memory_mb is None and sensor.memory_bytes is not None:
        agent.memory_mb = int(sensor.memory_bytes / (1024 * 1024))
        dirty = True

    if dirty:
        await db.flush()
        await db.refresh(agent)
    return agent

async def get_agent_by_paid(db: AsyncSession, paid: str) -> Agent | None:
    """Get a single agent by PAID."""
    result = await db.execute(select(Agent).where(Agent.paid == paid))
    return result.scalar_one_or_none()

async def update_agent(db: AsyncSession, agent_id: uuid.UUID, data: AgentUpdate) -> Agent | None:
    """Update agent fields (name, status). Returns None if not found."""
    agent = await get_agent(db, agent_id)
    if agent is None:
        return None

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(agent, field, value)

    await db.flush()
    await db.refresh(agent)
    return agent

async def count_agents(db: AsyncSession) -> tuple[int, int]:
    """Return (total_agents, active_agents) for the current tenant."""
    total_result = await db.execute(select(func.count(Agent.id)))
    active_result = await db.execute(select(func.count(Agent.id)).where(Agent.status == "active"))
    return total_result.scalar_one(), active_result.scalar_one()

async def refresh_agent_statuses(db: AsyncSession) -> int:
    """
    Mark agents as stale/offline based on last_seen age.
    Returns number of agents updated. Should be called periodically.

    Thresholds:
      - >5 min since last_seen  → stale
      - >15 min since last_seen → offline
    Only affects agents with status 'active' or 'stale' (not terminated/quarantined).
    """
    now = datetime.now(UTC)
    stale_cutoff = now - _STALE_THRESHOLD
    offline_cutoff = now - _OFFLINE_THRESHOLD

    # Mark offline (no event in 15 min)
    result_offline = await db.execute(
        update(Agent)
        .where(
            Agent.status.in_(["active", "stale"]),
            Agent.last_seen < offline_cutoff,
        )
        .values(status="offline", updated_at=now)
    )

    # Mark stale (no event in 5 min but within 15 min)
    result_stale = await db.execute(
        update(Agent)
        .where(
            Agent.status == "active",
            Agent.last_seen < stale_cutoff,
            Agent.last_seen >= offline_cutoff,
        )
        .values(status="stale", updated_at=now)
    )

    return (result_offline.rowcount or 0) + (result_stale.rowcount or 0)
