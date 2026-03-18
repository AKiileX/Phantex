# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex GraphQL — DataLoaders.

Prevents N+1 queries by batching DB lookups within a single GraphQL request.

Usage in resolvers:
    agent = await info.context.loaders.agent.load(agent_id)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sqlalchemy import select
from strawberry.dataloader import DataLoader

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import Rule

# ── Batch functions ───────────────────────────────────────────────────────────

async def _batch_load_agents(keys: list[uuid.UUID], db: AsyncSession) -> list[Agent | None]:
    result = await db.execute(select(Agent).where(Agent.id.in_(keys)))
    by_id = {a.id: a for a in result.scalars().all()}
    return [by_id.get(k) for k in keys]

async def _batch_load_alerts(keys: list[uuid.UUID], db: AsyncSession) -> list[Alert | None]:
    result = await db.execute(select(Alert).where(Alert.id.in_(keys)))
    by_id = {a.id: a for a in result.scalars().all()}
    return [by_id.get(k) for k in keys]

async def _batch_load_events(keys: list[uuid.UUID], db: AsyncSession) -> list[Event | None]:
    result = await db.execute(select(Event).where(Event.id.in_(keys)))
    by_id = {e.id: e for e in result.scalars().all()}
    return [by_id.get(k) for k in keys]

async def _batch_load_rules(keys: list[uuid.UUID], db: AsyncSession) -> list[Rule | None]:
    result = await db.execute(select(Rule).where(Rule.id.in_(keys)))
    by_id = {r.id: r for r in result.scalars().all()}
    return [by_id.get(k) for k in keys]

# ── Loader container (one per request) ────────────────────────────────────────

@dataclass
class Loaders:
    """Per-request DataLoader instances.  Created fresh for each GraphQL request
    so caching doesn't leak across requests or tenants."""

    agent: DataLoader[uuid.UUID, Agent | None] = field(init=False)
    alert: DataLoader[uuid.UUID, Alert | None] = field(init=False)
    event: DataLoader[uuid.UUID, Event | None] = field(init=False)
    rule: DataLoader[uuid.UUID, Rule | None] = field(init=False)

    def __init__(self, db: AsyncSession) -> None:
        self.agent = DataLoader(load_fn=lambda keys: _batch_load_agents(keys, db))
        self.alert = DataLoader(load_fn=lambda keys: _batch_load_alerts(keys, db))
        self.event = DataLoader(load_fn=lambda keys: _batch_load_events(keys, db))
        self.rule = DataLoader(load_fn=lambda keys: _batch_load_rules(keys, db))
