# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex GraphQL — Subscriptions.

Real-time WebSocket subscriptions built on the existing AlertBroadcaster.
Alerts are pushed to GraphQL subscribers using the same in-memory pub/sub
that powers the REST WebSocket endpoint.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

import strawberry
from sqlalchemy import and_, or_, select
from strawberry.types import Info

from app.graphql.types import AlertSummaryType, EventSummaryType, TrustFactorType, TrustScoreType
from app.models.event import Event
from app.services.trust_client import get_trust_client

if TYPE_CHECKING:
    from app.graphql.context import GraphQLContext

def _ctx(info: Info) -> GraphQLContext:
    return info.context

def _event_summary_from_model(event: Event) -> EventSummaryType:
    return EventSummaryType(
        id=event.id,
        agent_id=event.agent_id,
        event_type=event.event_type,
        severity=event.severity,
        timestamp=event.timestamp,
    )

def _trust_score_from_result(result) -> TrustScoreType:
    return TrustScoreType(
        entity_id=result.entity_id,
        entity_type=result.entity_type,
        trust_score=result.trust_score,
        factors=[TrustFactorType(name=f.name, weight=f.weight, value=f.value) for f in result.factors],
        last_updated=result.last_updated,
    )

@strawberry.type
class Subscription:
    @strawberry.subscription(description="Stream new alerts in real-time for the current tenant.")
    async def alert_created(
        self,
        info: Info,
        severity: str | None = None,
    ) -> AsyncGenerator[AlertSummaryType, None]:
        """Subscribe to new alerts.  Optionally filter by severity."""
        ctx = _ctx(info)
        tenant_id = str(ctx.user.tenant_id)
        sub_id = f"gql-{uuid.uuid4()}"
        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=256)

        # Get the broadcaster from the app state (set during lifespan)
        broadcaster = ctx.request.app.state.alert_broadcaster

        async def _on_alert(payload: dict) -> None:
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                # Drop oldest if backpressured
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                queue.put_nowait(payload)

        broadcaster.subscribe(tenant_id, sub_id, _on_alert)
        try:
            while True:
                payload = await queue.get()
                # Apply severity filter if requested
                if severity and payload.get("severity") != severity:
                    continue
                yield AlertSummaryType(
                    id=uuid.UUID(payload["id"])
                    if isinstance(payload.get("id"), str)
                    else payload.get("id", uuid.uuid4()),
                    severity=payload.get("severity", "medium"),
                    title=payload.get("title", ""),
                    status=payload.get("status", "open"),
                    created_at=payload.get("created_at", payload.get("timestamp")),
                    agent_id=payload.get("agent_id"),
                    rule_id=uuid.UUID(payload["rule_id"]) if payload.get("rule_id") else None,
                    event_id=uuid.UUID(payload["event_id"]) if payload.get("event_id") else None,
                )
        finally:
            broadcaster.unsubscribe(tenant_id, sub_id)

    @strawberry.subscription(description="Stream new events in real-time for the current tenant.")
    async def event_created(
        self,
        info: Info,
        severity: str | None = None,
        event_type: str | None = None,
        agent_id: str | None = None,
    ) -> AsyncGenerator[EventSummaryType, None]:
        """Subscribe to newly-ingested events using lightweight DB polling."""
        ctx = _ctx(info)
        last_created_at = datetime.now(UTC)
        last_id = uuid.UUID(int=0)

        while True:
            stmt = (
                select(Event)
                .where(Event.tenant_id == ctx.user.tenant_id)
                .where(
                    or_(
                        Event.created_at > last_created_at,
                        and_(Event.created_at == last_created_at, Event.id > last_id),
                    )
                )
                .order_by(Event.created_at.asc(), Event.id.asc())
                .limit(100)
            )

            if severity:
                stmt = stmt.where(Event.severity == severity)
            if event_type:
                stmt = stmt.where(Event.event_type == event_type)
            if agent_id:
                stmt = stmt.where(Event.agent_id == agent_id)

            result = await ctx.db.execute(stmt)
            events = result.scalars().all()

            if not events:
                await asyncio.sleep(1.0)
                continue

            for event in events:
                last_created_at = event.created_at
                last_id = event.id
                yield _event_summary_from_model(event)

    @strawberry.subscription(description="Stream trust-score changes for an entity.")
    async def trust_score_updated(
        self,
        info: Info,
        entity_id: str,
        entity_type: str = "agent",
    ) -> AsyncGenerator[TrustScoreType, None]:
        """Subscribe to trust-score changes using trust-engine polling."""
        ctx = _ctx(info)
        client = get_trust_client()
        last_score: float | None = None
        last_updated: float | None = None

        while True:
            result = await client.get_trust_score(
                tenant_id=str(ctx.user.tenant_id),
                entity_id=entity_id,
                entity_type=entity_type,
            )

            if (
                last_score is None
                or result.trust_score != last_score
                or result.last_updated != last_updated
            ):
                last_score = result.trust_score
                last_updated = result.last_updated
                yield _trust_score_from_result(result)

            await asyncio.sleep(2.0)
