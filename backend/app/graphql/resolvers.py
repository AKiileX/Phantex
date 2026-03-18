# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex GraphQL — Query & Mutation Resolvers.

Thin wrappers over existing service functions — no business logic duplication.
Every resolver reads ``info.context`` for the authenticated user and DB session.
All operations emit structured logs for observability.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import strawberry
from strawberry.types import Info

from app.graphql.types import (
    # Connection types (paginated)
    AgentConnection,
    # Input types
    AgentFilterInput,
    # Summary types
    AgentSummaryType,
    # Entity types
    AgentType,
    AlertConnection,
    AlertFilterInput,
    AlertSummaryType,
    AlertType,
    AlertUpdateInput,
    EventConnection,
    EventFilterInput,
    EventSummaryType,
    EventType,
    PageInfo,
    RuleConnection,
    RuleCreateInput,
    RuleFilterInput,
    RuleSummaryType,
    RuleType,
    RuleUpdateInput,
    TrustFactorType,
    TrustGraphEdgeType,
    TrustGraphNodeType,
    TrustGraphType,
    TrustScoreType,
)
from app.utils.logging import get_logger

if TYPE_CHECKING:
    from app.graphql.context import GraphQLContext

_logger = get_logger("phantex.graphql.resolvers")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ctx(info: Info) -> GraphQLContext:
    return info.context

def _page_info(items: list, limit: int, offset: int, total: int | None = None) -> PageInfo:
    count = total if total is not None else len(items) + offset
    return PageInfo(total=count, limit=limit, offset=offset, has_next=len(items) >= limit)

# ── Query ─────────────────────────────────────────────────────────────────────

@strawberry.type
class Query:
    # ── Alerts ────────────────────────────────────────────────────────

    @strawberry.field(description="List alerts with optional filters and pagination.")
    async def alerts(
        self,
        info: Info,
        filters: AlertFilterInput | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AlertConnection:
        from app.schemas.alert import AlertFilter
        from app.services import alert_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="alerts", user_id=str(ctx.user.user_id), limit=limit, offset=offset)
        f = AlertFilter(
            status=filters.status if filters else None,
            severity=filters.severity if filters else None,
            agent_id=filters.agent_id if filters else None,
            since=filters.since if filters else None,
            search=filters.search if filters else None,
        )
        page = await alert_service.list_alerts(ctx.db, f, limit=max(1, min(limit, 100)))
        items = [
            AlertSummaryType(
                id=a.id,
                severity=a.severity,
                title=a.title,
                status=a.status,
                created_at=a.created_at,
                agent_id=a.agent_id,
                rule_id=a.rule_id,
                event_id=a.event_id,
            )
            for a in page.items
        ]
        return AlertConnection(
            items=items,
            page_info=_page_info(items, limit, offset),
        )

    @strawberry.field(description="Get a single alert by ID.")
    async def alert(self, info: Info, id: uuid.UUID) -> AlertType | None:
        from app.services import alert_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="alert", user_id=str(ctx.user.user_id), resource_id=str(id))
        a = await alert_service.get_alert(ctx.db, id)
        if a is None:
            return None
        return AlertType(
            id=a.id,
            tenant_id=a.tenant_id,
            agent_id=a.agent_id,
            event_id=a.event_id,
            rule_id=a.rule_id,
            severity=a.severity,
            title=a.title,
            description=a.description,
            status=a.status,
            context=a.context,
            created_at=a.created_at,
            updated_at=a.updated_at,
            resolved_at=a.resolved_at,
            resolved_by=a.resolved_by,
        )

    # ── Agents ────────────────────────────────────────────────────────

    @strawberry.field(description="List agents with optional filters and pagination.")
    async def agents(
        self,
        info: Info,
        filters: AgentFilterInput | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AgentConnection:
        from app.schemas.agent import AgentFilter
        from app.services import agent_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="agents", user_id=str(ctx.user.user_id), limit=limit, offset=offset)
        f = AgentFilter(
            status=filters.status if filters else None,
            framework=filters.framework if filters else None,
            search=filters.search if filters else None,
        )
        page = await agent_service.list_agents(ctx.db, f, limit=max(1, min(limit, 100)))
        items = [
            AgentSummaryType(
                id=a.id,
                paid=a.paid,
                name=a.name,
                framework=a.framework,
                status=a.status,
                ip_address=a.ip_address,
                hostname=a.hostname,
                os_type=a.os_type,
                tags=a.tags,
                last_seen=a.last_seen,
            )
            for a in page.items
        ]
        return AgentConnection(
            items=items,
            page_info=_page_info(items, limit, offset),
        )

    @strawberry.field(description="Get a single agent by ID.")
    async def agent(self, info: Info, id: uuid.UUID) -> AgentType | None:
        from app.services import agent_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="agent", user_id=str(ctx.user.user_id), resource_id=str(id))
        a = await agent_service.get_agent(ctx.db, id)
        if a is None:
            return None
        return AgentType(
            id=a.id,
            tenant_id=a.tenant_id,
            paid=a.paid,
            name=a.name,
            framework=a.framework,
            framework_ver=a.framework_ver,
            status=a.status,
            ip_address=a.ip_address,
            hostname=a.hostname,
            os_type=a.os_type,
            os_version=a.os_version,
            container_id=a.container_id,
            container_image=a.container_image,
            host_id=a.host_id,
            sensor_id=a.sensor_id,
            cpu_usage_pct=a.cpu_usage_pct,
            memory_mb=a.memory_mb,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            updated_at=a.updated_at,
            tags=a.tags,
            metadata=a.metadata,
        )

    # ── Events ────────────────────────────────────────────────────────

    @strawberry.field(description="List events with optional filters and pagination.")
    async def events(
        self,
        info: Info,
        filters: EventFilterInput | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> EventConnection:
        from app.schemas.event import EventFilter
        from app.services import event_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="events", user_id=str(ctx.user.user_id), limit=limit, offset=offset)
        f = EventFilter(
            agent_id=filters.agent_id if filters else None,
            event_type=filters.event_type if filters else None,
            severity=filters.severity if filters else None,
            since=filters.since if filters else None,
            until=filters.until if filters else None,
        )
        page = await event_service.list_events(ctx.db, f, limit=max(1, min(limit, 100)))
        items = [
            EventSummaryType(
                id=e.id,
                agent_id=e.agent_id,
                event_type=e.event_type,
                severity=e.severity,
                timestamp=e.timestamp,
            )
            for e in page.items
        ]
        return EventConnection(
            items=items,
            page_info=_page_info(items, limit, offset),
        )

    @strawberry.field(description="Get a single event by ID.")
    async def event(self, info: Info, id: uuid.UUID) -> EventType | None:
        from app.services import event_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="event", user_id=str(ctx.user.user_id), resource_id=str(id))
        e = await event_service.get_event(ctx.db, id)
        if e is None:
            return None
        return EventType(
            id=e.id,
            tenant_id=e.tenant_id,
            agent_id=e.agent_id,
            sensor_id=e.sensor_id,
            event_type=e.event_type,
            severity=e.severity,
            timestamp=e.timestamp,
            raw_data=e.raw_data,
            created_at=e.created_at,
        )

    # ── Rules ─────────────────────────────────────────────────────────

    @strawberry.field(description="List detection rules with optional filters.")
    async def rules(
        self,
        info: Info,
        filters: RuleFilterInput | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> RuleConnection:
        from app.schemas.rule import RuleFilter
        from app.services import rule_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="rules", user_id=str(ctx.user.user_id), limit=limit, offset=offset)
        f = RuleFilter(
            enabled=filters.enabled if filters else None,
            severity=filters.severity if filters else None,
            attack_class=filters.attack_class if filters else None,
            search=filters.search if filters else None,
        )
        page = await rule_service.list_rules(ctx.db, f, limit=max(1, min(limit, 100)))
        items = [
            RuleSummaryType(
                id=r.id,
                name=r.name,
                severity=r.severity,
                attack_class=r.attack_class,
                enabled=r.enabled,
                version=r.version,
                author=r.author,
                created_at=r.created_at,
            )
            for r in page.items
        ]
        return RuleConnection(
            items=items,
            page_info=_page_info(items, limit, offset),
        )

    @strawberry.field(description="Get a single rule by ID.")
    async def rule(self, info: Info, id: uuid.UUID) -> RuleType | None:
        from app.services import rule_service

        ctx = _ctx(info)
        _logger.info("graphql_query", operation="rule", user_id=str(ctx.user.user_id), resource_id=str(id))
        r = await rule_service.get_rule(ctx.db, id)
        if r is None:
            return None
        return RuleType(
            id=r.id,
            tenant_id=r.tenant_id,
            name=r.name,
            description=r.description,
            severity=r.severity,
            attack_class=r.attack_class,
            prl_source=r.prl_source,
            compiled=r.compiled,
            enabled=r.enabled,
            version=r.version,
            author=r.author,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )

    # ── Trust ─────────────────────────────────────────────────────────

    @strawberry.field(description="Get trust score for an entity.")
    async def trust_score(
        self,
        info: Info,
        entity_id: str,
        entity_type: str = "agent",
    ) -> TrustScoreType:
        from app.services.trust_client import get_trust_client

        ctx = _ctx(info)
        _logger.info(
            "graphql_query",
            operation="trust_score",
            user_id=str(ctx.user.user_id),
            entity_id=entity_id,
            entity_type=entity_type,
        )
        client = get_trust_client()
        result = await client.get_trust_score(
            tenant_id=str(ctx.user.tenant_id),
            entity_id=entity_id,
            entity_type=entity_type,
        )
        return TrustScoreType(
            entity_id=result.entity_id,
            entity_type=result.entity_type,
            trust_score=result.trust_score,
            factors=[TrustFactorType(name=f.name, weight=f.weight, value=f.value) for f in result.factors],
            last_updated=result.last_updated,
        )

    @strawberry.field(description="Get trust graph neighbourhood for an entity.")
    async def trust_graph(
        self,
        info: Info,
        entity_id: str,
        entity_type: str = "agent",
        depth: int = 2,
    ) -> TrustGraphType:
        from app.services.trust_client import get_trust_client

        ctx = _ctx(info)
        _logger.info(
            "graphql_query", operation="trust_graph", user_id=str(ctx.user.user_id), entity_id=entity_id, depth=depth
        )
        client = get_trust_client()
        neighbourhood = await client.get_trust_graph(
            tenant_id=str(ctx.user.tenant_id),
            entity_id=entity_id,
            entity_type=entity_type,
            depth=depth,
        )
        return TrustGraphType(
            nodes=[
                TrustGraphNodeType(
                    id=n.entity_id,
                    entity_type=n.entity_type,
                    trust_score=n.trust_score,
                    metadata=n.metadata,
                )
                for n in neighbourhood.nodes
            ],
            edges=[
                TrustGraphEdgeType(
                    source_id=e.source_id,
                    target_id=e.target_id,
                    edge_type=e.edge_type,
                    count=e.count,
                    weight=e.weight,
                )
                for e in neighbourhood.edges
            ],
            truncated=neighbourhood.truncated,
        )

# ── Mutation ──────────────────────────────────────────────────────────────────

@strawberry.type
class Mutation:
    @strawberry.mutation(description="Update an alert's status (acknowledge, resolve, false_positive).")
    async def update_alert(
        self,
        info: Info,
        id: uuid.UUID,
        input: AlertUpdateInput,
    ) -> AlertType | None:
        from app.schemas.alert import AlertUpdate
        from app.services import alert_service

        ctx = _ctx(info)
        _logger.info(
            "graphql_mutation",
            operation="update_alert",
            user_id=str(ctx.user.user_id),
            resource_id=str(id),
            new_status=input.status,
        )
        await ctx.require_permission("alerts.acknowledge")

        data = AlertUpdate(status=input.status)
        a = await alert_service.update_alert(
            ctx.db,
            id,
            data,
            user_id=ctx.user.user_id,
        )
        if a is None:
            return None

        await ctx.audit(
            action=f"alert.{input.status}",
            resource_type="alert",
            resource_id=id,
            details={"new_status": input.status, "via": "graphql"},
        )
        _logger.info("graphql_mutation_ok", operation="update_alert", resource_id=str(id), new_status=input.status)

        return AlertType(
            id=a.id,
            tenant_id=a.tenant_id,
            agent_id=a.agent_id,
            event_id=a.event_id,
            rule_id=a.rule_id,
            severity=a.severity,
            title=a.title,
            description=a.description,
            status=a.status,
            context=a.context,
            created_at=a.created_at,
            updated_at=a.updated_at,
            resolved_at=a.resolved_at,
            resolved_by=a.resolved_by,
        )

    @strawberry.mutation(description="Create a new detection rule.")
    async def create_rule(
        self,
        info: Info,
        input: RuleCreateInput,
    ) -> RuleType:
        from app.schemas.rule import RuleCreate
        from app.services import rule_service

        ctx = _ctx(info)
        _logger.info(
            "graphql_mutation",
            operation="create_rule",
            user_id=str(ctx.user.user_id),
            rule_name=input.name,
            severity=input.severity,
        )
        await ctx.require_permission("rules.write")

        data = RuleCreate(
            name=input.name,
            description=input.description,
            severity=input.severity,
            attack_class=input.attack_class,
            prl_source=input.prl_source,
            enabled=input.enabled,
        )
        r = await rule_service.create_rule(
            ctx.db,
            data,
            tenant_id=ctx.user.tenant_id,
            author=ctx.user.email,
        )

        await ctx.audit(
            action="rule.create",
            resource_type="rule",
            resource_id=r.id,
            details={"name": r.name, "severity": r.severity, "via": "graphql"},
        )
        _logger.info("graphql_mutation_ok", operation="create_rule", resource_id=str(r.id), rule_name=r.name)

        return RuleType(
            id=r.id,
            tenant_id=r.tenant_id,
            name=r.name,
            description=r.description,
            severity=r.severity,
            attack_class=r.attack_class,
            prl_source=r.prl_source,
            compiled=r.compiled,
            enabled=r.enabled,
            version=r.version,
            author=r.author,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )

    @strawberry.mutation(description="Update an existing detection rule.")
    async def update_rule(
        self,
        info: Info,
        id: uuid.UUID,
        input: RuleUpdateInput,
    ) -> RuleType | None:
        from app.schemas.rule import RuleUpdate
        from app.services import rule_service

        ctx = _ctx(info)
        _logger.info("graphql_mutation", operation="update_rule", user_id=str(ctx.user.user_id), resource_id=str(id))
        await ctx.require_permission("rules.write")

        data = RuleUpdate(
            name=input.name,
            description=input.description,
            severity=input.severity,
            attack_class=input.attack_class,
            prl_source=input.prl_source,
            enabled=input.enabled,
        )
        r = await rule_service.update_rule(ctx.db, id, data)
        if r is None:
            return None

        await ctx.audit(
            action="rule.update",
            resource_type="rule",
            resource_id=id,
            details={"name": r.name, "via": "graphql"},
        )
        _logger.info("graphql_mutation_ok", operation="update_rule", resource_id=str(id))

        return RuleType(
            id=r.id,
            tenant_id=r.tenant_id,
            name=r.name,
            description=r.description,
            severity=r.severity,
            attack_class=r.attack_class,
            prl_source=r.prl_source,
            compiled=r.compiled,
            enabled=r.enabled,
            version=r.version,
            author=r.author,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )

    @strawberry.mutation(description="Bulk acknowledge all open alerts.")
    async def bulk_acknowledge_alerts(self, info: Info) -> int:
        from app.services import alert_service

        ctx = _ctx(info)
        _logger.info("graphql_mutation", operation="bulk_acknowledge_alerts", user_id=str(ctx.user.user_id))
        await ctx.require_permission("alerts.acknowledge")

        count = await alert_service.bulk_acknowledge(ctx.db, user_id=ctx.user.user_id)

        if count > 0:
            await ctx.audit(
                action="alert.bulk_acknowledge",
                resource_type="alert",
                details={"count": count, "via": "graphql"},
            )

        _logger.info("graphql_mutation_ok", operation="bulk_acknowledge_alerts", count=count)
        return count
