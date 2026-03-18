# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex GraphQL — Strawberry Types.

Mirrors the existing Pydantic REST schemas so the GraphQL layer
exposes the same data shapes as the REST API.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import strawberry
from strawberry.scalars import JSON

# ── Alert Types ───────────────────────────────────────────────────────────────

@strawberry.type
class AlertType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: str | None = None
    event_id: uuid.UUID | None = None
    rule_id: uuid.UUID | None = None
    severity: str
    title: str
    description: str | None = None
    status: str
    context: JSON
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    resolved_by: uuid.UUID | None = None

@strawberry.type
class AlertSummaryType:
    id: uuid.UUID
    severity: str
    title: str
    status: str
    created_at: datetime
    agent_id: str | None = None
    rule_id: uuid.UUID | None = None
    event_id: uuid.UUID | None = None

# ── Agent Types ───────────────────────────────────────────────────────────────

@strawberry.type
class AgentType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    paid: str
    name: str | None = None
    framework: str | None = None
    framework_ver: str | None = None
    status: str
    ip_address: str | None = None
    hostname: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    container_id: str | None = None
    container_image: str | None = None
    host_id: str | None = None
    sensor_id: str | None = None
    cpu_usage_pct: float | None = None
    memory_mb: int | None = None
    first_seen: datetime
    last_seen: datetime
    updated_at: datetime
    tags: JSON
    metadata: JSON

@strawberry.type
class AgentSummaryType:
    id: uuid.UUID
    paid: str
    name: str | None = None
    framework: str | None = None
    status: str
    ip_address: str | None = None
    hostname: str | None = None
    os_type: str | None = None
    tags: JSON
    last_seen: datetime

# ── Event Types ───────────────────────────────────────────────────────────────

@strawberry.type
class EventType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: str | None = None
    sensor_id: str | None = None
    event_type: str
    severity: str
    timestamp: datetime
    raw_data: JSON
    created_at: datetime

@strawberry.type
class EventSummaryType:
    id: uuid.UUID
    agent_id: str | None = None
    event_type: str
    severity: str
    timestamp: datetime

# ── Rule Types ────────────────────────────────────────────────────────────────

@strawberry.type
class RuleType:
    id: uuid.UUID
    tenant_id: uuid.UUID | None = None
    name: str
    description: str | None = None
    severity: str
    attack_class: str | None = None
    prl_source: str
    compiled: JSON | None = None
    enabled: bool
    version: int
    author: str | None = None
    created_at: datetime
    updated_at: datetime

@strawberry.type
class RuleSummaryType:
    id: uuid.UUID
    name: str
    severity: str
    attack_class: str | None = None
    enabled: bool
    version: int
    author: str | None = None
    created_at: datetime

# ── Trust Types ───────────────────────────────────────────────────────────────

@strawberry.type
class TrustFactorType:
    name: str
    weight: float
    value: float

@strawberry.type
class TrustScoreType:
    entity_id: str
    entity_type: str
    trust_score: float
    factors: list[TrustFactorType]
    last_updated: float | None = None

@strawberry.type
class TrustGraphNodeType:
    id: str
    entity_type: str
    trust_score: float
    metadata: JSON

@strawberry.type
class TrustGraphEdgeType:
    source_id: str
    target_id: str
    edge_type: str
    count: int = 0
    weight: float = 0.0

@strawberry.type
class TrustGraphType:
    nodes: list[TrustGraphNodeType]
    edges: list[TrustGraphEdgeType]
    truncated: bool = False

# ── Pagination ────────────────────────────────────────────────────────────────

@strawberry.type
class PageInfo:
    total: int
    limit: int
    offset: int
    has_next: bool

@strawberry.type
class AlertConnection:
    items: list[AlertSummaryType]
    page_info: PageInfo

@strawberry.type
class AgentConnection:
    items: list[AgentSummaryType]
    page_info: PageInfo

@strawberry.type
class EventConnection:
    items: list[EventSummaryType]
    page_info: PageInfo

@strawberry.type
class RuleConnection:
    items: list[RuleSummaryType]
    page_info: PageInfo

# ── Input Types ───────────────────────────────────────────────────────────────

@strawberry.input
class AlertFilterInput:
    status: str | None = None
    severity: str | None = None
    agent_id: str | None = None
    since: datetime | None = None
    search: str | None = None

@strawberry.input
class AgentFilterInput:
    status: str | None = None
    framework: str | None = None
    search: str | None = None
    tag: str | None = None

@strawberry.input
class EventFilterInput:
    agent_id: str | None = None
    event_type: str | None = None
    severity: str | None = None
    since: datetime | None = None
    until: datetime | None = None

@strawberry.input
class RuleFilterInput:
    enabled: bool | None = None
    severity: str | None = None
    attack_class: str | None = None
    search: str | None = None

@strawberry.input
class AlertUpdateInput:
    status: str

@strawberry.input
class RuleCreateInput:
    name: str
    description: str | None = None
    severity: str = "medium"
    attack_class: str | None = None
    prl_source: str
    enabled: bool = True

@strawberry.input
class RuleUpdateInput:
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    attack_class: str | None = None
    prl_source: str | None = None
    enabled: bool | None = None
