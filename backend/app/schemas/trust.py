# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Trust Graph API Schemas.

Pydantic models wrapping the gRPC TrustClient dataclasses
for REST serialisation.  Used by ``routers/trust.py``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

class TrustFactorResponse(BaseModel):
    """A single trust factor (dimension) within a score breakdown."""

    name: str
    weight: float
    value: float

class TrustScoreResponse(BaseModel):
    """Full trust score for a single entity."""

    entity_id: str
    entity_type: str
    trust_score: float = Field(ge=0.0, le=1.0)
    factors: list[TrustFactorResponse] = []
    last_updated: float | None = None

class TrustGraphNodeResponse(BaseModel):
    """A node in the trust neighbourhood graph."""

    id: str
    entity_type: str
    trust_score: float = Field(ge=0.0, le=1.0)
    metadata: dict[str, str] = {}

class TrustGraphEdgeResponse(BaseModel):
    """An edge in the trust neighbourhood graph."""

    source_id: str
    target_id: str
    edge_type: str
    count: int = 0
    weight: float = 0.0

class TrustGraphResponse(BaseModel):
    """Full trust graph neighbourhood for a tenant or entity."""

    nodes: list[TrustGraphNodeResponse] = []
    edges: list[TrustGraphEdgeResponse] = []
    truncated: bool = False

class TrustHealthResponse(BaseModel):
    """Trust engine health status."""

    status: str = "NOT_SERVING"
    total_nodes: int = 0
    total_edges: int = 0
    tenants: int = 0
    uptime_secs: float = 0.0
