# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Timeline (L1) and MITRE ATLAS (L2)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import PhantexBase

# ── Timeline Schemas ──────────────────────────────────────────────────────────

class TimelineEvent(PhantexBase):
    """A single event in the investigation timeline."""

    id: str  # str to support both PG UUIDs and ClickHouse event IDs
    source: Literal["postgres", "clickhouse", "neo4j", "trust_engine"]
    event_type: str
    severity: str = "info"
    timestamp: datetime
    agent_id: str | None = None
    description: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    trust_score: float | None = None
    atlas_techniques: list[dict[str, Any]] = Field(default_factory=list)
    attack_chain_position: int | None = None
    session_id: str | None = None

class TimelineSession(PhantexBase):
    """A group of related events (< 5 min gap between consecutive events)."""

    session_id: str
    start: datetime
    end: datetime
    event_count: int
    severities: dict[str, int] = Field(default_factory=dict)  # severity → count

class DataSourceStatus(PhantexBase):
    """Availability status for a data source used in timeline assembly."""

    source: str
    available: bool
    event_count: int = 0
    error: str | None = None
    latency_ms: float | None = None

class TimelineResponse(PhantexBase):
    """Full timeline API response."""

    agent_id: str | None = None
    alert_id: str | None = None
    range_hours: float
    total_events: int
    events: list[TimelineEvent]
    sessions: list[TimelineSession] = Field(default_factory=list)
    data_sources: list[DataSourceStatus] = Field(default_factory=list)
    has_more: bool = False
    next_cursor: str | None = None

# ── MITRE ATLAS Schemas ───────────────────────────────────────────────────────

class AtlasTechnique(PhantexBase):
    """MITRE ATLAS technique summary."""

    id: str
    name: str
    tactic: str = ""
    url: str = ""
    detected: bool = False
    detected_by: list[dict[str, str]] = Field(default_factory=list)
    best_confidence: str = "none"

class AtlasCoverageResponse(PhantexBase):
    """ATLAS coverage matrix response."""

    total_techniques: int
    detected_techniques: int
    coverage_pct: float
    techniques: list[AtlasTechnique]

class AtlasRuleMappingResponse(PhantexBase):
    """Mapping detail for a single rule."""

    rule_name: str
    atlas_techniques: list[dict[str, str]] = Field(default_factory=list)
    confidence: str = "none"
    rationale: str = ""
