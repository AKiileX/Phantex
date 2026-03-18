# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Sensor (deployed sensor instances)."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Response ──────────────────────────────────────────────────────────────────

class SensorResponse(PhantexBase):
    """Full sensor details returned by the API."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    sensor_id: str
    hostname: str | None = None
    ip_address: str | None = None
    kernel: str | None = None
    arch: str | None = None
    version: str | None = None
    os_type: str | None = None
    status: str
    probes_loaded: int = 0
    probes_total: int = 0
    events_read: int = 0
    events_sent: int = 0
    events_dropped: int = 0
    parse_errors: int = 0
    agents_tracked: int = 0
    uptime_seconds: int = 0
    cpu_percent: float | None = None
    memory_bytes: int | None = None
    buffer_used: int = 0
    first_seen: datetime
    last_heartbeat: datetime
    updated_at: datetime
    decommissioned_at: datetime | None = None
    decommissioned_by: str | None = None
    decommission_reason: str | None = None
    tags: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict, alias="metadata_")

class SensorSummary(PhantexBase):
    """Compact sensor info for list views."""

    id: uuid.UUID
    sensor_id: str
    hostname: str | None = None
    ip_address: str | None = None
    version: str | None = None
    os_type: str | None = None
    status: str
    probes_loaded: int = 0
    probes_total: int = 0
    events_sent: int = 0
    events_dropped: int = 0
    agents_tracked: int = 0
    cpu_percent: float | None = None
    memory_bytes: int | None = None
    last_heartbeat: datetime

# ── Query Filters ─────────────────────────────────────────────────────────────

class SensorFilter(BaseModel):
    """Query parameters for filtering sensors."""

    status: Literal["online", "degraded", "offline", "decommissioned"] | None = None
    search: str | None = Field(None, max_length=200)
