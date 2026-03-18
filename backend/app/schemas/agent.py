# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Agent (AI agents)."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Response ──────────────────────────────────────────────────────────────────

class AgentResponse(PhantexBase):
    """Agent details returned by the API."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    paid: str
    name: str | None = None
    framework: str | None = None
    framework_ver: str | None = None
    process_pid: int | None = None
    exe_path: str | None = None
    cmdline: str | None = None
    container_id: str | None = None
    container_image: str | None = None
    host_id: str | None = None
    sensor_id: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    cpu_usage_pct: float | None = None
    memory_mb: int | None = None
    status: str
    first_seen: datetime
    last_seen: datetime
    updated_at: datetime
    tags: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict, alias="metadata_")

class AgentSummary(PhantexBase):
    """Compact agent info for list views."""

    id: uuid.UUID
    paid: str
    name: str | None = None
    framework: str | None = None
    status: str
    ip_address: str | None = None
    hostname: str | None = None
    os_type: str | None = None
    tags: dict = Field(default_factory=dict)
    last_seen: datetime

# ── Request ───────────────────────────────────────────────────────────────────

class AgentUpdate(BaseModel):
    """Fields that can be updated on an agent (admin/analyst only)."""

    name: str | None = Field(None, max_length=255)
    status: Literal["active", "stale", "offline", "terminated", "quarantined"] | None = None
    tags: dict[str, str] | None = None

# ── Query Filters ─────────────────────────────────────────────────────────────

class AgentFilter(BaseModel):
    """Query parameters for filtering agents."""

    status: Literal["active", "stale", "offline", "terminated", "quarantined"] | None = None
    framework: str | None = Field(None, max_length=200)
    search: str | None = Field(None, max_length=200)  # Name or PAID partial match
    tag: str | None = Field(None, max_length=200)  # Filter by tag key=value
