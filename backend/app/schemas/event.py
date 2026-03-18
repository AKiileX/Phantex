# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Event (security events)."""

import uuid
from datetime import datetime
from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Response ──────────────────────────────────────────────────────────────────

class EventResponse(PhantexBase):
    """Full event details."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: str | None = None
    sensor_id: str | None = None
    event_type: str
    severity: str
    timestamp: datetime
    raw_data: dict
    created_at: datetime

class EventSummary(PhantexBase):
    """Compact event info for list views."""

    id: uuid.UUID
    agent_id: str | None = None
    event_type: str
    severity: str
    timestamp: datetime

# ── Query Filters ─────────────────────────────────────────────────────────────

class EventFilter(BaseModel):
    """Query parameters for filtering events."""

    agent_id: str | None = None
    event_type: str | None = Field(None, max_length=100)
    severity: str | None = Field(None, max_length=100)
    since: datetime | None = None
    until: datetime | None = None
    agent_only: bool = True
