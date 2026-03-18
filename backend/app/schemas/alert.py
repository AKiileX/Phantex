# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Alert (security alerts)."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import PhantexBase

# ── Response ──────────────────────────────────────────────────────────────────

class AlertResponse(PhantexBase):
    """Full alert details."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: str | None = None
    event_id: uuid.UUID | None = None
    rule_id: uuid.UUID | None = None
    severity: str
    title: str
    description: str | None = None
    status: str
    context: dict
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    resolved_by: uuid.UUID | None = None

class AlertSummary(PhantexBase):
    """Compact alert info for list views."""

    id: uuid.UUID
    severity: str
    title: str
    status: str
    created_at: datetime
    agent_id: str | None = None
    rule_id: uuid.UUID | None = None
    event_id: uuid.UUID | None = None

# ── Request ───────────────────────────────────────────────────────────────────

class AlertUpdate(BaseModel):
    """Update an alert's status (acknowledge, resolve, mark false positive)."""

    status: Literal["open", "acknowledged", "resolved", "false_positive"]

# ── Query Filters ─────────────────────────────────────────────────────────────

class AlertFilter(BaseModel):
    """Query parameters for filtering alerts."""

    status: Literal["open", "acknowledged", "resolved", "false_positive"] | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    agent_id: str | None = None
    since: datetime | None = None
    search: str | None = None
