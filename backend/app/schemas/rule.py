# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Rule (PRL detection rules)."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Response ──────────────────────────────────────────────────────────────────

class RuleResponse(PhantexBase):
    """Full rule details."""

    id: uuid.UUID
    tenant_id: uuid.UUID | None = None
    name: str
    description: str | None = None
    severity: str
    attack_class: str | None = None
    prl_source: str
    compiled: dict | None = None
    enabled: bool
    version: int
    author: str | None = None
    created_at: datetime
    updated_at: datetime

class RuleSummary(PhantexBase):
    """Compact rule info for list views."""

    id: uuid.UUID
    tenant_id: uuid.UUID | None = None
    name: str
    description: str | None = None
    severity: str
    attack_class: str | None = None
    prl_source: str
    enabled: bool
    version: int
    author: str | None = None
    created_at: datetime
    updated_at: datetime

# ── Request ───────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    """Create a new detection rule."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str | None = Field(None, max_length=4096)
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    attack_class: str | None = Field(None, max_length=128)
    prl_source: str = Field(..., min_length=1, max_length=65536)
    enabled: bool = True

class RuleUpdate(BaseModel):
    """Update an existing rule."""

    name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=4096)
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    attack_class: str | None = Field(None, max_length=128)
    prl_source: str | None = Field(None, min_length=1, max_length=65536)
    enabled: bool | None = None

# ── Query Filters ─────────────────────────────────────────────────────────────

class RuleFilter(BaseModel):
    """Query parameters for filtering rules."""

    enabled: bool | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    attack_class: str | None = Field(None, max_length=128)
    search: str | None = Field(None, max_length=200)  # Name partial match
