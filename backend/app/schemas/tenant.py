# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Tenant management (S5)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

class TenantCreate(BaseModel):
    """Create a new tenant."""

    name: str = Field(..., min_length=2, max_length=128)
    slug: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9-]*$")
    plan: str = Field("community", pattern=r"^(community|starter|business|enterprise)$")
    max_users: int = Field(100, ge=1, le=100000)
    max_agents: int = Field(50, ge=1, le=100000)
    max_events_per_day: int = Field(10_000_000, ge=1000)
    admin_email: str = Field(..., description="Email for the first admin user")
    admin_password: str = Field(..., min_length=12, max_length=256)
    admin_name: str | None = None

class TenantUpdate(BaseModel):
    """Update tenant settings (partial)."""

    name: str | None = Field(None, min_length=2, max_length=128)
    plan: str | None = Field(None, pattern=r"^(community|starter|business|enterprise)$")
    settings: dict | None = None
    max_users: int | None = Field(None, ge=1, le=100000)
    max_agents: int | None = Field(None, ge=1, le=100000)
    max_events_per_day: int | None = Field(None, ge=1000)

class TenantResponse(PhantexBase):
    """Tenant info."""

    id: uuid.UUID
    name: str
    slug: str
    plan: str
    settings: dict = {}
    is_active: bool = True
    max_users: int = 100
    max_agents: int = 50
    max_events_per_day: int = 10_000_000
    onboarded_at: datetime | None = None
    suspended_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

class TenantUsageResponse(PhantexBase):
    """Tenant usage metrics."""

    tenant_id: uuid.UUID
    user_count: int = 0
    agent_count: int = 0
    events_today: int = 0
    alerts_open: int = 0
    storage_bytes: int = 0
