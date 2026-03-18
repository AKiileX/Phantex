# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — User management (admin CRUD + self-service password change)."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import PhantexBase

# ── Request Schemas ───────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    """Create a new user (admin only)."""

    email: EmailStr
    password: str = Field(
        ...,
        min_length=12,
        max_length=256,
        description="Must be 12+ chars with uppercase, lowercase, digit, and special character",
    )
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    name: str | None = Field(None, max_length=255)

class UserUpdate(BaseModel):
    """Update user attributes (admin only)."""

    role: Literal["admin", "analyst", "viewer"] | None = None
    name: str | None = Field(None, max_length=255)
    is_active: bool | None = None

class PasswordChange(BaseModel):
    """Change own password (any authenticated user)."""

    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(
        ...,
        min_length=12,
        max_length=256,
        description="Must be 12+ chars with uppercase, lowercase, digit, and special character",
    )

# ── Response Schemas ──────────────────────────────────────────────────────────

class UserDetail(PhantexBase):
    """Detailed user info (admin view)."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: str
    name: str | None = None
    is_active: bool = True
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None = None

class UserSummary(PhantexBase):
    """Brief user info for list views."""

    id: uuid.UUID
    email: str
    role: str
    name: str | None = None
    is_active: bool = True
