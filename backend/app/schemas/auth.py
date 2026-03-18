# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Auth (login, tokens, user context)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import PhantexBase

# ── Request Schemas ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """Login with email + password."""

    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)

class RegisterPasswordRequest(BaseModel):
    """Validates password for user creation (12-char minimum enforced)."""

    password: str = Field(..., min_length=12, max_length=256)

class RefreshRequest(BaseModel):
    """Refresh access token using a refresh token."""

    refresh_token: str = Field(..., max_length=256)

# ── Response Schemas ──────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    """JWT token pair returned on login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires
    must_change_password: bool = False

class UserResponse(PhantexBase):
    """Public user info (never includes password hash)."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: str
    name: str | None = None
    is_active: bool = True
    created_at: datetime
    last_login: datetime | None = None
    must_change_password: bool = False

# ── Internal (used by middleware, not exposed in API) ─────────────────────────

class TokenPayload(BaseModel):
    """Decoded JWT access token payload."""

    sub: str  # user_id as string
    tenant_id: str
    role: str
    mcp: bool = False  # must_change_password
    exp: int  # expiry timestamp
    iat: int  # issued at

class CurrentUser(BaseModel):
    """Authenticated user context, injected into requests."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str
    email: str | None = None
    must_change_password: bool = False
