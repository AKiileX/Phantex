# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — ABAC (roles, permissions, user-role assignments)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Permission Schemas ────────────────────────────────────────────────────────

class PermissionResponse(PhantexBase):
    """A single permission (resource.action)."""

    id: uuid.UUID
    resource: str
    action: str
    description: str

# ── Role Schemas ──────────────────────────────────────────────────────────────

class RoleCreate(BaseModel):
    """Create a new custom role."""

    name: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    description: str = Field("", max_length=256)
    permission_ids: list[uuid.UUID] = Field(default_factory=list)
    policy: dict = Field(default_factory=dict)

class RoleUpdate(BaseModel):
    """Update a role (partial)."""

    name: str | None = Field(None, min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    description: str | None = Field(None, max_length=256)
    permission_ids: list[uuid.UUID] | None = None
    policy: dict | None = None

class RolePermissionResponse(PhantexBase):
    """A permission grant within a role."""

    permission_id: uuid.UUID
    conditions: dict
    permission: PermissionResponse

class RoleResponse(PhantexBase):
    """Full role with permissions."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str
    is_builtin: bool
    policy: dict
    role_permissions: list[RolePermissionResponse] = []
    created_at: datetime
    updated_at: datetime

class RoleSummary(PhantexBase):
    """Compact role info (for user listings)."""

    id: uuid.UUID
    name: str
    description: str
    is_builtin: bool

# ── User-Role Assignment ─────────────────────────────────────────────────────

class UserRoleAssign(BaseModel):
    """Assign a role to a user."""

    role_id: uuid.UUID

class UserRolesResponse(PhantexBase):
    """A user's assigned roles."""

    user_id: uuid.UUID
    roles: list[RoleSummary]
    effective_permissions: list[str] = []  # ["alerts.read", "rules.write", ...]
