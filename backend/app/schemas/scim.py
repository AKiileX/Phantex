# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — SCIM 2.0 provisioning (RFC 7643/7644)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── SCIM Token Management ────────────────────────────────────────────────────

class SCIMTokenCreate(BaseModel):
    """Create a SCIM bearer token for a tenant."""

    description: str = Field("", max_length=256)
    expires_in_days: int | None = Field(None, ge=1, le=365)

class SCIMTokenResponse(PhantexBase):
    """SCIM token info (token value only returned once at creation)."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    description: str
    is_active: bool
    created_at: datetime
    expires_at: datetime | None = None
    token: str | None = None  # Only set on creation

# ── SCIM 2.0 Core Schemas (RFC 7643) ─────────────────────────────────────────

class SCIMName(BaseModel):
    """SCIM name component."""

    formatted: str | None = None
    familyName: str | None = None
    givenName: str | None = None

class SCIMEmail(BaseModel):
    """SCIM email."""

    value: str
    type: str = "work"
    primary: bool = True

class SCIMGroup(BaseModel):
    """SCIM group reference."""

    value: str  # group ID
    display: str | None = None

class SCIMMeta(BaseModel):
    """SCIM resource meta."""

    resourceType: str = "User"
    created: str | None = None
    lastModified: str | None = None
    location: str | None = None

class SCIMUser(BaseModel):
    """SCIM 2.0 User resource (RFC 7643 §4.1)."""

    schemas: list[str] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    id: str | None = None
    externalId: str | None = None
    userName: str
    name: SCIMName | None = None
    displayName: str | None = None
    emails: list[SCIMEmail] = []
    active: bool = True
    groups: list[SCIMGroup] = []
    meta: SCIMMeta | None = None

class SCIMUserCreate(BaseModel):
    """Inbound SCIM user creation request."""

    schemas: list[str] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    externalId: str | None = None
    userName: str
    name: SCIMName | None = None
    displayName: str | None = None
    emails: list[SCIMEmail] = []
    active: bool = True
    password: str | None = None

class SCIMPatchOp(BaseModel):
    """A single SCIM PATCH operation."""

    op: str = Field(..., pattern=r"^(add|remove|replace)$")
    path: str | None = None
    value: str | dict | list | bool | None = None

class SCIMPatchRequest(BaseModel):
    """SCIM PATCH request (RFC 7644 §3.5.2)."""

    schemas: list[str] = ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
    Operations: list[SCIMPatchOp]

class SCIMListResponse(BaseModel):
    """SCIM list response (RFC 7644 §3.4.2)."""

    schemas: list[str] = ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int = 100
    Resources: list[SCIMUser] = []

class SCIMError(BaseModel):
    """SCIM error response (RFC 7644 §3.12)."""

    schemas: list[str] = ["urn:ietf:params:scim:api:messages:2.0:Error"]
    detail: str
    status: str  # HTTP status code as string
    scimType: str | None = None
