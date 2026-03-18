# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Policy Pydantic Schemas.

Defines request/response schemas for the policy CRUD API.
Supports both JSON and YAML input (YAML is parsed server-side).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ── Policy Rule Override ──────────────────────────────────────────────────────

class PolicyRuleOverride(BaseModel):
    """Override settings for a specific PRL rule within a policy."""

    name: str = Field(..., min_length=1, max_length=128)
    enabled: bool = True
    severity_override: str | None = Field(None, pattern=r"^(info|low|medium|high|critical)$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    notifications: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("parameters")
    @classmethod
    def cap_parameters(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 50:
            raise ValueError("Too many parameters (max 50)")
        return v

    @field_validator("notifications")
    @classmethod
    def cap_notifications(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(v) > 20:
            raise ValueError("Too many notifications (max 20)")
        return v

# ── Policy Schedule ──────────────────────────────────────────────────────────

class PolicySchedule(BaseModel):
    """Scheduling config for alert suppression."""

    active_hours: str | None = Field(
        None,
        description="Active hours in 'HH:MM-HH:MM TZ' format",
        max_length=64,
    )
    weekend: str | None = Field(
        None,
        pattern=r"^(suppress|alert|inherit)$",
        description="Weekend behavior: suppress non-critical, alert all, or inherit default",
    )

# ── Policy Scope ─────────────────────────────────────────────────────────────

class PolicyScope(BaseModel):
    """Scope: which agents/frameworks this policy targets."""

    agent_tags: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)

    @field_validator("agent_tags", "frameworks")
    @classmethod
    def validate_tag_length(cls, v: list[str]) -> list[str]:
        for tag in v:
            if len(tag) > 128:
                raise ValueError(f"Tag too long (max 128 chars): {tag[:32]}...")
            if not re.match(r"^[a-zA-Z0-9_\-\.]+$", tag):
                raise ValueError(f"Invalid tag format: {tag[:32]}")
        if len(v) > 50:
            raise ValueError("Too many tags (max 50)")
        return v

# ── Policy Definition ────────────────────────────────────────────────────────

class PolicyDefinition(BaseModel):
    """Full policy definition (what gets stored in JSONB)."""

    rules: list[PolicyRuleOverride] = Field(default_factory=list)
    schedule: PolicySchedule | None = None
    scope: PolicyScope = Field(default_factory=PolicyScope)

    @field_validator("rules")
    @classmethod
    def validate_rules_limit(cls, v: list[PolicyRuleOverride]) -> list[PolicyRuleOverride]:
        if len(v) > 100:
            raise ValueError("Too many rule overrides (max 100)")
        # Check for duplicate rule names
        names = [r.name for r in v]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate rule names in policy")
        return v

# ── Create / Update Requests ─────────────────────────────────────────────────

class PolicyCreateRequest(BaseModel):
    """Create a new policy."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field("", max_length=2048)
    enabled: bool = True
    definition: PolicyDefinition = Field(default_factory=PolicyDefinition)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.\s]+$", v.strip()):
            raise ValueError("Policy name must contain only alphanumeric chars, spaces, hyphens, underscores, dots")
        return v.strip()

class PolicyUpdateRequest(BaseModel):
    """Update an existing policy (partial updates supported)."""

    name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=2048)
    enabled: bool | None = None
    definition: PolicyDefinition | None = None
    change_summary: str = Field("", max_length=512)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            if not re.match(r"^[a-zA-Z0-9_\-\.\s]+$", v.strip()):
                raise ValueError("Policy name must contain only alphanumeric chars, spaces, hyphens, underscores, dots")
            return v.strip()
        return v

class PolicyValidateRequest(BaseModel):
    """Validate policy YAML/JSON without saving."""

    yaml_content: str | None = Field(None, max_length=65536)
    json_content: PolicyDefinition | None = None

# ── Response Schemas ─────────────────────────────────────────────────────────

class PolicyResponse(BaseModel):
    """Full policy response."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str
    version: int
    enabled: bool
    definition: dict
    scope_agent_tags: list[str]
    scope_frameworks: list[str]
    created_by: uuid.UUID
    updated_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

class PolicyListResponse(BaseModel):
    """Paginated policy list."""

    items: list[PolicyResponse]
    total: int
    page: int
    page_size: int

class PolicyVersionResponse(BaseModel):
    """Policy version history entry."""

    id: uuid.UUID
    policy_id: uuid.UUID
    version: int
    definition: dict
    change_summary: str
    created_by: uuid.UUID
    created_at: datetime

class PolicyValidationResult(BaseModel):
    """Result of policy validation."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    parsed: dict | None = None
