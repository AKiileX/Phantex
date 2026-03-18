# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Pydantic schemas — Agent Tagging & Policy

P1: Agent tag CRUD
P2: Rule exemptions
P3: Alert routing rules
P4: Maintenance windows
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

# ══════════════════════════════════════════════════════════════════════════════
#  P1: Agent Tags
# ══════════════════════════════════════════════════════════════════════════════

class AgentTagsUpdate(BaseModel):
    """Set tags on an agent (key-value pairs)."""

    tags: dict[str, str] = Field(..., max_length=50)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 50:
            raise ValueError("Too many tags (max 50)")
        for key, val in v.items():
            if not re.match(r"^[a-zA-Z0-9_\-\.]{1,64}$", key):
                raise ValueError(
                    f"Invalid tag key '{key[:32]}': alphanumeric, hyphens, underscores, dots only (max 64 chars)"
                )
            if len(val) > 256:
                raise ValueError(f"Tag value too long for key '{key}' (max 256 chars)")
            if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", val):
                raise ValueError(f"Tag value for key '{key}' contains control characters")
        return v

class AgentTagsResponse(BaseModel):
    """Agent tags response."""

    agent_id: uuid.UUID
    tags: dict[str, str]
    updated_at: datetime

# ══════════════════════════════════════════════════════════════════════════════
#  P2: Rule Exemptions
# ══════════════════════════════════════════════════════════════════════════════

def _sanitize_text(value: str, field_name: str, max_len: int = 256) -> str:
    """Strip control characters and validate length."""
    # Remove ASCII control chars (except tab, newline)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    if len(cleaned) > max_len:
        raise ValueError(f"{field_name} too long (max {max_len} chars)")
    return cleaned

def _validate_match_tags(v: dict[str, str]) -> dict[str, str]:
    """Shared match_tags validation for exemptions, routing rules, windows."""
    if len(v) > 20:
        raise ValueError("Too many match conditions (max 20)")
    for key, val in v.items():
        if not re.match(r"^[a-zA-Z0-9_\-\.]{1,64}$", key):
            raise ValueError(f"Invalid match_tags key '{key[:32]}': alphanumeric, hyphens, underscores, dots only")
        if len(val) > 256:
            raise ValueError(f"match_tags value too long for key '{key}' (max 256 chars)")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", val):
            raise ValueError(f"match_tags value for key '{key}' contains control characters")
    return v

def _validate_channel_ids(channels: list[str]) -> list[str]:
    """Validate channel ID format."""
    for ch in channels:
        if not re.match(r"^[a-zA-Z0-9_\-\.]{1,128}$", ch):
            raise ValueError(
                f"Invalid channel ID '{ch[:32]}': alphanumeric, hyphens, underscores, dots only (max 128 chars)"
            )
    return channels

class ExemptionCreate(BaseModel):
    """Create a rule exemption."""

    rule_name: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    match_tags: dict[str, str] = Field(..., description="Tag match conditions, e.g. {'agent.tag.role': 'ci-runner'}")
    reason: str = Field(..., min_length=1, max_length=1024)
    expires_at: datetime | None = None

    @field_validator("match_tags")
    @classmethod
    def validate_match_tags(cls, v: dict[str, str]) -> dict[str, str]:
        if not v:
            raise ValueError("match_tags must have at least one condition")
        return _validate_match_tags(v)

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, v: str) -> str:
        return _sanitize_text(v, "reason", 1024)

class ExemptionUpdate(BaseModel):
    """Update an exemption."""

    enabled: bool | None = None
    reason: str | None = Field(None, min_length=1, max_length=1024)
    expires_at: datetime | None = None

class ExemptionResponse(BaseModel):
    """Exemption detail."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    rule_name: str
    match_tags: dict[str, str]
    reason: str
    enabled: bool
    expires_at: datetime | None
    hit_count: int
    last_hit_at: datetime | None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime

# ══════════════════════════════════════════════════════════════════════════════
#  P3: Alert Routing Rules
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

class RoutingRuleCreate(BaseModel):
    """Create a tag-based alert routing rule."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field("", max_length=2048)
    match_tags: dict[str, str] = Field(
        default_factory=dict,
        description="Agent tag conditions for matching",
    )
    severity_min: str = Field("info", pattern=r"^(info|low|medium|high|critical)$")
    channels: list[str] = Field(..., min_length=1, max_length=20)
    priority: int = Field(0, ge=0, le=1000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.\s]+$", v.strip()):
            raise ValueError("Name must be alphanumeric with hyphens, underscores, dots, or spaces")
        return v.strip()

    @field_validator("match_tags")
    @classmethod
    def validate_match_tags(cls, v: dict[str, str]) -> dict[str, str]:
        return _validate_match_tags(v)

    @field_validator("channels")
    @classmethod
    def validate_channels(cls, v: list[str]) -> list[str]:
        return _validate_channel_ids(v)

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: str) -> str:
        return _sanitize_text(v, "description", 2048)

class RoutingRuleUpdate(BaseModel):
    """Update a routing rule."""

    name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=2048)
    match_tags: dict[str, str] | None = None
    severity_min: str | None = Field(None, pattern=r"^(info|low|medium|high|critical)$")
    channels: list[str] | None = Field(None, min_length=1, max_length=20)
    enabled: bool | None = None
    priority: int | None = Field(None, ge=0, le=1000)

    @field_validator("match_tags")
    @classmethod
    def validate_match_tags(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is not None:
            return _validate_match_tags(v)
        return v

    @field_validator("channels")
    @classmethod
    def validate_channels(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            return _validate_channel_ids(v)
        return v

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: str | None) -> str | None:
        if v is not None:
            return _sanitize_text(v, "description", 2048)
        return v

class RoutingRuleResponse(BaseModel):
    """Routing rule detail."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str
    match_tags: dict[str, str]
    severity_min: str
    channels: list[str]
    enabled: bool
    priority: int
    created_by: uuid.UUID
    updated_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

class RoutingSimulationRequest(BaseModel):
    """Simulate routing for a hypothetical alert."""

    severity: str = Field(..., pattern=r"^(info|low|medium|high|critical)$")
    agent_tags: dict[str, str] = Field(default_factory=dict)
    rule_name: str | None = None

class RoutingSimulationResult(BaseModel):
    """Result of routing simulation."""

    matched_rules: list[RoutingRuleResponse]
    channels: list[str]
    would_be_exempted: bool = False
    exemption_reason: str | None = None

# ══════════════════════════════════════════════════════════════════════════════
#  P4: Maintenance Windows
# ══════════════════════════════════════════════════════════════════════════════

# Standard 5-field cron: minute hour day_of_month month day_of_week
_CRON_FIELD = r"(\*|[0-9,\-\/]+)"
_CRON_PATTERN = re.compile(rf"^\s*{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s*$")

class MaintenanceWindowCreate(BaseModel):
    """Create a maintenance window."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field("", max_length=2048)
    cron_schedule: str = Field(..., max_length=128)
    duration_minutes: int = Field(..., ge=1, le=1440)
    rules: list[str] = Field(..., min_length=1, max_length=50)
    match_tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("cron_schedule")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        if not _CRON_PATTERN.match(v):
            raise ValueError(
                f"Invalid cron expression: '{v}'. Expected 5-field cron: minute hour day_of_month month day_of_week"
            )
        return v.strip()

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\.\s]+$", v.strip()):
            raise ValueError("Name must be alphanumeric with hyphens, underscores, dots, or spaces")
        return v.strip()

    @field_validator("match_tags")
    @classmethod
    def validate_match_tags(cls, v: dict[str, str]) -> dict[str, str]:
        return _validate_match_tags(v)

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, v: list[str]) -> list[str]:
        for r in v:
            if not re.match(r"^[a-zA-Z0-9_\-\.\*]{1,128}$", r):
                raise ValueError(f"Invalid rule name '{r[:32]}': alphanumeric, hyphens, underscores, dots, or * only")
        return v

class MaintenanceWindowUpdate(BaseModel):
    """Update a maintenance window."""

    name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=2048)
    cron_schedule: str | None = Field(None, max_length=128)
    duration_minutes: int | None = Field(None, ge=1, le=1440)
    rules: list[str] | None = Field(None, min_length=1, max_length=50)
    match_tags: dict[str, str] | None = None
    enabled: bool | None = None

    @field_validator("cron_schedule")
    @classmethod
    def validate_cron(cls, v: str | None) -> str | None:
        if v is not None and not _CRON_PATTERN.match(v):
            raise ValueError(
                f"Invalid cron expression: '{v}'. Expected 5-field cron: minute hour day_of_month month day_of_week"
            )
        return v.strip() if v else v

    @field_validator("match_tags")
    @classmethod
    def validate_match_tags(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is not None:
            return _validate_match_tags(v)
        return v

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for r in v:
                if not re.match(r"^[a-zA-Z0-9_\-\.\*]{1,128}$", r):
                    raise ValueError(
                        f"Invalid rule name '{r[:32]}': alphanumeric, hyphens, underscores, dots, or * only"
                    )
        return v

class MaintenanceWindowResponse(BaseModel):
    """Maintenance window detail."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str
    cron_schedule: str
    duration_minutes: int
    rules: list[str]
    match_tags: dict[str, str]
    enabled: bool
    next_start: datetime | None
    last_started_at: datetime | None
    last_ended_at: datetime | None
    force_ended_by: uuid.UUID | None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
