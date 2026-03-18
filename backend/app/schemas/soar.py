# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SOAR Integration Schemas

Pydantic models for SOAR API requests and responses.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── API Key schemas ───────────────────────────────────────────────────────────

class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Human-readable key name")
    scopes: list[str] = Field(
        default=["*"],
        description="Allowed scopes: alerts.read, alerts.write, actions.execute, enrichment.read, webhooks.manage, *",
    )
    expires_in_days: int | None = Field(
        default=None,
        ge=1,
        le=3650,
        description="Days until expiry. Null = never expires.",
    )

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: list[str]) -> list[str]:
        allowed = {"*", "alerts.read", "alerts.write", "actions.execute", "enrichment.read", "webhooks.manage"}
        for scope in v:
            if scope not in allowed:
                raise ValueError(f"Unknown scope '{scope}'. Allowed: {', '.join(sorted(allowed))}")
        return v

class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    revoked: bool

    model_config = ConfigDict(from_attributes=True)

class ApiKeyCreatedResponse(ApiKeyResponse):
    """Returned only on creation — includes the raw key (shown once)."""

    raw_key: str = Field(..., description="Full API key — store securely, shown only once")

# ── Webhook Subscription schemas ──────────────────────────────────────────────

VALID_EVENT_TYPES = frozenset(
    {
        "alert.created",
        "alert.updated",
        "alert.resolved",
        "action.executed",
        "action.shadow",
        "escalation.triggered",
        "escalation.reset",
        "agent.isolated",
        "agent.trust_changed",
    }
)

class CreateWebhookRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=10, max_length=2048)
    secret: str | None = Field(default=None, max_length=500, description="HMAC signing secret")
    event_types: list[str] = Field(default=["alert.created"])
    severity_filter: list[str] | None = Field(
        default=None,
        description="Filter by severity: critical, high, medium, low, info. Null = all.",
    )
    retry_count: int = Field(default=3, ge=0, le=10)
    retry_delay_sec: int = Field(default=30, ge=1, le=3600)
    timeout_sec: int = Field(default=15, ge=1, le=120)

    @field_validator("url")
    @classmethod
    def validate_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("Webhook URL must use HTTPS")
        return v

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, v: list[str]) -> list[str]:
        for et in v:
            if et not in VALID_EVENT_TYPES:
                raise ValueError(f"Unknown event type '{et}'. Valid: {', '.join(sorted(VALID_EVENT_TYPES))}")
        return v

    @field_validator("severity_filter")
    @classmethod
    def validate_severity_filter(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        allowed = {"critical", "high", "medium", "low", "info"}
        for s in v:
            if s not in allowed:
                raise ValueError(f"Unknown severity '{s}'")
        return v

class UpdateWebhookRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    url: str | None = Field(default=None, max_length=2048)
    secret: str | None = Field(default=None, max_length=500)
    event_types: list[str] | None = None
    severity_filter: list[str] | None = None
    enabled: bool | None = None
    retry_count: int | None = Field(default=None, ge=0, le=10)
    retry_delay_sec: int | None = Field(default=None, ge=1, le=3600)
    timeout_sec: int | None = Field(default=None, ge=1, le=120)

    @field_validator("url")
    @classmethod
    def validate_https(cls, v: str | None) -> str | None:
        if v and not v.startswith("https://"):
            raise ValueError("Webhook URL must use HTTPS")
        return v

    @field_validator("event_types")
    @classmethod
    def validate_event_types(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for et in v:
            if et not in VALID_EVENT_TYPES:
                raise ValueError(f"Unknown event type '{et}'")
        return v

class WebhookResponse(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    event_types: list[str]
    severity_filter: list[str] | None
    enabled: bool
    retry_count: int
    retry_delay_sec: int
    timeout_sec: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class WebhookLogEntry(BaseModel):
    id: uuid.UUID
    subscription_id: uuid.UUID
    event_type: str
    event_id: uuid.UUID | None
    status_code: int | None
    response_ms: int | None
    attempt: int
    success: bool
    error: str | None
    created_at: datetime

class WebhookLogResponse(BaseModel):
    total: int
    entries: list[WebhookLogEntry]

# ── SOAR Action schemas ──────────────────────────────────────────────────────

VALID_SOAR_ACTIONS = frozenset(
    {
        "isolate_agent",
        "dismiss_alert",
        "escalate_alert",
        "create_rule",
        "acknowledge_alert",
        "resolve_alert",
        "add_tag",
        "trust_penalty",
        "collect_forensics",
    }
)

class SOARActionRequest(BaseModel):
    action: str = Field(..., description="Action to execute")
    target_type: Literal["alert", "agent", "rule"] = Field(...)
    target_id: uuid.UUID = Field(...)
    params: dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")
    reason: str = Field(default="", max_length=1000, description="SOC/SOAR justification")

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in VALID_SOAR_ACTIONS:
            raise ValueError(f"Unknown action '{v}'. Valid: {', '.join(sorted(VALID_SOAR_ACTIONS))}")
        return v

class SOARActionResponse(BaseModel):
    id: uuid.UUID
    action: str
    target_type: str
    target_id: uuid.UUID
    result: str
    error: str | None = None
    created_at: datetime

class SOARActionLogResponse(BaseModel):
    total: int
    entries: list[SOARActionResponse]

# ── Enrichment schemas ────────────────────────────────────────────────────────

class AlertEnrichmentResponse(BaseModel):
    alert_id: uuid.UUID
    severity: str
    status: str
    rule_name: str | None = None
    event_type: str | None = None
    agent_id: str | None = None
    agent_hostname: str | None = None
    agent_trust_score: float | None = None
    atlas_mapping: dict[str, Any] | None = None
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    related_alerts: list[dict[str, Any]] = Field(default_factory=list)

# ── SOAR Integration schemas ─────────────────────────────────────────────────

class CreateIntegrationRequest(BaseModel):
    platform: Literal["xsoar", "phantom", "tines", "generic"] = Field(...)
    name: str = Field(..., min_length=1, max_length=200)
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

class UpdateIntegrationRequest(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    config: dict[str, Any] | None = None
    enabled: bool | None = None

class IntegrationResponse(BaseModel):
    id: uuid.UUID
    platform: str
    name: str
    config: dict[str, Any]  # secrets masked
    enabled: bool
    last_sync_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class IntegrationListResponse(BaseModel):
    total: int
    integrations: list[IntegrationResponse]
