# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — OCSF v1.1 models and PDR export configuration."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── OCSF Base Types ──────────────────────────────────────────────────────────

class OCSFMetadata(BaseModel):
    """OCSF metadata object — present on every event."""

    version: str = "1.1.0"
    product: dict[str, str] = Field(
        default_factory=lambda: {
            "name": "Phantex",
            "vendor_name": "Phantex Security",
            "version": "2.0.0",
        }
    )
    log_name: str = "phantex"
    log_provider: str = "phantex-backend"
    original_time: str | None = None
    uid: str | None = None
    tenant_uid: str | None = None

class OCSFActor(BaseModel):
    """OCSF actor object — who/what performed the action."""

    process: dict[str, Any] | None = None
    user: dict[str, Any] | None = None
    session: dict[str, Any] | None = None

class OCSFEndpoint(BaseModel):
    """OCSF endpoint — source or destination."""

    ip: str | None = None
    port: int | None = None
    domain: str | None = None
    hostname: str | None = None

class OCSFFile(BaseModel):
    """OCSF file object."""

    name: str | None = None
    path: str | None = None
    type_id: int | None = None
    size: int | None = None

class OCSFProcess(BaseModel):
    """OCSF process object."""

    pid: int | None = None
    name: str | None = None
    cmd_line: str | None = None
    file: OCSFFile | None = None
    uid: str | None = None

class OCSFAPI(BaseModel):
    """OCSF API object — for tool/API call events."""

    operation: str | None = None
    service: dict[str, str] | None = None
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None

class OCSFDns(BaseModel):
    """OCSF DNS query object."""

    query: dict[str, str] | None = None
    answers: list[dict[str, str]] = Field(default_factory=list)

class OCSFFinding(BaseModel):
    """OCSF finding info — for Security Finding (2001) events."""

    uid: str | None = None
    title: str | None = None
    desc: str | None = None
    types: list[str] = Field(default_factory=list)
    src_url: str | None = None

# ── OCSF Event Envelope ──────────────────────────────────────────────────────

class OCSFEvent(BaseModel):
    """Full OCSF v1.1 event envelope.

    Every Phantex event/alert maps to one of these.  Required fields:
    metadata, class_uid, category_uid, activity_id, type_uid,
    severity_id, time, message.
    """

    # ── Required
    metadata: OCSFMetadata = Field(default_factory=OCSFMetadata)
    class_uid: int
    class_name: str = ""
    category_uid: int
    category_name: str = ""
    activity_id: int
    activity_name: str = ""
    type_uid: int
    severity_id: int
    severity: str = "Unknown"
    time: str  # ISO 8601
    message: str = ""

    # ── Optional / class-specific
    actor: OCSFActor | None = None
    src_endpoint: OCSFEndpoint | None = None
    dst_endpoint: OCSFEndpoint | None = None
    file: OCSFFile | None = None
    process: OCSFProcess | None = None
    api: OCSFAPI | None = None
    dns: OCSFDns | None = None
    finding_info: OCSFFinding | None = None

    # ── Phantex extensions
    unmapped: dict[str, Any] = Field(
        default_factory=dict,
        description="Phantex-specific fields that don't map to OCSF",
    )
    observables: list[dict[str, Any]] = Field(default_factory=list)
    enrichments: list[dict[str, Any]] = Field(default_factory=list)
    raw_data: str | None = None

    status_id: int | None = None
    status: str | None = None

# ── PDR Export Configuration ──────────────────────────────────────────────────

class PDRChannelConfig(PhantexBase):
    """Configuration for a single PDR export channel."""

    channel_type: Literal["s3", "webhook", "kafka_mirror"]
    enabled: bool = True
    name: str = Field(..., min_length=1, max_length=128)

    # S3-specific
    s3_bucket: str | None = None
    s3_region: str | None = None
    s3_prefix: str | None = Field(None, max_length=256)
    s3_iam_role: str | None = None

    # Webhook-specific
    webhook_url: str | None = None
    webhook_secret: str | None = None  # HMAC signing key

    # Kafka-mirror-specific
    kafka_bootstrap: str | None = None
    kafka_topic: str | None = None
    kafka_sasl_mechanism: str | None = None
    kafka_sasl_username: str | None = None
    kafka_sasl_password: str | None = None

    # Shared
    pii_redaction_enabled: bool = False
    pii_fields_to_redact: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(
        default_factory=list,
        description="Filter: only export these event types. Empty = all.",
    )
    min_severity: int = 1  # 1=info, 5=critical

class PDRChannelCreate(BaseModel):
    """Request body for creating a PDR export channel."""

    channel_type: Literal["s3", "webhook", "kafka_mirror"]
    name: str = Field(..., min_length=1, max_length=128)
    config: dict[str, Any]
    enabled: bool = True

class PDRChannelUpdate(BaseModel):
    """Request body for updating a PDR export channel."""

    name: str | None = Field(None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    enabled: bool | None = None

class PDRChannelResponse(PhantexBase):
    """Response model for a PDR channel (credentials masked)."""

    id: str
    tenant_id: str
    channel_type: str
    name: str
    enabled: bool
    config_masked: dict[str, Any]
    created_at: str
    updated_at: str

class PDRExportStatus(PhantexBase):
    """Status of a PDR export run."""

    channel_id: str
    channel_type: str
    last_export_at: str | None = None
    events_exported: int = 0
    errors: int = 0
    status: Literal["healthy", "degraded", "error", "pending"] = "pending"
