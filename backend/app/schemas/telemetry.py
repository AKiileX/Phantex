# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Telemetry Export (Q3) & Cloud Ingestion (Q4)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

# ── Q3: Telemetry Config Schemas ─────────────────────────────────────────────

class TelemetryConfigUpdate(BaseModel):
    """Request body for enabling/disabling telemetry export."""

    enabled: bool = Field(..., description="Enable (true) or disable (false) telemetry export")
    dp_epsilon: float | None = Field(
        None,
        ge=0.1,
        le=10.0,
        description="Differential privacy epsilon (0.1=max privacy, 10.0=min privacy)",
    )

    @field_validator("dp_epsilon")
    @classmethod
    def validate_epsilon(cls, v: float | None) -> float | None:
        if v is not None and v <= 0:
            raise ValueError("Epsilon must be positive")
        return v

class TelemetryConfigResponse(BaseModel):
    """Current telemetry export configuration for a tenant."""

    tenant_id: str
    enabled: bool
    dp_epsilon: float
    global_kill_switch_active: bool
    cloud_endpoint_configured: bool
    created_at: str | None = None
    updated_at: str | None = None

class TelemetryStatusResponse(BaseModel):
    """Runtime telemetry export status and metrics."""

    enabled: bool
    global_kill_switch_active: bool
    cloud_endpoint_configured: bool
    buffer_size: int
    metrics: dict[str, Any]

class TelemetryViewerEntry(BaseModel):
    """A single entry in the telemetry viewer."""

    payload_preview: list[dict[str, Any]]
    record_count: int
    exported_at: float
    destination: str
    success: bool
    error: str | None = None

class TelemetryViewerResponse(BaseModel):
    """Response for the telemetry viewer endpoint."""

    entries: list[TelemetryViewerEntry]
    total_entries: int
    pending_records: int

class TelemetryPendingPreview(BaseModel):
    """Preview of records pending export."""

    records: list[dict[str, Any]]
    total_pending: int

# ── Q4: Cloud Ingestion Schemas ──────────────────────────────────────────────

class TelemetryVector(BaseModel):
    """A single anonymized telemetry vector in an ingestion batch."""

    anonymized_tenant_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="HMAC-SHA256 hex digest of tenant ID",
    )
    feature_vector: list[float] = Field(
        ...,
        min_length=62,
        max_length=62,
        description="62-dimension feature vector with DP noise applied",
    )
    attack_class: str = Field(
        ...,
        max_length=100,
        description="Attack classification label",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model confidence score",
    )
    timestamp: float = Field(
        ...,
        description="Event timestamp (Unix epoch seconds)",
    )

    @field_validator("feature_vector")
    @classmethod
    def validate_no_nan_inf(cls, v: list[float]) -> list[float]:
        import math

        for i, val in enumerate(v):
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Feature vector index {i} contains NaN/Inf")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_range(cls, v: float) -> float:
        # Reject timestamps before 2020 or more than 1 day in the future
        import time

        min_ts = 1577836800  # 2020-01-01
        max_ts = time.time() + 86400  # Now + 1 day
        if v < min_ts or v > max_ts:
            raise ValueError(f"Timestamp {v} is out of valid range")
        return v

class TelemetryBatch(BaseModel):
    """A batch of telemetry vectors for cloud ingestion (Q4)."""

    records: list[TelemetryVector] = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="Batch of anonymized telemetry vectors",
    )
    # Optional metadata (not required, for diagnostics)
    client_version: str | None = Field(
        None,
        max_length=50,
        description="Sending Phantex instance version",
    )
    batch_id: str | None = Field(
        None,
        max_length=100,
        description="Client-generated batch identifier",
    )

class IngestionResult(BaseModel):
    """Response from the cloud ingestion endpoint."""

    accepted: int = Field(..., description="Number of records accepted")
    rejected: int = Field(..., description="Number of records rejected (validation)")
    duplicates: int = Field(..., description="Number of duplicate records skipped")
    batch_id: str | None = None

class IngestionStats(BaseModel):
    """Aggregate ingestion statistics (admin use)."""

    total_records_ingested: int
    total_batches_received: int
    unique_tenant_hashes: int
    records_last_24h: int
    storage_size_bytes: int
    oldest_record_timestamp: float | None
    newest_record_timestamp: float | None
