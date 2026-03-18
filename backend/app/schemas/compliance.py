# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Compliance"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Request ───────────────────────────────────────────────────────────────────

class ComplianceReportRequest(BaseModel):
    """Request body for generating a compliance report."""

    frameworks: list[Literal["eu_ai_act", "nist_ai_rmf"]] = Field(
        default=["eu_ai_act", "nist_ai_rmf"],
        description="Frameworks to include in the report.",
    )
    period_start: datetime | None = Field(
        default=None,
        description="Start of evidence-collection window. Defaults to 30 days ago.",
    )
    period_end: datetime | None = Field(
        default=None,
        description="End of evidence-collection window. Defaults to now.",
    )

class ScanScheduleUpdate(BaseModel):
    """Update the automated scan schedule."""

    quick_scan_cron: str | None = Field(
        default=None,
        description="Cron expression for quick scans (e.g. '0 6 * * *').",
    )
    full_scan_cron: str | None = Field(
        default=None,
        description="Cron expression for full scans (e.g. '0 2 * * 0').",
    )
    drift_threshold: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description="Score drop threshold to trigger a drift alert.",
    )
    enabled: bool = True

# ── Response ──────────────────────────────────────────────────────────────────

class ComplianceScorecard(PhantexBase):
    """Quick scorecard — headline numbers without full evidence."""

    tenant_id: uuid.UUID
    generated_at: datetime
    frameworks: list[FrameworkScore]

class FrameworkScore(PhantexBase):
    """Per-framework headline score."""

    framework: str
    overall_score: float = Field(ge=0.0, le=1.0)
    total_items: int
    satisfied: int
    partial: int
    gaps: int

# Resolve forward reference
ComplianceScorecard.model_rebuild()

class ComplianceReportMeta(PhantexBase):
    """Stored report metadata (for /history listing)."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    frameworks: list[str]
    overall_score: float
    created_at: datetime
    created_by: uuid.UUID | None = None

class ComplianceReportFull(PhantexBase):
    """Full report response including all evidence."""

    id: uuid.UUID | None = None
    tenant_id: uuid.UUID
    generated_at: datetime
    frameworks: list[dict[str, Any]]
    cross_reference: list[dict[str, str]] = []

class ComplianceHistoryResponse(PhantexBase):
    """Paginated list of stored reports."""

    items: list[ComplianceReportMeta]
    total: int

class ScanStatusResponse(PhantexBase):
    """Current scanner configuration and last-run timestamps."""

    enabled: bool
    quick_scan_cron: str | None = None
    full_scan_cron: str | None = None
    drift_threshold: float = 0.05
    last_quick_scan: datetime | None = None
    last_full_scan: datetime | None = None
    next_quick_scan: datetime | None = None
    next_full_scan: datetime | None = None
