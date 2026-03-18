# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Red Team Simulator."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import PhantexBase

# ── Enums ─────────────────────────────────────────────────────────────────────

class CampaignTypeEnum(StrEnum):
    EVASION = "evasion"
    POISONING = "poisoning"
    MODEL_THEFT = "model_theft"
    PROMPT_INJECT = "prompt_inject"

class CampaignStatusEnum(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

# ── Request schemas ───────────────────────────────────────────────────────────

class CreateCampaignRequest(BaseModel):
    """Create a new red team campaign."""

    campaign_type: CampaignTypeEnum
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Campaign configuration: n_samples, epsilons, flip_rates, etc.",
    )

class CreateScheduleRequest(BaseModel):
    """Create a recurring campaign schedule."""

    campaign_type: CampaignTypeEnum
    interval_hours: float = Field(ge=0.5, le=720, description="Hours between runs (min 0.5)")
    config: dict[str, Any] = Field(default_factory=dict)

class ToggleScheduleRequest(BaseModel):
    """Enable or disable a schedule."""

    enabled: bool

class GenerateDataRequest(BaseModel):
    """Generate synthetic attack data."""

    count: int = Field(default=100, ge=1, le=10_000)
    attack_pattern: str | None = Field(default=None, description="Specific attack pattern or null for mixed")
    seed: int | None = None

class GenerateFeatureMatrixRequest(BaseModel):
    """Generate feature matrix for ML testing."""

    count: int = Field(default=500, ge=10, le=10_000)
    n_features: int = Field(default=64, ge=2, le=512)
    anomaly_ratio: float = Field(default=0.1, ge=0.0, le=1.0)
    seed: int | None = None

# ── Response schemas ──────────────────────────────────────────────────────────

class AttackRunResponse(PhantexBase):
    """Single attack run result."""

    attack_class: str
    epsilon: float
    samples_tested: int
    samples_evaded: int
    evasion_rate: float
    mean_perturbation: float
    duration_ms: float

class CampaignResponse(PhantexBase):
    """Campaign summary."""

    campaign_id: str
    campaign_type: str
    tenant_id: str
    status: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    overall_evasion_rate: float = 0.0
    overall_score: float = 100.0
    config: dict[str, Any] = {}
    error: str | None = None
    attack_runs: list[AttackRunResponse] = []

class CampaignListResponse(PhantexBase):
    """List of campaigns."""

    items: list[CampaignResponse]
    total: int

class CategoryScoreResponse(PhantexBase):
    """Score for a single attack category."""

    category: str
    score: float
    grade: str
    attacks_run: int
    avg_evasion_rate: float
    worst_evasion_rate: float

class ScorecardResponse(PhantexBase):
    """Aggregate security scorecard."""

    tenant_id: str
    generated_at: str
    overall_score: float
    overall_grade: str
    campaigns_analyzed: int
    categories: list[CategoryScoreResponse]
    recommendations: list[str]

class ScheduleResponse(PhantexBase):
    """Campaign schedule."""

    schedule_id: str
    tenant_id: str
    campaign_type: str
    interval_hours: float
    config: dict[str, Any] = {}
    enabled: bool = True
    created_at: str
    last_run_at: str | None = None
    next_run_at: str | None = None
    run_count: int = 0

class ScheduleListResponse(PhantexBase):
    """List of schedules."""

    items: list[ScheduleResponse]

class SyntheticDataResponse(PhantexBase):
    """Generated synthetic attack events."""

    count: int
    events: list[dict[str, Any]]

class FeatureMatrixResponse(PhantexBase):
    """Generated feature matrix."""

    rows: int
    features: int
    anomaly_count: int
    normal_count: int
