# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Red Team Simulator Router.

REST endpoints for managing adversarial red team campaigns, viewing security
scorecards, scheduling recurring tests, and generating synthetic attack data.

Routes:
  POST   /api/v1/red-team/campaigns              — create campaign
  GET    /api/v1/red-team/campaigns              — list campaigns
  GET    /api/v1/red-team/campaigns/{id}         — get campaign
  POST   /api/v1/red-team/campaigns/{id}/run     — run campaign
  DELETE /api/v1/red-team/campaigns/{id}         — delete campaign
  GET    /api/v1/red-team/scorecard              — generate scorecard
  POST   /api/v1/red-team/schedules              — create schedule
  GET    /api/v1/red-team/schedules              — list schedules
  PATCH  /api/v1/red-team/schedules/{id}         — toggle schedule
  DELETE /api/v1/red-team/schedules/{id}         — delete schedule
  POST   /api/v1/red-team/generate/events        — synthetic events
  POST   /api/v1/red-team/generate/features      — feature matrix
  GET    /api/v1/red-team/attack-patterns        — reference data

Security:
  - All endpoints require admin role + ml.manage permission
  - Tenant-scoped: campaigns isolated per tenant
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.red_team import (
    CampaignListResponse,
    CampaignResponse,
    CreateCampaignRequest,
    CreateScheduleRequest,
    FeatureMatrixResponse,
    GenerateDataRequest,
    GenerateFeatureMatrixRequest,
    ScheduleListResponse,
    ScheduleResponse,
    ScorecardResponse,
    SyntheticDataResponse,
    ToggleScheduleRequest,
)
from app.services.red_team.data_generator import (
    generate_events,
    generate_feature_matrix,
)
from app.services.red_team.scheduler import (
    create_schedule,
    delete_schedule,
    list_schedules,
    toggle_schedule,
)
from app.services.red_team.scorecard import generate_scorecard
from app.services.red_team.simulator import (
    CampaignType,
    create_campaign,
    delete_campaign,
    get_campaign,
    list_campaigns,
    run_campaign,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.router.red_team")

router = APIRouter(
    prefix="/api/v1/red-team",
    tags=["red-team"],
    dependencies=[Depends(rate_limit), Depends(require_permission("ml.manage"))],
)

# ── Campaigns ─────────────────────────────────────────────────────────────────

@router.post("/campaigns", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED)
async def api_create_campaign(
    body: CreateCampaignRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Create a new red team campaign (does not start execution)."""
    campaign = await create_campaign(
        tenant_id=str(user.tenant_id),
        campaign_type=CampaignType(body.campaign_type.value),
        config=body.config,
    )
    return campaign.to_dict()

@router.get("/campaigns", response_model=CampaignListResponse)
async def api_list_campaigns(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
    campaign_status: str | None = None,
    limit: int = 50,
):
    """List all red team campaigns for the tenant."""
    campaigns = await list_campaigns(
        tenant_id=str(user.tenant_id),
        status=campaign_status,
        limit=min(limit, 200),
    )
    return {
        "items": [c.to_dict() for c in campaigns],
        "total": len(campaigns),
    }

@router.get("/campaigns/{campaign_id}", response_model=CampaignResponse)
async def api_get_campaign(
    campaign_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Get a specific campaign and its results."""
    campaign = await get_campaign(str(user.tenant_id), campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign.to_dict()

@router.post("/campaigns/{campaign_id}/run", response_model=CampaignResponse)
async def api_run_campaign(
    campaign_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Execute a campaign's attack simulations."""
    campaign = await get_campaign(str(user.tenant_id), campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status not in ("pending", "failed"):
        raise HTTPException(status_code=409, detail=f"Campaign is {campaign.status}, cannot re-run")

    result = await run_campaign(str(user.tenant_id), campaign_id)
    return result.to_dict()

@router.delete("/campaigns/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT)
async def api_delete_campaign(
    campaign_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Delete a campaign and its results."""
    deleted = await delete_campaign(str(user.tenant_id), campaign_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Campaign not found")

# ── Scorecard ─────────────────────────────────────────────────────────────────

@router.get("/scorecard", response_model=ScorecardResponse)
async def api_get_scorecard(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Generate a security scorecard from all completed campaigns."""
    campaigns = await list_campaigns(str(user.tenant_id), limit=1000)
    scorecard = generate_scorecard(str(user.tenant_id), campaigns)
    return scorecard.to_dict()

# ── Schedules ─────────────────────────────────────────────────────────────────

@router.post("/schedules", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def api_create_schedule(
    body: CreateScheduleRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Create a recurring campaign schedule."""
    sched = await create_schedule(
        tenant_id=str(user.tenant_id),
        campaign_type=CampaignType(body.campaign_type.value),
        interval_hours=body.interval_hours,
        config=body.config,
    )
    return sched.to_dict()

@router.get("/schedules", response_model=ScheduleListResponse)
async def api_list_schedules(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """List all campaign schedules."""
    schedules = await list_schedules(str(user.tenant_id))
    return {"items": [s.to_dict() for s in schedules]}

@router.patch("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def api_toggle_schedule(
    schedule_id: str,
    body: ToggleScheduleRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Enable or disable a schedule."""
    sched = await toggle_schedule(str(user.tenant_id), schedule_id, body.enabled)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return sched.to_dict()

@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def api_delete_schedule(
    schedule_id: str,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Delete a campaign schedule."""
    deleted = await delete_schedule(str(user.tenant_id), schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")

# ── Data generation ───────────────────────────────────────────────────────────

@router.post("/generate/events", response_model=SyntheticDataResponse)
async def api_generate_events(
    body: GenerateDataRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Generate synthetic attack telemetry events."""
    events = generate_events(
        n=body.count,
        attack_pattern=body.attack_pattern,
        seed=body.seed,
    )
    return {"count": len(events), "events": events}

@router.post("/generate/features", response_model=FeatureMatrixResponse)
async def api_generate_features(
    body: GenerateFeatureMatrixRequest,
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Generate a labelled feature matrix for ML testing."""
    X, y = generate_feature_matrix(
        n=body.count,
        n_features=body.n_features,
        anomaly_ratio=body.anomaly_ratio,
        seed=body.seed,
    )
    anomaly_count = sum(y)
    return {
        "rows": len(X),
        "features": body.n_features,
        "anomaly_count": anomaly_count,
        "normal_count": len(X) - anomaly_count,
    }

# ── Reference data ────────────────────────────────────────────────────────────

@router.get("/attack-patterns")
async def api_attack_patterns(
    user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """List available attack patterns and campaign types."""
    return {
        "campaign_types": [
            {"value": "evasion", "label": "Evasion", "description": "Bypass ML detection via adversarial perturbation"},
            {"value": "poisoning", "label": "Data Poisoning", "description": "Inject subtle drift into training data"},
            {
                "value": "model_theft",
                "label": "Model Theft",
                "description": "Probe decision boundaries to extract model logic",
            },
            {
                "value": "prompt_inject",
                "label": "Prompt Injection",
                "description": "Test LLM components against injection attacks",
            },
        ],
        "attack_classes": [
            {"value": "fgsm", "label": "FGSM", "description": "Fast Gradient Sign Method"},
            {"value": "pgd", "label": "PGD", "description": "Projected Gradient Descent"},
            {
                "value": "feature_perturbation",
                "label": "Feature Perturbation",
                "description": "Top-k feature perturbation",
            },
            {"value": "label_flip", "label": "Label Flip", "description": "Training label corruption"},
            {"value": "boundary_probe", "label": "Boundary Probe", "description": "Decision boundary sampling"},
            {"value": "prompt_injection", "label": "Prompt Injection", "description": "LLM prompt injection"},
        ],
        "attack_patterns": [
            "privilege_escalation",
            "data_exfiltration",
            "lateral_movement",
            "credential_theft",
            "command_injection",
            "model_manipulation",
        ],
    }
