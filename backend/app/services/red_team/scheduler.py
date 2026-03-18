# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Red Team Campaign Scheduler.

Manages recurring red team campaign schedules so security teams can
automate continuous adversarial testing.  Schedules are stored in-memory
(per tenant) and executed via an asyncio background loop.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.red_team.simulator import (
    CampaignType,
    create_campaign,
    run_campaign,
)

logger = structlog.get_logger("phantex.red_team.scheduler")

@dataclass
class Schedule:
    """A recurring red team campaign schedule."""

    schedule_id: str
    tenant_id: str
    campaign_type: str
    interval_hours: float
    config: dict[str, Any]
    enabled: bool = True
    created_at: str = ""
    last_run_at: str | None = None
    next_run_at: str | None = None
    run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "tenant_id": self.tenant_id,
            "campaign_type": self.campaign_type,
            "interval_hours": self.interval_hours,
            "config": self.config,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "run_count": self.run_count,
        }

# ── In-memory schedule store ─────────────────────────────────────────────────

_schedules: dict[str, dict[str, Schedule]] = {}
_lock = asyncio.Lock()
_runner_task: asyncio.Task | None = None

def _tenant_schedules(tenant_id: str) -> dict[str, Schedule]:
    if tenant_id not in _schedules:
        _schedules[tenant_id] = {}
    return _schedules[tenant_id]

async def create_schedule(
    tenant_id: str,
    campaign_type: CampaignType,
    interval_hours: float,
    config: dict[str, Any] | None = None,
) -> Schedule:
    """Create a new recurring campaign schedule."""
    schedule_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    sched = Schedule(
        schedule_id=schedule_id,
        tenant_id=tenant_id,
        campaign_type=campaign_type.value,
        interval_hours=max(0.5, interval_hours),  # min 30 minutes
        config=config or {},
        created_at=now.isoformat(),
    )
    async with _lock:
        _tenant_schedules(tenant_id)[schedule_id] = sched

    logger.info("schedule_created", schedule_id=schedule_id, interval_h=interval_hours)
    return sched

async def list_schedules(tenant_id: str) -> list[Schedule]:
    async with _lock:
        return list(_tenant_schedules(tenant_id).values())

async def get_schedule(tenant_id: str, schedule_id: str) -> Schedule | None:
    async with _lock:
        return _tenant_schedules(tenant_id).get(schedule_id)

async def toggle_schedule(tenant_id: str, schedule_id: str, enabled: bool) -> Schedule | None:
    async with _lock:
        sched = _tenant_schedules(tenant_id).get(schedule_id)
        if sched:
            sched.enabled = enabled
    return sched

async def delete_schedule(tenant_id: str, schedule_id: str) -> bool:
    async with _lock:
        store = _tenant_schedules(tenant_id)
        if schedule_id in store:
            del store[schedule_id]
            return True
        return False

# ── Background runner ─────────────────────────────────────────────────────────

async def _scheduler_loop() -> None:
    """Background loop that checks and runs due schedules."""
    while True:
        await asyncio.sleep(60)  # check every minute
        now = datetime.now(UTC)

        async with _lock:
            all_schedules = [s for tenants in _schedules.values() for s in tenants.values() if s.enabled]

        for sched in all_schedules:
            try:
                if sched.last_run_at:
                    last = datetime.fromisoformat(sched.last_run_at)
                    elapsed_hours = (now - last).total_seconds() / 3600
                    if elapsed_hours < sched.interval_hours:
                        continue

                # Time to run
                campaign = await create_campaign(
                    sched.tenant_id,
                    CampaignType(sched.campaign_type),
                    sched.config,
                )
                asyncio.create_task(run_campaign(sched.tenant_id, campaign.campaign_id))

                async with _lock:
                    sched.last_run_at = now.isoformat()
                    sched.run_count += 1

                logger.info(
                    "scheduled_campaign_triggered",
                    schedule_id=sched.schedule_id,
                    campaign_id=campaign.campaign_id,
                )
            except Exception as exc:
                logger.warning(
                    "scheduled_campaign_error",
                    schedule_id=sched.schedule_id,
                    error=str(exc),
                )

def start_scheduler() -> None:
    """Start the background scheduler loop (idempotent)."""
    global _runner_task
    if _runner_task is None or _runner_task.done():
        _runner_task = asyncio.create_task(_scheduler_loop(), name="red-team-scheduler")
        logger.info("red_team_scheduler_started")

def stop_scheduler() -> None:
    """Stop the background scheduler loop."""
    global _runner_task
    if _runner_task and not _runner_task.done():
        _runner_task.cancel()
        _runner_task = None
        logger.info("red_team_scheduler_stopped")

# ── Continuous red-team extension ─────────────────────────────────

@dataclass
class TrendPoint:
    """A single data point in detection-rate trend history."""

    timestamp: str
    detection_rate: float
    score: float
    classes_tested: int

@dataclass
class ContinuousSchedule:
    """Red team schedule with 14-class support and trend tracking."""

    schedule_id: str
    tenant_id: str
    agent_id: str
    attack_classes: list[int]  # which of the 14 classes to run
    interval_hours: float
    enabled: bool = True
    created_at: str = ""
    last_run_at: str | None = None
    run_count: int = 0
    trend: list[TrendPoint] = field(default_factory=list)
    regression_threshold: float = 0.05  # alert if detection drops by 5%+
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "attack_classes": self.attack_classes,
            "interval_hours": self.interval_hours,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_run_at": self.last_run_at,
            "run_count": self.run_count,
            "regression_threshold": self.regression_threshold,
            "trend": [
                {
                    "timestamp": t.timestamp,
                    "detection_rate": round(t.detection_rate, 4),
                    "score": round(t.score, 1),
                    "classes_tested": t.classes_tested,
                }
                for t in self.trend[-50:]  # last 50 data points
            ],
        }

_continuous_schedules: dict[str, dict[str, ContinuousSchedule]] = {}
_cont_lock = asyncio.Lock()
_cont_runner_task: asyncio.Task | None = None

def _cont_tenant(tenant_id: str) -> dict[str, ContinuousSchedule]:
    if tenant_id not in _continuous_schedules:
        _continuous_schedules[tenant_id] = {}
    return _continuous_schedules[tenant_id]

async def create_continuous_schedule(
    tenant_id: str,
    agent_id: str,
    attack_classes: list[int] | None = None,
    interval_hours: float = 168.0,  # default: weekly
    regression_threshold: float = 0.05,
    config: dict[str, Any] | None = None,
) -> ContinuousSchedule:
    """Create a continuous red-team schedule for an agent."""
    classes = attack_classes or list(range(1, 15))
    valid = [c for c in classes if 1 <= c <= 14]
    schedule_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    sched = ContinuousSchedule(
        schedule_id=schedule_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        attack_classes=valid,
        interval_hours=max(1.0, interval_hours),
        regression_threshold=regression_threshold,
        config=config or {},
        created_at=now.isoformat(),
    )
    async with _cont_lock:
        _cont_tenant(tenant_id)[schedule_id] = sched

    logger.info(
        "continuous_schedule_created",
        schedule_id=schedule_id,
        agent_id=agent_id,
        classes=len(valid),
        interval_h=interval_hours,
    )
    return sched

async def list_continuous_schedules(tenant_id: str) -> list[ContinuousSchedule]:
    async with _cont_lock:
        return list(_cont_tenant(tenant_id).values())

async def delete_continuous_schedule(tenant_id: str, schedule_id: str) -> bool:
    async with _cont_lock:
        store = _cont_tenant(tenant_id)
        if schedule_id in store:
            del store[schedule_id]
            return True
        return False

async def record_trend_point(
    tenant_id: str,
    schedule_id: str,
    detection_rate: float,
    score: float,
    classes_tested: int,
) -> bool:
    """Record a trend data point and check for regression."""
    async with _cont_lock:
        sched = _cont_tenant(tenant_id).get(schedule_id)
        if sched is None:
            return False

        point = TrendPoint(
            timestamp=datetime.now(UTC).isoformat(),
            detection_rate=detection_rate,
            score=score,
            classes_tested=classes_tested,
        )
        sched.trend.append(point)
        sched.last_run_at = point.timestamp
        sched.run_count += 1

        # Check regression against previous run
        if len(sched.trend) >= 2:
            prev = sched.trend[-2].detection_rate
            drop = prev - detection_rate
            if drop >= sched.regression_threshold:
                logger.warning(
                    "detection_regression_alert",
                    schedule_id=schedule_id,
                    agent_id=sched.agent_id,
                    previous_rate=round(prev, 4),
                    current_rate=round(detection_rate, 4),
                    drop=round(drop, 4),
                )
        return True

async def get_trend(
    tenant_id: str,
    schedule_id: str,
    last_n: int = 50,
) -> list[TrendPoint]:
    """Retrieve trend history for a continuous schedule."""
    async with _cont_lock:
        sched = _cont_tenant(tenant_id).get(schedule_id)
        if sched is None:
            return []
        return sched.trend[-last_n:]

def start_continuous_scheduler() -> None:
    """Start the continuous red-team scheduler (idempotent)."""
    global _cont_runner_task
    if _cont_runner_task is None or _cont_runner_task.done():
        _cont_runner_task = asyncio.create_task(
            _continuous_loop(),
            name="continuous-red-team-scheduler",
        )
        logger.info("continuous_red_team_scheduler_started")

def stop_continuous_scheduler() -> None:
    """Stop the continuous red-team scheduler."""
    global _cont_runner_task
    if _cont_runner_task and not _cont_runner_task.done():
        _cont_runner_task.cancel()
        _cont_runner_task = None
        logger.info("continuous_red_team_scheduler_stopped")

async def _continuous_loop() -> None:
    """Background loop for continuous red-team scheduling."""
    while True:
        await asyncio.sleep(60)
        now = datetime.now(UTC)

        async with _cont_lock:
            all_scheds = [s for tenants in _continuous_schedules.values() for s in tenants.values() if s.enabled]

        for sched in all_scheds:
            try:
                if sched.last_run_at:
                    last = datetime.fromisoformat(sched.last_run_at)
                    elapsed_hours = (now - last).total_seconds() / 3600
                    if elapsed_hours < sched.interval_hours:
                        continue

                # Execute via registry
                from ml.adversarial.attack_modules.registry import AttackModuleRegistry

                registry = AttackModuleRegistry()
                report = await registry.run_all(
                    sched.tenant_id,
                    sched.agent_id,
                    sched.config,
                    sched.attack_classes,
                )
                await record_trend_point(
                    sched.tenant_id,
                    sched.schedule_id,
                    report.overall_detection_rate,
                    report.overall_score,
                    len(report.module_reports),
                )
                logger.info(
                    "continuous_campaign_complete",
                    schedule_id=sched.schedule_id,
                    score=round(report.overall_score, 1),
                    detection_rate=round(report.overall_detection_rate, 4),
                )
            except Exception:
                logger.exception(
                    "continuous_campaign_error",
                    schedule_id=sched.schedule_id,
                )
