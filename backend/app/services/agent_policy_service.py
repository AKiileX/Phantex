# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Tagging & Policy Service

P1: Agent tag CRUD + tag matching engine
P2: Rule exemptions with hit counting & expiration
P3: Tag-based alert routing rules
P4: Maintenance windows with cron scheduling & emergency override
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_policy import (
    AlertRoutingRule,
    MaintenanceWindow,
    RuleExemption,
)
from app.models.audit import AuditLog
from app.schemas.agent_policy import SEVERITY_ORDER

logger = structlog.get_logger("phantex.agent_policy")

# Sentinel for "not provided" vs explicit None
_UNSET = object()

# Allowlisted fields for update operations (defense-in-depth)
_ROUTING_RULE_UPDATABLE = frozenset(
    {
        "name",
        "description",
        "match_tags",
        "severity_min",
        "channels",
        "enabled",
        "priority",
    }
)
_MAINTENANCE_WINDOW_UPDATABLE = frozenset(
    {
        "name",
        "description",
        "cron_schedule",
        "duration_minutes",
        "rules",
        "match_tags",
        "enabled",
    }
)

# Cron iteration safety cap (prevents CPU exhaustion on impossible expressions)
_CRON_MAX_ITERATIONS = 525_960  # ~1 year of minutes

# ══════════════════════════════════════════════════════════════════════════════
#  Tag matching engine
# ══════════════════════════════════════════════════════════════════════════════

def tags_match(agent_tags: dict[str, str], match_tags: dict[str, str]) -> bool:
    """Check if agent tags satisfy all match_tags conditions.

    Each key in *match_tags* must exist in *agent_tags* with the same
    value (case-insensitive).  Empty match_tags matches ALL agents.
    """
    if not match_tags:
        return True
    for key, expected in match_tags.items():
        actual = agent_tags.get(key)
        if actual is None:
            return False
        if str(actual).lower() != str(expected).lower():
            return False
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  P1: Agent Tags
# ══════════════════════════════════════════════════════════════════════════════

async def set_agent_tags(
    db: AsyncSession,
    agent_id: uuid.UUID,
    tags: dict[str, str],
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> Agent | None:
    """Replace agent tags atomically."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return None

    old_tags = dict(agent.tags) if agent.tags else {}
    agent.tags = tags

    # Audit
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action="agent.tags.update",
            resource_type="agent",
            resource_id=str(agent_id),
            details={"old_tags": old_tags, "new_tags": tags},
        )
    )

    await db.flush()
    await db.refresh(agent)
    return agent

async def get_agent_tags(db: AsyncSession, agent_id: uuid.UUID) -> dict | None:
    """Return agent tags or None if agent not found."""
    result = await db.execute(select(Agent.tags).where(Agent.id == agent_id))
    row = result.one_or_none()
    return dict(row[0]) if row else None

# ══════════════════════════════════════════════════════════════════════════════
#  P2: Rule Exemptions
# ══════════════════════════════════════════════════════════════════════════════

async def create_exemption(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    rule_name: str,
    match_tags: dict[str, str],
    reason: str,
    expires_at: datetime | None = None,
) -> RuleExemption:
    """Create a new rule exemption."""
    exemption = RuleExemption(
        tenant_id=tenant_id,
        rule_name=rule_name,
        match_tags=match_tags,
        reason=reason,
        expires_at=expires_at,
        created_by=user_id,
    )
    db.add(exemption)
    await db.flush()
    await db.refresh(exemption)

    # Audit
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action="exemption.create",
            resource_type="rule_exemption",
            resource_id=str(exemption.id),
            details={
                "rule_name": rule_name,
                "match_tags": match_tags,
                "reason": reason,
                "expires_at": str(expires_at) if expires_at else None,
            },
        )
    )

    await db.flush()
    return exemption

async def list_exemptions(
    db: AsyncSession,
    *,
    rule_name: str | None = None,
    enabled_only: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> list[RuleExemption]:
    """List rule exemptions (RLS-filtered)."""
    q = select(RuleExemption).order_by(RuleExemption.created_at.desc())
    if enabled_only:
        q = q.where(RuleExemption.enabled.is_(True))
    if rule_name:
        q = q.where(RuleExemption.rule_name == rule_name)
    q = q.offset(offset).limit(min(limit, 500))
    result = await db.execute(q)
    return list(result.scalars().all())

async def get_exemption(db: AsyncSession, exemption_id: uuid.UUID) -> RuleExemption | None:
    result = await db.execute(select(RuleExemption).where(RuleExemption.id == exemption_id))
    return result.scalar_one_or_none()

async def update_exemption(
    db: AsyncSession,
    exemption_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    enabled: bool | None = None,
    reason: str | None = None,
    expires_at: datetime | None = _UNSET,  # type: ignore[assignment]
) -> RuleExemption | None:
    """Update an exemption (enabled, reason, expires_at)."""
    exemption = await get_exemption(db, exemption_id)
    if exemption is None:
        return None

    changes: dict = {}
    if enabled is not None:
        changes["enabled"] = enabled
        exemption.enabled = enabled
    if reason is not None:
        changes["reason"] = reason
        exemption.reason = reason
    if expires_at is not _UNSET:
        changes["expires_at"] = str(expires_at) if expires_at else None
        exemption.expires_at = expires_at

    if changes:
        db.add(
            AuditLog(
                tenant_id=tenant_id,
                user_id=user_id,
                action="exemption.update",
                resource_type="rule_exemption",
                resource_id=str(exemption_id),
                details=changes,
            )
        )

    await db.flush()
    await db.refresh(exemption)
    return exemption

async def delete_exemption(
    db: AsyncSession,
    exemption_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> bool:
    """Delete an exemption. Returns True if deleted."""
    exemption = await get_exemption(db, exemption_id)
    if exemption is None:
        return False

    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action="exemption.delete",
            resource_type="rule_exemption",
            resource_id=str(exemption_id),
            details={"rule_name": exemption.rule_name, "reason": exemption.reason},
        )
    )

    await db.delete(exemption)
    await db.flush()
    return True

async def check_exemption(
    db: AsyncSession,
    rule_name: str,
    agent_tags: dict[str, str],
    *,
    dry_run: bool = False,
) -> RuleExemption | None:
    """Check if a rule trigger is exempted for an agent (by tags).

    Returns the matching exemption (and bumps hit_count unless dry_run), or None.
    Expired exemptions are skipped.
    """
    now = datetime.now(UTC)
    q = (
        select(RuleExemption)
        .where(
            RuleExemption.rule_name == rule_name,
            RuleExemption.enabled.is_(True),
        )
        .order_by(RuleExemption.created_at.desc())
    )
    result = await db.execute(q)
    exemptions = result.scalars().all()

    for exemption in exemptions:
        # Skip expired
        if exemption.expires_at and exemption.expires_at < now:
            continue
        if tags_match(agent_tags, exemption.match_tags or {}):
            if not dry_run:
                # Bump hit count
                exemption.hit_count = (exemption.hit_count or 0) + 1
                exemption.last_hit_at = now
                await db.flush()
            return exemption

    return None

# ══════════════════════════════════════════════════════════════════════════════
#  P3: Alert Routing by Tag
# ══════════════════════════════════════════════════════════════════════════════

async def create_routing_rule(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    name: str,
    description: str = "",
    match_tags: dict[str, str] | None = None,
    severity_min: str = "info",
    channels: list[str],
    priority: int = 0,
) -> AlertRoutingRule:
    """Create a tag-based alert routing rule."""
    rule = AlertRoutingRule(
        tenant_id=tenant_id,
        name=name,
        description=description,
        match_tags=match_tags or {},
        severity_min=severity_min,
        channels=channels,
        priority=priority,
        created_by=user_id,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule

async def list_routing_rules(
    db: AsyncSession,
    *,
    enabled_only: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> list[AlertRoutingRule]:
    """List routing rules, ordered by priority DESC."""
    q = select(AlertRoutingRule).order_by(AlertRoutingRule.priority.desc(), AlertRoutingRule.created_at.desc())
    if enabled_only:
        q = q.where(AlertRoutingRule.enabled.is_(True))
    q = q.offset(offset).limit(min(limit, 500))
    result = await db.execute(q)
    return list(result.scalars().all())

async def get_routing_rule(db: AsyncSession, rule_id: uuid.UUID) -> AlertRoutingRule | None:
    result = await db.execute(select(AlertRoutingRule).where(AlertRoutingRule.id == rule_id))
    return result.scalar_one_or_none()

async def update_routing_rule(
    db: AsyncSession,
    rule_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    **kwargs,
) -> AlertRoutingRule | None:
    """Update routing rule fields (allowlisted only)."""
    rule = await get_routing_rule(db, rule_id)
    if rule is None:
        return None

    for field, value in kwargs.items():
        if value is not None and field in _ROUTING_RULE_UPDATABLE:
            setattr(rule, field, value)
    rule.updated_by = user_id

    await db.flush()
    await db.refresh(rule)
    return rule

async def delete_routing_rule(
    db: AsyncSession,
    rule_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> bool:
    """Delete routing rule with audit. Returns True if deleted."""
    rule = await get_routing_rule(db, rule_id)
    if rule is None:
        return False

    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action="routing_rule.delete",
            resource_type="alert_routing_rule",
            resource_id=str(rule_id),
            details={"name": rule.name, "channels": list(rule.channels or [])},
        )
    )

    await db.delete(rule)
    await db.flush()
    return True

def evaluate_tag_routing(
    agent_tags: dict[str, str],
    alert_severity: str,
    rules: list[AlertRoutingRule],
) -> list[str]:
    """Evaluate tag-based routing rules and return matching channel IDs.

    Rules are pre-sorted by priority (highest first).
    A rule matches if:
      1. Agent tags satisfy match_tags (AND logic)
      2. Alert severity >= severity_min
    """
    sev_num = SEVERITY_ORDER.get(alert_severity.lower(), 0)
    matched_channels: list[str] = []
    seen: set[str] = set()

    for rule in rules:
        if not rule.enabled:
            continue
        min_num = SEVERITY_ORDER.get(rule.severity_min or "info", 0)
        if sev_num < min_num:
            continue
        if not tags_match(agent_tags, rule.match_tags or {}):
            continue
        for ch in rule.channels or []:
            if ch not in seen:
                seen.add(ch)
                matched_channels.append(ch)

    return matched_channels

# ══════════════════════════════════════════════════════════════════════════════
#  P4: Maintenance Windows
# ══════════════════════════════════════════════════════════════════════════════

def _parse_cron_field(field: str, min_val: int, max_val: int) -> set[int]:
    """Parse a single cron field into a set of matching values."""
    values: set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if part == "*":
            values.update(range(min_val, max_val + 1))
        elif "/" in part:
            base, step = part.split("/", 1)
            step_int = int(step)
            if step_int <= 0:
                raise ValueError(f"Invalid cron step: {step_int}")
            start = min_val if base == "*" else int(base)
            values.update(range(start, max_val + 1, step_int))
        elif "-" in part:
            lo, hi = part.split("-", 1)
            values.update(range(int(lo), int(hi) + 1))
        else:
            values.add(int(part))
    # Clamp to valid range (defense against out-of-bounds values)
    return {v for v in values if min_val <= v <= max_val}

def compute_next_cron(cron_schedule: str, after: datetime | None = None) -> datetime | None:
    """Compute next run time from a 5-field cron expression.

    Returns the next datetime (UTC) >= *after*.  Returns None if the
    expression is invalid.  This is a simplified cron evaluator — it
    handles basic patterns but does not cover every edge case
    (e.g. day-of-week combined with day-of-month).
    """
    if after is None:
        after = datetime.now(UTC)

    parts = cron_schedule.strip().split()
    if len(parts) != 5:
        return None

    try:
        minutes = _parse_cron_field(parts[0], 0, 59)
        hours = _parse_cron_field(parts[1], 0, 23)
        days = _parse_cron_field(parts[2], 1, 31)
        months = _parse_cron_field(parts[3], 1, 12)
        dows = _parse_cron_field(parts[4], 0, 6)  # 0=Sun
    except (ValueError, IndexError):
        return None

    # Iterate forward minute-by-minute with safety cap
    candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    end = after + timedelta(days=400)
    iterations = 0
    while candidate < end and iterations < _CRON_MAX_ITERATIONS:
        iterations += 1
        if (
            candidate.month in months
            and candidate.day in days
            and candidate.weekday() in {(d - 1) % 7 for d in dows}  # cron 0=Sun → Python 6=Sun
            and candidate.hour in hours
            and candidate.minute in minutes
        ):
            return candidate
        candidate += timedelta(minutes=1)

    return None

def is_window_active(
    window: MaintenanceWindow,
    now: datetime | None = None,
) -> bool:
    """Check if a maintenance window is currently active."""
    if not window.enabled:
        return False
    if window.force_ended_by:
        # Force ended → only consider active if restarted after force end
        if window.last_ended_at and (not window.last_started_at or window.last_started_at < window.last_ended_at):
            return False
    if not window.last_started_at:
        return False

    now = now or datetime.now(UTC)
    end_time = window.last_started_at + timedelta(minutes=window.duration_minutes)
    return window.last_started_at <= now < end_time

async def create_maintenance_window(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    name: str,
    description: str = "",
    cron_schedule: str,
    duration_minutes: int,
    rules: list[str],
    match_tags: dict[str, str] | None = None,
) -> MaintenanceWindow:
    """Create a maintenance window with computed next_start."""
    next_start = compute_next_cron(cron_schedule)
    window = MaintenanceWindow(
        tenant_id=tenant_id,
        name=name,
        description=description,
        cron_schedule=cron_schedule,
        duration_minutes=duration_minutes,
        rules=rules,
        match_tags=match_tags or {},
        next_start=next_start,
        created_by=user_id,
    )
    db.add(window)
    await db.flush()
    await db.refresh(window)
    return window

async def list_maintenance_windows(
    db: AsyncSession,
    *,
    enabled_only: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> list[MaintenanceWindow]:
    """List maintenance windows (RLS-filtered)."""
    q = select(MaintenanceWindow).order_by(
        MaintenanceWindow.next_start.asc().nullslast(),
        MaintenanceWindow.created_at.desc(),
    )
    if enabled_only:
        q = q.where(MaintenanceWindow.enabled.is_(True))
    q = q.offset(offset).limit(min(limit, 500))
    result = await db.execute(q)
    return list(result.scalars().all())

async def get_maintenance_window(db: AsyncSession, window_id: uuid.UUID) -> MaintenanceWindow | None:
    result = await db.execute(select(MaintenanceWindow).where(MaintenanceWindow.id == window_id))
    return result.scalar_one_or_none()

async def update_maintenance_window(
    db: AsyncSession,
    window_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    **kwargs,
) -> MaintenanceWindow | None:
    """Update maintenance window fields (allowlisted only).  Recomputes next_start if cron changes."""
    window = await get_maintenance_window(db, window_id)
    if window is None:
        return None

    for field, value in kwargs.items():
        if value is not None and field in _MAINTENANCE_WINDOW_UPDATABLE:
            setattr(window, field, value)

    # Recompute next_start when cron changes
    if "cron_schedule" in kwargs and kwargs["cron_schedule"] is not None:
        window.next_start = compute_next_cron(kwargs["cron_schedule"])

    await db.flush()
    await db.refresh(window)
    return window

async def delete_maintenance_window(
    db: AsyncSession,
    window_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> bool:
    """Delete maintenance window with audit."""
    window = await get_maintenance_window(db, window_id)
    if window is None:
        return False

    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action="maintenance_window.delete",
            resource_type="maintenance_window",
            resource_id=str(window_id),
            details={"name": window.name, "rules": list(window.rules or [])},
        )
    )

    await db.delete(window)
    await db.flush()
    return True

async def force_end_maintenance_window(
    db: AsyncSession,
    window_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> MaintenanceWindow | None:
    """Emergency override — force end a maintenance window."""
    window = await get_maintenance_window(db, window_id)
    if window is None:
        return None

    now = datetime.now(UTC)
    window.force_ended_by = user_id
    window.last_ended_at = now

    # Audit
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action="maintenance_window.force_end",
            resource_type="maintenance_window",
            resource_id=str(window_id),
            details={"name": window.name, "forced_at": str(now)},
        )
    )

    await db.flush()
    await db.refresh(window)
    return window

async def check_maintenance_suppression(
    db: AsyncSession,
    rule_name: str,
    agent_tags: dict[str, str],
) -> MaintenanceWindow | None:
    """Check if a rule trigger should be suppressed by an active maintenance window.

    Returns the matching window or None.
    """
    q = select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True))
    result = await db.execute(q)
    windows = result.scalars().all()

    for window in windows:
        if not is_window_active(window):
            continue
        # Check if rule is in the window's rule list (or wildcard *)
        rules_list = window.rules or []
        if "*" not in rules_list and rule_name not in rules_list:
            continue
        # Check tag match
        if not tags_match(agent_tags, window.match_tags or {}):
            continue
        return window

    return None
