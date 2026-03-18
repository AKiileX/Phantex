# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Escalation Ladder.

Progressive response system that ratchets up enforcement based on
repeated offenses from the same agent within a configurable window.

Default ladder (configurable per tenant in response_config.escalation_steps):
  Level 1 → log_only        (Monitor — just record the incident)
  Level 2 → throttle         (Rate-limit the agent's actions)
  Level 3 → isolate_agent    (Network isolation via sensor)
  Level 4 → block_ip         (Full block + SOC notification)

The ladder resets when the escalation window expires without new offenses.

SECURITY:
  - All DB queries include explicit tenant_id (defense-in-depth)
  - Escalation steps are validated from DB config (no user code execution)
  - Level is capped at max configured steps (cannot overflow)
  - Window expiry prevents permanent state accumulation
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger("phantex.response.escalation")

# Default escalation steps (used if tenant has no config row)
DEFAULT_STEPS: list[dict[str, Any]] = [
    {"level": 1, "action": "log_only", "label": "Monitor"},
    {"level": 2, "action": "throttle", "label": "Throttle", "params": {"rate_limit": 10}},
    {"level": 3, "action": "isolate_agent", "label": "Isolate"},
    {"level": 4, "action": "block_ip", "label": "Block + Alert SOC"},
]

DEFAULT_WINDOW_SEC = 3600  # 1 hour

@dataclass
class EscalationResult:
    """Outcome of an escalation check."""

    new_level: int
    action: str
    action_params: dict[str, Any]
    label: str
    offense_count: int
    window_restarted: bool  # True if the window was reset (first offense or expired)

async def get_escalation_config(
    db: AsyncSession,
    tenant_id: str,
) -> tuple[list[dict[str, Any]], int, bool]:
    """
    Load escalation configuration for a tenant.

    Returns (steps, window_sec, enabled).
    Falls back to defaults if no config row exists.
    """
    query = text("""
        SELECT escalation_enabled, escalation_window, escalation_steps
        FROM response_config
        WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    if not row:
        return DEFAULT_STEPS, DEFAULT_WINDOW_SEC, True

    enabled = bool(row["escalation_enabled"])
    window_sec = int(row["escalation_window"])

    # Parse steps — defend against corrupted JSON
    raw_steps = row["escalation_steps"]
    if isinstance(raw_steps, str):
        try:
            steps = json.loads(raw_steps)
        except (json.JSONDecodeError, TypeError):
            logger.warning("escalation_steps_parse_error", tenant_id=tenant_id)
            steps = DEFAULT_STEPS
    elif isinstance(raw_steps, list):
        steps = raw_steps
    else:
        steps = DEFAULT_STEPS

    # Validate each step has required fields
    validated: list[dict[str, Any]] = []
    for s in steps:
        if isinstance(s, dict) and "level" in s and "action" in s:
            validated.append(s)
    if not validated:
        validated = DEFAULT_STEPS

    return validated, window_sec, enabled

async def evaluate_escalation(
    db: AsyncSession,
    *,
    tenant_id: str,
    agent_id: str,
) -> EscalationResult:
    """
    Check and advance the escalation ladder for an agent.

    Algorithm:
      1. Load current state for (tenant_id, agent_id)
      2. If no state or window expired → reset to level 1
      3. Otherwise → increment offense count, advance level
      4. Cap at max level
      5. Upsert state back to DB
      6. Return the action for the new level
    """
    steps, window_sec, enabled = await get_escalation_config(db, tenant_id)

    # If escalation is disabled, always return level 1 (log_only)
    if not enabled:
        return EscalationResult(
            new_level=1,
            action=steps[0]["action"] if steps else "log_only",
            action_params=steps[0].get("params", {}) if steps else {},
            label=steps[0].get("label", "Monitor") if steps else "Monitor",
            offense_count=1,
            window_restarted=True,
        )

    max_level = len(steps)
    now = datetime.now(UTC)

    # Load current state (SKIP LOCKED to avoid deadlocks under concurrency)
    query = text("""
        SELECT current_level, offense_count, first_offense, last_offense, reset_at
        FROM escalation_state
        WHERE tenant_id = :tid AND agent_id = :aid AND deleted_at IS NULL
        FOR UPDATE SKIP LOCKED
    """)
    result = await db.execute(query, {"tid": tenant_id, "aid": agent_id})
    row = result.mappings().first()

    window_restarted = False
    if row is None:
        # First offense
        new_level = 1
        offense_count = 1
        window_restarted = True
    else:
        first_offense = row["first_offense"]
        window_cutoff = first_offense + timedelta(seconds=window_sec)

        if now > window_cutoff:
            # Window expired — reset
            new_level = 1
            offense_count = 1
            window_restarted = True
        else:
            # Within window — escalate
            offense_count = int(row["offense_count"]) + 1
            current = int(row["current_level"])
            new_level = min(current + 1, max_level)

    # Clamp level to valid range
    new_level = max(1, min(new_level, max_level))
    step_index = new_level - 1
    step = steps[step_index] if step_index < len(steps) else steps[-1]

    # Upsert state
    upsert_query = text("""
        INSERT INTO escalation_state (tenant_id, agent_id, current_level, offense_count, first_offense, last_offense, reset_at)
        VALUES (:tid, :aid, :level, :count, :now, :now, :reset_at)
        ON CONFLICT (tenant_id, agent_id)
        DO UPDATE SET
            current_level = :level,
            offense_count = :count,
            first_offense = CASE WHEN :window_restarted THEN :now ELSE escalation_state.first_offense END,
            last_offense = :now,
            reset_at = :reset_at
    """)
    reset_at = now + timedelta(seconds=window_sec)
    await db.execute(
        upsert_query,
        {
            "tid": tenant_id,
            "aid": agent_id,
            "level": new_level,
            "count": offense_count,
            "now": now,
            "reset_at": reset_at,
            "window_restarted": window_restarted,
        },
    )

    logger.info(
        "escalation_evaluated",
        tenant_id=tenant_id,
        agent_id=agent_id,
        new_level=new_level,
        offense_count=offense_count,
        action=step["action"],
    )

    return EscalationResult(
        new_level=new_level,
        action=step["action"],
        action_params=step.get("params", {}),
        label=step.get("label", f"Level {new_level}"),
        offense_count=offense_count,
        window_restarted=window_restarted,
    )

async def reset_escalation(
    db: AsyncSession,
    *,
    tenant_id: str,
    agent_id: str,
) -> bool:
    """
    Manually reset the escalation ladder for an agent (Human Override).

    Returns True if a row was soft-deleted, False if no active state existed.
    """
    query = text("""
        UPDATE escalation_state
        SET deleted_at = now()
        WHERE tenant_id = :tid AND agent_id = :aid AND deleted_at IS NULL
    """)
    result = await db.execute(query, {"tid": tenant_id, "aid": agent_id})
    deleted = result.rowcount > 0
    if deleted:
        logger.info("escalation_reset", tenant_id=tenant_id, agent_id=agent_id)
    return deleted

async def get_escalation_state(
    db: AsyncSession,
    *,
    tenant_id: str,
    agent_id: str | None = None,
) -> list[dict[str, Any]]:
    """
    Get current escalation state. If agent_id is None, return all for tenant.
    """
    if agent_id:
        query = text("""
            SELECT agent_id, current_level, offense_count, first_offense, last_offense, reset_at
            FROM escalation_state
            WHERE tenant_id = :tid AND agent_id = :aid AND deleted_at IS NULL
        """)
        result = await db.execute(query, {"tid": tenant_id, "aid": agent_id})
    else:
        query = text("""
            SELECT agent_id, current_level, offense_count, first_offense, last_offense, reset_at
            FROM escalation_state
            WHERE tenant_id = :tid AND deleted_at IS NULL
            ORDER BY last_offense DESC
            LIMIT 200
        """)
        result = await db.execute(query, {"tid": tenant_id})

    rows = result.mappings().all()
    return [
        {
            "agent_id": str(r["agent_id"]),
            "current_level": r["current_level"],
            "offense_count": r["offense_count"],
            "first_offense": r["first_offense"].isoformat() if r["first_offense"] else None,
            "last_offense": r["last_offense"].isoformat() if r["last_offense"] else None,
            "reset_at": r["reset_at"].isoformat() if r["reset_at"] else None,
        }
        for r in rows
    ]
