# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Auto-Response Orchestrator.

Single entry point that the alert pipeline calls after creating an alert.
Coordinates all decision-layer components:

  1. Kill Switch check  — if ON, skip everything
  2. Policy Engine      — match alert → response policy
  3. Rate Limit check   — per-tenant hourly cap
  4. Shadow Mode check  — if ON, log only (no enforcement)
  5. Escalation Ladder  — progressive response ratchet
  6. Dispatcher         — route action to enforcement backend
  7. Audit Log          — immutable record of every decision

SECURITY:
  - Entire pipeline is wrapped in try/except — failures do NOT block alerts
  - Every decision path produces an audit log entry
  - Kill switch is checked FIRST (fail-closed for safety)
  - All DB queries include tenant_id (defense-in-depth)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.response.dispatcher import DispatchResult, dispatch
from app.services.response.escalation import evaluate_escalation
from app.services.response.policy_engine import evaluate_alert, log_decision
from app.services.response.shadow import is_shadow_mode

logger = structlog.get_logger("phantex.response.orchestrator")

async def handle_alert(
    db: AsyncSession,
    *,
    tenant_id: str,
    alert_id: str,
    agent_id: str | None,
    severity: str,
    confidence: float,
    attack_class: str,
    event_type: str,
    event_data: dict[str, Any] | None = None,
) -> DispatchResult | None:
    """
    Main entry point for the auto-response system.

    Called by rule_engine._create_alerts() after an alert is persisted.
    Returns the dispatch result, or None if no action was triggered.
    """
    try:
        # ── 1. Kill Switch ────────────────────────────────────────────────
        kill_active, kill_reason = await _check_kill_switch(db, tenant_id)
        if kill_active:
            logger.info(
                "auto_response_killed",
                tenant_id=tenant_id,
                alert_id=alert_id,
                reason=kill_reason,
            )
            await log_decision(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                policy_id=None,
                agent_id=agent_id,
                action="none",
                action_params={},
                decision="blocked_kill_switch",
                severity=severity,
                confidence=confidence,
                attack_class=attack_class,
                event_type=event_type,
            )
            await db.commit()
            return DispatchResult(
                success=False,
                action="none",
                decision="blocked_kill_switch",
                details={"reason": kill_reason},
            )

        # ── 2. Policy Evaluation ──────────────────────────────────────────
        match = await evaluate_alert(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            agent_id=agent_id,
            severity=severity,
            confidence=confidence,
            attack_class=attack_class,
            event_type=event_type,
            event_data=event_data,
        )

        if match is None:
            # No policy matched — nothing to do
            return None

        # ── 3. Rate Limit ────────────────────────────────────────────────
        rate_exceeded = await _check_rate_limit(db, tenant_id)
        if rate_exceeded:
            logger.warning(
                "auto_response_rate_limited",
                tenant_id=tenant_id,
                alert_id=alert_id,
                action=match.policy.action,
            )
            await log_decision(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                policy_id=match.policy.id,
                agent_id=agent_id,
                action=match.policy.action,
                action_params=match.policy.action_params,
                decision="rate_limited",
                severity=severity,
                confidence=confidence,
                attack_class=attack_class,
                event_type=event_type,
            )
            await db.commit()
            return DispatchResult(
                success=False,
                action=match.policy.action,
                decision="rate_limited",
            )

        # ── 4. Shadow Mode ───────────────────────────────────────────────
        shadow = await is_shadow_mode(db, tenant_id)

        # ── 5. Escalation Ladder ─────────────────────────────────────────
        escalation_level: int | None = None
        escalated_action: str | None = None

        if agent_id:
            esc_result = await evaluate_escalation(
                db,
                tenant_id=tenant_id,
                agent_id=agent_id,
            )
            escalation_level = esc_result.new_level
            # Escalation can override the policy's action with a more severe one
            if esc_result.action != match.policy.action:
                escalated_action = esc_result.action
                logger.info(
                    "escalation_override",
                    original_action=match.policy.action,
                    escalated_action=escalated_action,
                    level=escalation_level,
                    agent_id=agent_id,
                )

        # ── 6. Dispatch ──────────────────────────────────────────────────
        result = await dispatch(
            db,
            match,
            shadow_mode=shadow,
            escalation_level=escalation_level,
            escalated_action=escalated_action,
        )

        # ── 7. Audit (immutable) ─────────────────────────────────────────
        try:
            from app.services.audit_service import log_action

            await log_action(
                db,
                tenant_id=uuid.UUID(tenant_id),
                user_id=None,  # System-initiated
                action=f"auto_response.{result.decision}",
                resource_type="alert",
                resource_id=uuid.UUID(alert_id),
                details={
                    "policy_id": match.policy.id,
                    "policy_name": match.policy.name,
                    "action": result.action,
                    "shadow": shadow,
                    "escalation_level": escalation_level,
                    "success": result.success,
                    "error": result.error,
                },
            )
            await db.commit()
        except Exception:
            logger.exception("audit_log_failed", alert_id=alert_id)

        logger.info(
            "auto_response_completed",
            alert_id=alert_id,
            action=result.action,
            decision=result.decision,
            shadow=shadow,
            escalation_level=escalation_level,
        )
        return result

    except Exception:
        logger.exception(
            "auto_response_error",
            tenant_id=tenant_id,
            alert_id=alert_id,
        )
        # CRITICAL: Never block alert pipeline — fail open
        return None

# ── Kill Switch ───────────────────────────────────────────────────────────────

async def _check_kill_switch(
    db: AsyncSession,
    tenant_id: str,
) -> tuple[bool, str]:
    """
    Check if the kill switch is active for a tenant.

    Returns (is_active, reason).
    """
    query = text("""
        SELECT kill_switch, kill_switch_reason
        FROM response_config
        WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    if not row:
        return False, ""

    if row["kill_switch"]:
        return True, row["kill_switch_reason"] or "Kill switch active"

    return False, ""

async def set_kill_switch(
    db: AsyncSession,
    tenant_id: str,
    *,
    active: bool,
    reason: str = "",
    set_by: str | None = None,
) -> dict[str, Any]:
    """
    Toggle the kill switch for a tenant.

    When active=True: ALL auto-response is halted immediately.
    When active=False: Auto-response resumes (subject to shadow mode).
    """
    reason = reason[:1000]  # Bound reason length

    query = text("""
        INSERT INTO response_config (tenant_id, kill_switch, kill_switch_reason, kill_switch_set_by, kill_switch_set_at, updated_at)
        VALUES (:tid, :active, :reason, :set_by, :set_at, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            kill_switch = :active,
            kill_switch_reason = :reason,
            kill_switch_set_by = :set_by,
            kill_switch_set_at = :set_at,
            updated_at = now()
    """)
    set_at = datetime.now(UTC) if active else None
    await db.execute(
        query,
        {
            "tid": tenant_id,
            "active": active,
            "reason": reason,
            "set_by": set_by,
            "set_at": set_at,
        },
    )
    await db.commit()

    logger.warning(
        "kill_switch_toggled",
        tenant_id=tenant_id,
        active=active,
        reason=reason,
        set_by=set_by,
    )

    return {
        "kill_switch": active,
        "reason": reason,
        "set_by": set_by,
        "set_at": set_at.isoformat() if set_at else None,
    }

async def get_kill_switch_status(
    db: AsyncSession,
    tenant_id: str,
) -> dict[str, Any]:
    """Get current kill switch state for a tenant."""
    query = text("""
        SELECT kill_switch, kill_switch_reason, kill_switch_set_by, kill_switch_set_at
        FROM response_config
        WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    if not row:
        return {"kill_switch": False, "reason": "", "set_by": None, "set_at": None}

    return {
        "kill_switch": bool(row["kill_switch"]),
        "reason": row["kill_switch_reason"] or "",
        "set_by": str(row["kill_switch_set_by"]) if row["kill_switch_set_by"] else None,
        "set_at": row["kill_switch_set_at"].isoformat() if row["kill_switch_set_at"] else None,
    }

# ── Rate Limit (internal) ────────────────────────────────────────────────────

async def _check_rate_limit(
    db: AsyncSession,
    tenant_id: str,
) -> bool:
    """Check if tenant has exceeded max auto-response actions per hour."""
    from app.services.response.policy_engine import _check_rate_limit as _rl_check

    # Load max_actions_per_hour from config
    query = text("""
        SELECT max_actions_per_hour FROM response_config WHERE tenant_id = :tid
    """)
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()
    max_per_hour = int(row["max_actions_per_hour"]) if row else 50

    return await _rl_check(db, tenant_id, max_per_hour)
