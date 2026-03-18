# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Response Action Dispatcher.

Routes auto-response actions to the correct enforcement subsystem:

  isolate_agent / block_ip / kill_process / quarantine_file / collect_forensics / disable_user
      → agent_command_service.queue_command()   (gateway → sensor)

  trust_penalty
      → trust_client.update_event()  (severity="critical")

  block_mcp_server
      → MCPServerRegistry.block()   (content enforcement)

  notify_soc
      → notification channel send   (Slack / PagerDuty / webhook / email)

  log_only / throttle
      → no enforcement, just audit log

SECURITY:
  - Action type is whitelisted — unknown actions are REJECTED
  - Every dispatch is audit-logged (immutable INSERT-only table)
  - Errors are caught per-action to avoid cascading failures
  - agent_id is validated before dispatch
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.response.policy_engine import ALLOWED_ACTIONS, PolicyMatch, log_decision

logger = structlog.get_logger("phantex.response.dispatcher")

_UUID_RE = __import__("re").compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    __import__("re").IGNORECASE,
)

# Actions that go through the agent command pipeline (gateway → sensor)
_AGENT_ACTIONS: frozenset[str] = frozenset(
    {
        "isolate_agent",
        "block_ip",
        "quarantine_file",
        "kill_process",
        "disable_user",
        "collect_forensics",
    }
)

# Actions that are decision-layer only (no enforcement dispatch)
_PASSIVE_ACTIONS: frozenset[str] = frozenset({"log_only", "throttle"})

@dataclass
class DispatchResult:
    """Outcome of dispatching an action."""

    success: bool
    action: str
    decision: str  # "executed", "shadow", "error", etc.
    details: dict[str, Any] = None  # type: ignore[assignment]
    error: str | None = None

    def __post_init__(self) -> None:
        if self.details is None:
            self.details = {}

# ── Main dispatch function ────────────────────────────────────────────────────

async def dispatch(
    db: AsyncSession,
    match: PolicyMatch,
    *,
    shadow_mode: bool = False,
    escalation_level: int | None = None,
    escalated_action: str | None = None,
) -> DispatchResult:
    """
    Dispatch a matched policy action to the correct enforcement subsystem.

    If shadow_mode is True, the action is logged but NOT enforced.
    If escalated_action is provided, it overrides the policy's action.
    """
    action = escalated_action or match.policy.action
    tenant_id = match.policy.tenant_id
    agent_id = match.agent_id
    alert_id = match.alert_id
    action_params = match.policy.action_params

    # Strict whitelist — paranoid check even though policy_engine already filters
    if action not in ALLOWED_ACTIONS:
        logger.error("dispatch_unknown_action", action=action)
        return DispatchResult(success=False, action=action, decision="error", error=f"Unknown action: {action}")

    # ── Shadow mode — log only, do NOT enforce ────────────────────────────
    if shadow_mode:
        await log_decision(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            policy_id=match.policy.id,
            agent_id=agent_id,
            action=action,
            action_params=action_params,
            decision="shadow",
            severity=match.alert_severity,
            confidence=match.alert_confidence,
            attack_class=match.attack_class,
            event_type=match.event_type,
            escalation_level=escalation_level,
        )
        await db.commit()
        logger.info(
            "shadow_mode_logged",
            action=action,
            alert_id=alert_id,
            agent_id=agent_id,
        )
        return DispatchResult(success=True, action=action, decision="shadow")

    # ── Real enforcement ──────────────────────────────────────────────────
    try:
        if action in _AGENT_ACTIONS:
            result = await _dispatch_agent_command(db, tenant_id, agent_id, alert_id, action, action_params)
        elif action == "trust_penalty":
            result = await _dispatch_trust_penalty(tenant_id, agent_id)
        elif action == "block_mcp_server":
            result = await _dispatch_mcp_block(tenant_id, action_params)
        elif action == "notify_soc":
            result = await _dispatch_notification(tenant_id, match, action_params)
        elif action in _PASSIVE_ACTIONS:
            result = DispatchResult(success=True, action=action, decision="executed", details={"passive": True})
        else:
            result = DispatchResult(success=False, action=action, decision="error", error="No dispatcher")

        # Log the outcome
        await log_decision(
            db,
            tenant_id=tenant_id,
            alert_id=alert_id,
            policy_id=match.policy.id,
            agent_id=agent_id,
            action=action,
            action_params=action_params,
            decision=result.decision,
            severity=match.alert_severity,
            confidence=match.alert_confidence,
            attack_class=match.attack_class,
            event_type=match.event_type,
            escalation_level=escalation_level,
        )
        await db.commit()
        return result

    except Exception as exc:
        logger.error("dispatch_error", action=action, error=str(exc), alert_id=alert_id)
        try:
            await log_decision(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                policy_id=match.policy.id,
                agent_id=agent_id,
                action=action,
                action_params=action_params,
                decision="error",
                severity=match.alert_severity,
                confidence=match.alert_confidence,
                attack_class=match.attack_class,
                event_type=match.event_type,
                escalation_level=escalation_level,
            )
            await db.commit()
        except Exception:
            logger.exception("dispatch_error_logging_failed")
        return DispatchResult(success=False, action=action, decision="error", error=str(exc))

# ── Enforcement backends ──────────────────────────────────────────────────────

async def _dispatch_agent_command(
    db: AsyncSession,
    tenant_id: str,
    agent_id: str | None,
    alert_id: str,
    action: str,
    params: dict[str, Any],
) -> DispatchResult:
    """Queue a command for the sensor via agent_command_service."""
    if not agent_id or not _UUID_RE.match(agent_id):
        return DispatchResult(
            success=False,
            action=action,
            decision="error",
            error="Missing or invalid agent_id for agent command",
        )

    from app.services.agent_command_service import queue_command

    cmd = await queue_command(
        db,
        tenant_id=uuid.UUID(tenant_id),
        agent_id=agent_id,
        alert_id=alert_id,
        action=action,
        parameters=params,
        issued_by=None,  # System-initiated
        reason=f"Auto-response: policy match on alert {alert_id}",
    )
    logger.info(
        "agent_command_queued",
        command_id=cmd.id,
        action=action,
        agent_id=agent_id,
    )
    return DispatchResult(
        success=True,
        action=action,
        decision="executed",
        details={"command_id": cmd.id, "command_type": cmd.command_type},
    )

async def _dispatch_trust_penalty(
    tenant_id: str,
    agent_id: str | None,
) -> DispatchResult:
    """Push a critical trust event to reduce agent's trust score."""
    if not agent_id:
        return DispatchResult(
            success=False,
            action="trust_penalty",
            decision="error",
            error="Missing agent_id for trust penalty",
        )

    try:
        from app.services.trust_client import get_trust_client

        client = get_trust_client()
        source_score, target_score = await client.update_event(
            tenant_id=tenant_id,
            source_id=agent_id,
            source_type="agent",
            target_id=agent_id,
            target_type="agent",
            event_type="trust_penalty",
            severity="critical",
        )
        logger.info(
            "trust_penalty_applied",
            agent_id=agent_id,
            source_score=source_score,
            target_score=target_score,
        )
        return DispatchResult(
            success=True,
            action="trust_penalty",
            decision="executed",
            details={"source_score": source_score, "target_score": target_score},
        )
    except Exception as exc:
        logger.error("trust_penalty_failed", agent_id=agent_id, error=str(exc))
        return DispatchResult(
            success=False,
            action="trust_penalty",
            decision="error",
            error=str(exc),
        )

async def _dispatch_mcp_block(
    tenant_id: str,
    params: dict[str, Any],
) -> DispatchResult:
    """Block an MCP server via the content enforcement registry."""
    server_id = params.get("server_id")
    if not server_id:
        return DispatchResult(
            success=False,
            action="block_mcp_server",
            decision="error",
            error="Missing server_id in action_params",
        )

    try:
        from ml.content.policy.mcp_registry import MCPServerRegistry

        registry = MCPServerRegistry()
        registry.block(tenant_id, server_id)
        logger.info("mcp_server_blocked", tenant_id=tenant_id, server_id=server_id)
        return DispatchResult(
            success=True,
            action="block_mcp_server",
            decision="executed",
            details={"server_id": server_id},
        )
    except Exception as exc:
        logger.error("mcp_block_failed", server_id=server_id, error=str(exc))
        return DispatchResult(
            success=False,
            action="block_mcp_server",
            decision="error",
            error=str(exc),
        )

async def _dispatch_notification(
    tenant_id: str,
    match: PolicyMatch,
    params: dict[str, Any],
) -> DispatchResult:
    """Send notification via configured channel (Slack/PagerDuty/webhook/email)."""
    channel_type = params.get("channel_type", "webhook")
    channel_config = params.get("channel_config", {})

    if not channel_config:
        return DispatchResult(
            success=False,
            action="notify_soc",
            decision="error",
            error="Missing channel_config in action_params",
        )

    try:
        from app.notifications.router import get_channel

        channel = get_channel(
            channel_type,
            tenant_id=tenant_id,
            config=channel_config,
        )
        alert_payload = {
            "alert_id": match.alert_id,
            "severity": match.alert_severity,
            "confidence": match.alert_confidence,
            "attack_class": match.attack_class,
            "event_type": match.event_type,
            "agent_id": match.agent_id,
            "auto_response": True,
            "policy_name": match.policy.name,
            "action": match.policy.action,
        }
        await channel.send(alert_payload)
        logger.info("soc_notification_sent", channel_type=channel_type, alert_id=match.alert_id)
        return DispatchResult(
            success=True,
            action="notify_soc",
            decision="executed",
            details={"channel_type": channel_type},
        )
    except Exception as exc:
        logger.error("notification_failed", channel_type=channel_type, error=str(exc))
        return DispatchResult(
            success=False,
            action="notify_soc",
            decision="error",
            error=str(exc),
        )
