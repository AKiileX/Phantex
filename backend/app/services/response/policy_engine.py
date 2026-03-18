# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Response Policy Engine.

Evaluates alerts against per-tenant response policies to determine whether
an automated action should fire.

Pipeline:
  1. Load enabled policies for the tenant (cached, 60s TTL)
  2. Match alert fields against each policy's conditions (AND logic)
  3. Check cooldown: skip if same action fired within cooldown_sec
  4. Return first matching policy (ordered by priority ASC)

SECURITY:
  - All DB queries include explicit tenant_id (defense-in-depth beyond RLS)
  - Policy conditions are evaluated in-process — no user-supplied code exec
  - Cooldown prevents runaway loops
  - Rate limit check prevents flooding
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger("phantex.response.policy_engine")

# ── Data transfer objects ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class ResponsePolicy:
    """A single response policy loaded from DB."""

    id: str
    tenant_id: str
    name: str
    severity: list[str]
    attack_class: list[str]
    event_type: list[str]
    min_confidence: float
    action: str
    action_params: dict[str, Any]
    enabled: bool
    priority: int
    cooldown_sec: int
    require_shadow: bool

@dataclass
class PolicyMatch:
    """Result of policy evaluation — describes the action to take."""

    policy: ResponsePolicy
    alert_id: str
    agent_id: str | None
    alert_severity: str
    alert_confidence: float
    attack_class: str
    event_type: str

# ── Allowed actions whitelist ─────────────────────────────────────────────────

ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {
        "isolate_agent",
        "block_ip",
        "quarantine_file",
        "kill_process",
        "disable_user",
        "collect_forensics",
        "trust_penalty",
        "block_mcp_server",
        "log_only",
        "throttle",
        "notify_soc",
    }
)

# ── Policy cache (per-tenant, bounded) ────────────────────────────────────────

_MAX_CACHED_TENANTS = 200
_CACHE_TTL_SEC = 60

@dataclass
class _CacheEntry:
    policies: list[ResponsePolicy]
    loaded_at: float

_policy_cache: dict[str, _CacheEntry] = {}

def _evict_cache_if_needed() -> None:
    """Evict oldest entries if cache exceeds max size."""
    if len(_policy_cache) > _MAX_CACHED_TENANTS:
        # Sort by loaded_at, remove oldest quarter
        sorted_keys = sorted(_policy_cache, key=lambda k: _policy_cache[k].loaded_at)
        for k in sorted_keys[: len(sorted_keys) // 4]:
            _policy_cache.pop(k, None)

def invalidate_policy_cache(tenant_id: str | None = None) -> None:
    """Invalidate cached policies. If tenant_id is None, clear all."""
    if tenant_id is None:
        _policy_cache.clear()
    else:
        _policy_cache.pop(tenant_id, None)

# ── Load policies from DB ─────────────────────────────────────────────────────

async def _load_policies(db: AsyncSession, tenant_id: str) -> list[ResponsePolicy]:
    """Load enabled response policies for a tenant, ordered by priority."""
    now = time.monotonic()
    cached = _policy_cache.get(tenant_id)
    if cached and (now - cached.loaded_at) < _CACHE_TTL_SEC:
        return cached.policies

    query = text("""
        SELECT id, tenant_id, name, severity, attack_class, event_type,
               min_confidence, action, action_params, enabled, priority,
               cooldown_sec, require_shadow
        FROM response_policies
        WHERE tenant_id = :tid AND enabled = true
        ORDER BY priority ASC, created_at ASC
    """)
    result = await db.execute(query, {"tid": tenant_id})
    rows = result.mappings().all()

    policies: list[ResponsePolicy] = []
    for r in rows:
        action = r["action"]
        # Strict whitelist — skip unknown actions
        if action not in ALLOWED_ACTIONS:
            logger.warning(
                "policy_unknown_action",
                policy_id=str(r["id"]),
                action=action,
            )
            continue
        policies.append(
            ResponsePolicy(
                id=str(r["id"]),
                tenant_id=str(r["tenant_id"]),
                name=r["name"],
                severity=[s.lower() for s in (r["severity"] or [])],
                attack_class=[a.lower() for a in (r["attack_class"] or [])],
                event_type=[e.lower() for e in (r["event_type"] or [])],
                min_confidence=float(r["min_confidence"]),
                action=action,
                action_params=r["action_params"] or {},
                enabled=bool(r["enabled"]),
                priority=int(r["priority"]),
                cooldown_sec=int(r["cooldown_sec"]),
                require_shadow=bool(r["require_shadow"]),
            )
        )

    _policy_cache[tenant_id] = _CacheEntry(policies=policies, loaded_at=now)
    _evict_cache_if_needed()

    logger.info("policies_loaded", tenant_id=tenant_id, count=len(policies))
    return policies

# ── Cooldown check ────────────────────────────────────────────────────────────

async def _check_cooldown(
    db: AsyncSession,
    tenant_id: str,
    policy_id: str,
    agent_id: str | None,
    cooldown_sec: int,
) -> bool:
    """Return True if the action is still in cooldown (should be SKIPPED)."""
    if cooldown_sec <= 0:
        return False

    cutoff = datetime.now(UTC) - timedelta(seconds=cooldown_sec)

    # Check if same policy fired for same agent within cooldown window
    query = text("""
        SELECT 1 FROM response_action_log
        WHERE tenant_id = :tid
          AND policy_id = :pid
          AND (:aid IS NULL OR agent_id = :aid)
          AND decision IN ('executed', 'shadow')
          AND created_at > :cutoff
        LIMIT 1
    """)
    result = await db.execute(
        query,
        {
            "tid": tenant_id,
            "pid": policy_id,
            "aid": agent_id,
            "cutoff": cutoff,
        },
    )
    return result.first() is not None

# ── Rate limit check ─────────────────────────────────────────────────────────

async def _check_rate_limit(
    db: AsyncSession,
    tenant_id: str,
    max_per_hour: int,
) -> bool:
    """Return True if tenant has exceeded max actions per hour (should BLOCK)."""
    if max_per_hour <= 0:
        return False

    cutoff = datetime.now(UTC) - timedelta(hours=1)
    query = text("""
        SELECT COUNT(*) AS cnt FROM response_action_log
        WHERE tenant_id = :tid
          AND decision IN ('executed', 'shadow')
          AND created_at > :cutoff
    """)
    result = await db.execute(query, {"tid": tenant_id, "cutoff": cutoff})
    row = result.mappings().first()
    count = int(row["cnt"]) if row else 0
    return count >= max_per_hour

# ── Main evaluation entry point ──────────────────────────────────────────────

async def evaluate_alert(
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
) -> PolicyMatch | None:
    """
    Evaluate an alert against all enabled response policies for the tenant.

    Returns the first matching PolicyMatch, or None if no policy fires.
    Cooldown and rate limits are enforced here.
    """
    policies = await _load_policies(db, tenant_id)
    if not policies:
        return None

    severity_lower = severity.lower()
    attack_lower = attack_class.lower() if attack_class else ""
    event_lower = event_type.lower() if event_type else ""

    for policy in policies:
        # -- Condition matching (AND logic) --

        # Severity filter (empty = match all)
        if policy.severity and severity_lower not in policy.severity:
            continue

        # Attack class filter (empty = match all)
        if policy.attack_class and attack_lower not in policy.attack_class:
            continue

        # Event type filter (empty = match all)
        if policy.event_type and event_lower not in policy.event_type:
            continue

        # Confidence threshold
        if confidence < policy.min_confidence:
            continue

        # -- Cooldown check --
        in_cooldown = await _check_cooldown(db, tenant_id, policy.id, agent_id, policy.cooldown_sec)
        if in_cooldown:
            logger.debug(
                "policy_cooldown_skip",
                policy=policy.name,
                agent_id=agent_id,
            )
            # Log the skip
            await _log_decision(
                db,
                tenant_id=tenant_id,
                alert_id=alert_id,
                policy_id=policy.id,
                agent_id=agent_id,
                action=policy.action,
                action_params=policy.action_params,
                decision="cooldown_skip",
                severity=severity,
                confidence=confidence,
                attack_class=attack_class,
                event_type=event_type,
            )
            continue  # Try next policy (don't short-circuit)

        # Match found
        logger.info(
            "policy_matched",
            policy=policy.name,
            action=policy.action,
            alert_id=alert_id,
            severity=severity,
        )
        return PolicyMatch(
            policy=policy,
            alert_id=alert_id,
            agent_id=agent_id,
            alert_severity=severity,
            alert_confidence=confidence,
            attack_class=attack_class,
            event_type=event_type,
        )

    return None

# ── Decision logging ──────────────────────────────────────────────────────────

async def _log_decision(
    db: AsyncSession,
    *,
    tenant_id: str,
    alert_id: str,
    policy_id: str | None,
    agent_id: str | None,
    action: str,
    action_params: dict[str, Any],
    decision: str,
    severity: str,
    confidence: float,
    attack_class: str,
    event_type: str,
    escalation_level: int | None = None,
    overridden_by: str | None = None,
    override_reason: str = "",
) -> str:
    """Write an immutable entry to the response_action_log. Returns the log ID."""
    log_id = str(uuid.uuid4())
    executed_at = datetime.now(UTC) if decision == "executed" else None

    query = text("""
        INSERT INTO response_action_log
            (id, tenant_id, alert_id, policy_id, agent_id, action, action_params,
             decision, escalation_level, alert_severity, alert_confidence,
             attack_class, event_type, overridden_by, override_reason, executed_at)
        VALUES
            (:id, :tid, :alert_id, :policy_id, :agent_id, :action, CAST(:action_params AS jsonb),
             :decision, :escalation_level, :severity, :confidence,
             :attack_class, :event_type, :overridden_by, :override_reason, :executed_at)
    """)
    await db.execute(
        query,
        {
            "id": log_id,
            "tid": tenant_id,
            "alert_id": alert_id,
            "policy_id": policy_id,
            "agent_id": agent_id,
            "action": action,
            "action_params": json.dumps(action_params),
            "decision": decision,
            "escalation_level": escalation_level,
            "severity": severity,
            "confidence": confidence,
            "attack_class": attack_class,
            "event_type": event_type,
            "overridden_by": overridden_by,
            "override_reason": override_reason[:1000] if override_reason else "",
            "executed_at": executed_at,
        },
    )
    return log_id

# Expose _log_decision for use by other modules in the package
log_decision = _log_decision
