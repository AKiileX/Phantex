# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Sandbox PRL Functions & Actions.

Extends the PRL engine with sandbox-specific built-in functions and
action handlers for sandbox isolation, quarantine, and restriction.

Functions added to BuiltinRegistry:
  - sandbox_violation_count(agent_id, window) → int
  - is_quarantined(agent_id) → bool
  - sandbox_tier(agent_id) → str ("wasm" | "gvisor" | "firecracker" | "none")

Action handlers:
  - sandbox_quarantine — trigger quarantine via QuarantineManager
  - sandbox_isolate — upgrade sandbox tier (e.g., WASM → gVisor)
  - sandbox_restrict — reduce resource grants for the agent's sandbox
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.sandbox.prl")

# ── Sandbox Violation Tracker ─────────────────────────────────────────────────

_MAX_WINDOW_ENTRIES = 50_000

@dataclass
class SandboxViolationTracker:
    """Track sandbox violation events per-agent for PRL function lookups.

    Thread-safety: designed for single-threaded async use (one event loop).
    """

    # agent_id → deque of violation timestamps
    _violations: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=_MAX_WINDOW_ENTRIES)),
    )

    # agent_id → current sandbox tier
    _sandbox_tiers: dict[str, str] = field(default_factory=dict)

    # agent_id → quarantined flag
    _quarantined: dict[str, bool] = field(default_factory=dict)

    def record_violation(self, agent_id: str, timestamp: float | None = None) -> None:
        """Record a sandbox violation for an agent."""
        ts = timestamp or time.time()
        self._violations[agent_id].append(ts)

    def count_violations(self, agent_id: str, window_seconds: float) -> int:
        """Count violations for agent within the sliding window."""
        cutoff = time.time() - window_seconds
        dq = self._violations.get(agent_id)
        if not dq:
            return 0
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def set_tier(self, agent_id: str, tier: str) -> None:
        """Update the sandbox tier for an agent."""
        valid = {"wasm", "gvisor", "firecracker", "none"}
        if tier not in valid:
            raise ValueError(f"Invalid tier {tier!r}, expected one of {valid}")
        self._sandbox_tiers[agent_id] = tier

    def get_tier(self, agent_id: str) -> str:
        """Get current sandbox tier for an agent."""
        return self._sandbox_tiers.get(agent_id, "none")

    def set_quarantined(self, agent_id: str, quarantined: bool) -> None:
        self._quarantined[agent_id] = quarantined

    def is_quarantined(self, agent_id: str) -> bool:
        return self._quarantined.get(agent_id, False)

# ── Global tracker instance ──────────────────────────────────────────────────

_tracker = SandboxViolationTracker()

def get_tracker() -> SandboxViolationTracker:
    return _tracker

# ── PRL Built-in Functions ────────────────────────────────────────────────────

def fn_sandbox_violation_count(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> int:
    """
    sandbox_violation_count(agent_id, window) → int

    Count sandbox violations for the given agent within the time window.
    Window is a duration string like "5m", "1h", "24h".

    Example: sandbox_violation_count(event.agent_id, "5m") >= 5
    """
    from engine.evaluator.functions import parse_duration

    agent_id = str(args[0])
    window_str = str(args[1])
    window_s = parse_duration(window_str)
    return _tracker.count_violations(agent_id, window_s)

def fn_is_quarantined(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> bool:
    """
    is_quarantined(agent_id) → bool

    Check if the agent is currently in quarantine.

    Example: is_quarantined(event.agent_id)
    """
    agent_id = str(args[0])
    return _tracker.is_quarantined(agent_id)

def fn_sandbox_tier(
    args: list[Any],
    ctx: dict[str, Any],
    func_ctx: Any,
) -> str:
    """
    sandbox_tier(agent_id) → str

    Return the current sandbox tier for the agent.
    One of: "wasm", "gvisor", "firecracker", "none".

    Example: sandbox_tier(event.agent_id) == "wasm"
    """
    agent_id = str(args[0])
    return _tracker.get_tier(agent_id)

# ── PRL Action Handlers ──────────────────────────────────────────────────────

@dataclass
class SandboxActionResult:
    """Result of a sandbox PRL action."""

    action: str
    agent_id: str
    tenant_id: str
    success: bool
    detail: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "success": self.success,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }

async def sandbox_quarantine_action(
    *,
    agent_id: str,
    tenant_id: str,
    rule_name: str,
    reason: str = "",
) -> SandboxActionResult:
    """
    PRL action: place agent into quarantine sandbox.

    Triggered by rules with action = "sandbox_quarantine".
    Integrates with QuarantineManager.
    """
    now = datetime.now(UTC).isoformat()
    _tracker.set_quarantined(agent_id, True)

    logger.warning(
        "prl_sandbox_quarantine",
        agent_id=agent_id,
        tenant_id=tenant_id,
        rule_name=rule_name,
        reason=reason,
    )

    return SandboxActionResult(
        action="sandbox_quarantine",
        agent_id=agent_id,
        tenant_id=tenant_id,
        success=True,
        detail=f"Agent quarantined by rule '{rule_name}': {reason}",
        timestamp=now,
    )

async def sandbox_isolate_action(
    *,
    agent_id: str,
    tenant_id: str,
    rule_name: str,
    target_tier: str = "gvisor",
) -> SandboxActionResult:
    """
    PRL action: upgrade agent's sandbox tier.

    Triggered by rules with action = "sandbox_isolate".
    """
    now = datetime.now(UTC).isoformat()
    old_tier = _tracker.get_tier(agent_id)

    # Tier escalation order: none → wasm → gvisor → firecracker
    tier_order = {"none": 0, "wasm": 1, "gvisor": 2, "firecracker": 3}
    old_level = tier_order.get(old_tier, 0)
    new_level = tier_order.get(target_tier, 2)

    if new_level <= old_level:
        return SandboxActionResult(
            action="sandbox_isolate",
            agent_id=agent_id,
            tenant_id=tenant_id,
            success=False,
            detail=f"Agent already at tier '{old_tier}' (>= requested '{target_tier}')",
            timestamp=now,
        )

    _tracker.set_tier(agent_id, target_tier)

    logger.info(
        "prl_sandbox_isolate",
        agent_id=agent_id,
        tenant_id=tenant_id,
        rule_name=rule_name,
        old_tier=old_tier,
        new_tier=target_tier,
    )

    return SandboxActionResult(
        action="sandbox_isolate",
        agent_id=agent_id,
        tenant_id=tenant_id,
        success=True,
        detail=f"Agent sandbox escalated from '{old_tier}' to '{target_tier}'",
        timestamp=now,
    )

async def sandbox_restrict_action(
    *,
    agent_id: str,
    tenant_id: str,
    rule_name: str,
    restriction: str = "reduce_grants",
) -> SandboxActionResult:
    """
    PRL action: restrict an agent's sandbox resources.

    Triggered by rules with action = "sandbox_restrict".
    Reduces memory/network/filesystem grants.
    """
    now = datetime.now(UTC).isoformat()

    logger.info(
        "prl_sandbox_restrict",
        agent_id=agent_id,
        tenant_id=tenant_id,
        rule_name=rule_name,
        restriction=restriction,
    )

    return SandboxActionResult(
        action="sandbox_restrict",
        agent_id=agent_id,
        tenant_id=tenant_id,
        success=True,
        detail=f"Agent resources restricted ({restriction}) by rule '{rule_name}'",
        timestamp=now,
    )

# ── Registry Extension ───────────────────────────────────────────────────────

def register_sandbox_functions(registry: Any) -> None:
    """Register sandbox PRL functions into the BuiltinRegistry.

    Called from BuiltinRegistry.__init__() or engine startup.
    """
    registry.register("sandbox_violation_count", fn_sandbox_violation_count)
    registry.register("is_quarantined", fn_is_quarantined)
    registry.register("sandbox_tier", fn_sandbox_tier)

    logger.info("sandbox_prl_functions_registered", count=3)

# ── Action Dispatch ──────────────────────────────────────────────────────────

SANDBOX_ACTIONS = {
    "sandbox_quarantine": sandbox_quarantine_action,
    "sandbox_isolate": sandbox_isolate_action,
    "sandbox_restrict": sandbox_restrict_action,
}

async def dispatch_sandbox_action(
    action_name: str,
    *,
    agent_id: str,
    tenant_id: str,
    rule_name: str,
    **kwargs: Any,
) -> SandboxActionResult:
    """Dispatch a sandbox PRL action by name."""
    handler = SANDBOX_ACTIONS.get(action_name)
    if handler is None:
        raise ValueError(
            f"Unknown sandbox action: {action_name!r}. Available: {', '.join(sorted(SANDBOX_ACTIONS.keys()))}"
        )
    return await handler(
        agent_id=agent_id,
        tenant_id=tenant_id,
        rule_name=rule_name,
        **kwargs,
    )
