# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Policy Engine Consumer.

Applies tenant policies to incoming events in real-time.  Loaded as
a background task from main_consumer or invoked directly by the
policy apply endpoint.

Responsibilities:
- Resolve matching policies for an agent based on tags and framework.
- Apply severity overrides and parameter overrides from policy rules.
- Check schedule windows (active hours, weekend handling).
- Emit enriched events with policy metadata attached.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from app.utils.logging import get_logger

logger = get_logger("phantex.consumer.policy")

# ── Schedule Helpers ──────────────────────────────────────────────────────────

_TIME_RE = re.compile(r"^(\d{2}):(\d{2})$")

def _parse_hhmm(s: str) -> tuple[int, int] | None:
    m = _TIME_RE.match(s.strip())
    if not m:
        return None
    hh, mm = int(m.group(1)), int(m.group(2))
    if hh > 23 or mm > 59:
        return None
    return hh, mm

def is_within_schedule(schedule: dict | None, now: datetime | None = None) -> bool:
    """
    Check if the current time falls within the policy schedule.

    Returns True if:
    - No schedule is defined (always active)
    - Current time is within active_hours
    - Weekend handling allows activity

    Weekend modes: 'suppress' → skip, 'alert' → allow, 'inherit' → follow active_hours.
    """
    if not schedule:
        return True

    now = now or datetime.now(UTC)

    # Weekend check
    is_weekend = now.weekday() >= 5  # Saturday=5, Sunday=6
    weekend_mode = schedule.get("weekend", "inherit")
    if is_weekend:
        if weekend_mode == "suppress":
            return False
        if weekend_mode == "alert":
            return True
        # 'inherit' falls through to active_hours check

    # Active-hours check
    active_hours = schedule.get("active_hours")
    if not active_hours:
        return True

    # Format: "HH:MM-HH:MM TZ" — for now we operate in UTC
    parts = active_hours.strip().split("-")
    if len(parts) != 2:
        return True  # Malformed → default allow

    start_str = parts[0].strip()
    end_str = parts[1].strip().split()[0]  # Drop optional TZ suffix

    start = _parse_hhmm(start_str)
    end = _parse_hhmm(end_str)
    if start is None or end is None:
        return True

    current_minutes = now.hour * 60 + now.minute
    start_minutes = start[0] * 60 + start[1]
    end_minutes = end[0] * 60 + end[1]

    if start_minutes <= end_minutes:
        return start_minutes <= current_minutes <= end_minutes
    else:
        # Overnight window (e.g., 22:00 - 06:00)
        return current_minutes >= start_minutes or current_minutes <= end_minutes

# ── Rule Matching ─────────────────────────────────────────────────────────────

def match_policy_to_agent(
    policy: dict,
    agent_tags: list[str],
    agent_framework: str | None = None,
) -> bool:
    """
    Check if a policy applies to an agent based on scope tags and frameworks.

    A policy matches if:
    - No scope is defined (applies to all)
    - Agent tags overlap with policy scope_agent_tags
    - Agent framework is in policy scope_frameworks
    """
    scope_tags = policy.get("scope_agent_tags") or []
    scope_frameworks = policy.get("scope_frameworks") or []

    # If no scope at all, policy applies to everything
    if not scope_tags and not scope_frameworks:
        return True

    # Tag match — any overlap
    if scope_tags and agent_tags and set(scope_tags) & set(agent_tags):
        return True

    # Framework match
    return bool(scope_frameworks and agent_framework and agent_framework in scope_frameworks)

# ── Apply Policy Rules ───────────────────────────────────────────────────────

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

def apply_policy_rules(
    event: dict,
    policy: dict,
    now: datetime | None = None,
) -> dict:
    """
    Apply policy rule overrides to an event.

    Returns the modified event dict with:
    - severity_override applied if matching rule
    - parameter overrides merged
    - policy_metadata attached
    - schedule check (event marked as suppressed if outside)

    The original event dict is not mutated — a copy is returned.
    """
    result = dict(event)
    definition = policy.get("definition") or {}
    rules = definition.get("rules") or []
    schedule = definition.get("schedule")

    # Schedule gate
    if not is_within_schedule(schedule, now):
        result["_policy_suppressed"] = True
        result["_policy_suppressed_reason"] = "outside_schedule"
        result.setdefault("_policy_metadata", []).append(
            {
                "policy_id": policy.get("id"),
                "policy_name": policy.get("name"),
                "action": "suppressed",
            }
        )
        return result

    event_rule_name = event.get("rule_name", "")
    matched_any = False

    for rule in rules:
        rule_name = rule.get("name", "")
        if not rule_name:
            continue

        # Match by rule name
        if rule_name != event_rule_name:
            continue

        matched_any = True

        # Enabled check
        if not rule.get("enabled", True):
            result["_policy_suppressed"] = True
            result["_policy_suppressed_reason"] = "rule_disabled"
            result.setdefault("_policy_metadata", []).append(
                {
                    "policy_id": policy.get("id"),
                    "policy_name": policy.get("name"),
                    "rule_name": rule_name,
                    "action": "disabled",
                }
            )
            return result

        # Severity override
        severity_override = rule.get("severity_override")
        if severity_override and severity_override in VALID_SEVERITIES:
            result["_original_severity"] = result.get("severity")
            result["severity"] = severity_override

        # Parameter overrides — merged into event
        params = rule.get("parameters")
        if params and isinstance(params, dict):
            result.setdefault("_parameter_overrides", {}).update(params)

        # Notification overrides
        notifications = rule.get("notifications")
        if notifications and isinstance(notifications, list):
            result["_notification_overrides"] = notifications

        # Record metadata
        result.setdefault("_policy_metadata", []).append(
            {
                "policy_id": policy.get("id"),
                "policy_name": policy.get("name"),
                "rule_name": rule_name,
                "action": "override",
                "severity_override": severity_override,
            }
        )

    if not matched_any:
        # Policy matched by scope, but no rules matched the event name
        result.setdefault("_policy_metadata", []).append(
            {
                "policy_id": policy.get("id"),
                "policy_name": policy.get("name"),
                "action": "no_matching_rule",
            }
        )

    return result

def apply_policies_to_event(
    event: dict,
    policies: list[dict],
    agent_tags: list[str],
    agent_framework: str | None = None,
    now: datetime | None = None,
) -> dict:
    """
    Apply all matching policies to an event.

    Policies are applied in order.  First suppression wins (the loop breaks
    on the first policy that marks the event as suppressed).  Non-suppressing
    overrides (severity, parameters) accumulate from each matching policy.
    """
    result = dict(event)
    for policy in policies:
        if not policy.get("enabled", True):
            continue
        if not match_policy_to_agent(policy, agent_tags, agent_framework):
            continue
        result = apply_policy_rules(result, policy, now)
        if result.get("_policy_suppressed"):
            break  # First suppression wins
    return result
