# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Notification Router (N2).

Routes alerts to matching notification channels based on per-tenant
routing rules. Rules are evaluated in order — an alert can match
multiple rules and be sent to multiple channels.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.notifications.base import BaseNotificationChannel, NotificationError
from app.notifications.email import EmailChannel
from app.notifications.pagerduty import PagerDutyChannel
from app.notifications.slack import SlackChannel
from app.notifications.webhook import WebhookChannel

logger = structlog.get_logger("phantex.notification.router")

# Channel type → class
_CHANNEL_REGISTRY: dict[str, type[BaseNotificationChannel]] = {
    "slack": SlackChannel,
    "pagerduty": PagerDutyChannel,
    "webhook": WebhookChannel,
    "email": EmailChannel,
}

def get_channel(
    channel_type: str,
    *,
    tenant_id: str,
    config: dict[str, Any],
    rate_limit_per_min: int | None = None,
) -> BaseNotificationChannel:
    """Create a notification channel instance by type."""
    cls = _CHANNEL_REGISTRY.get(channel_type)
    if cls is None:
        raise NotificationError(
            f"Unknown channel type: {channel_type}. Available: {', '.join(sorted(_CHANNEL_REGISTRY.keys()))}",
            retryable=False,
        )
    return cls(
        tenant_id=tenant_id,
        config=config,
        rate_limit_per_min=rate_limit_per_min,
    )

def list_channel_types() -> list[str]:
    """Return all registered channel types."""
    return sorted(_CHANNEL_REGISTRY.keys())

def match_routing_rules(
    alert: dict[str, Any],
    rules: list[dict[str, Any]],
) -> list[str]:
    """Evaluate routing rules against an alert.

    Returns list of channel IDs (references to notification_channels rows)
    that the alert should be sent to.

    Rule format:
        {
            "condition": {"severity": ["critical", "high"], "attack_class": "credential_theft"},
            "channels": ["channel-id-1", "channel-id-2"]
        }

    Condition matching:
      - Each key in condition must match the alert
      - String values: exact match (case-insensitive)
      - List values: alert field must be IN the list (case-insensitive)
      - Multiple keys: ALL must match (AND logic)
      - Empty condition: matches all alerts
    """
    matched_channels = []

    for rule in rules:
        condition = rule.get("condition", {})
        channels = rule.get("channels", [])

        if not channels:
            continue

        if _matches_condition(alert, condition):
            matched_channels.extend(channels)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for ch_id in matched_channels:
        if ch_id not in seen:
            seen.add(ch_id)
            result.append(ch_id)

    return result

def _matches_condition(alert: dict[str, Any], condition: dict[str, Any]) -> bool:
    """Check if an alert matches a routing condition."""
    if not condition:
        return True  # Empty condition matches all

    for key, expected in condition.items():
        actual = alert.get(key, "")
        if actual is None:
            actual = ""

        actual_lower = str(actual).lower()

        if isinstance(expected, list):
            if actual_lower not in [str(v).lower() for v in expected]:
                return False
        else:
            if actual_lower != str(expected).lower():
                return False

    return True
