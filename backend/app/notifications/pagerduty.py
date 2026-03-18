# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — PagerDuty Notification Channel (N2).

PagerDuty Events API v2. Creates incidents with dedup key = alert_id
to prevent duplicate pages.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from app.notifications.base import BaseNotificationChannel, NotificationError

logger = structlog.get_logger("phantex.notification.pagerduty")

_PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# Phantex severity → PagerDuty severity
_PD_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}

class PagerDutyChannel(BaseNotificationChannel):
    """PagerDuty Events API v2 notification channel."""

    channel_type = "pagerduty"

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._routing_key = config.get("routing_key", "")
        if not self._routing_key:
            raise NotificationError("PagerDuty routing_key required", retryable=False)

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        return self._client

    async def send(self, alert: dict[str, Any]) -> bool:
        self._check_rate_limit()
        client = await self._get_client()

        severity = alert.get("severity", "info")
        alert_id = alert.get("alert_id", alert.get("event_id", ""))
        rule_name = alert.get("rule_name", "Phantex Alert")

        payload = {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": f"phantex-{alert_id}" if alert_id else None,
            "payload": {
                "summary": f"[Phantex] {rule_name} — {severity.upper()}",
                "source": f"phantex-{alert.get('agent_id', 'unknown')}",
                "severity": _PD_SEVERITY.get(severity, "info"),
                "component": "phantex-backend",
                "group": alert.get("attack_class", ""),
                "class": alert.get("event_type", ""),
                "custom_details": {
                    "agent_id": alert.get("agent_id", ""),
                    "tenant_id": alert.get("tenant_id", ""),
                    "framework": alert.get("framework", ""),
                    "message": alert.get("message", "")[:1024],
                    "alert_id": alert_id,
                },
            },
        }

        try:
            resp = await client.post(
                _PD_EVENTS_URL,
                content=json.dumps(payload, default=str),
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 202):
                return True
            if resp.status_code == 429:
                raise NotificationError("PagerDuty rate limited", retryable=True)
            raise NotificationError(f"PagerDuty HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise NotificationError(f"PagerDuty error: {e}", retryable=True)

    async def test(self) -> dict[str, Any]:
        try:
            result = await self.send(
                {
                    "alert_id": "phantex-test",
                    "rule_name": "phantex_connection_test",
                    "severity": "info",
                    "agent_id": "test-agent",
                    "message": "Phantex PagerDuty connectivity test",
                }
            )
            return {"success": result, "message": "PagerDuty test event sent"}
        except NotificationError as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
