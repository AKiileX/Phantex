# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Slack Notification Channel (N2).

Sends alert notifications via Slack Incoming Webhook with Block Kit formatting.
The webhook URL is treated as a secret (never logged or returned in API).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from app.notifications.base import BaseNotificationChannel, NotificationError

logger = structlog.get_logger("phantex.notification.slack")

# Severity → emoji + color
_SEVERITY_BADGE = {
    "critical": (":red_circle:", "#e01e5a"),
    "high": (":large_orange_circle:", "#ff6600"),
    "medium": (":large_yellow_circle:", "#ecb22e"),
    "low": (":large_blue_circle:", "#36a64f"),
    "info": (":white_circle:", "#cccccc"),
}

class SlackChannel(BaseNotificationChannel):
    """Slack webhook notification channel."""

    channel_type = "slack"

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._webhook_url = config.get("webhook_url", "")
        self._channel_name = config.get("channel_name", "#alerts")

        if not self._webhook_url:
            raise NotificationError("Slack webhook_url required", retryable=False)
        if not self._webhook_url.startswith("https://"):
            raise NotificationError("Slack webhook must use HTTPS", retryable=False)

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        return self._client

    async def send(self, alert: dict[str, Any]) -> bool:
        self._check_rate_limit()
        client = await self._get_client()
        payload = _build_slack_blocks(alert)

        try:
            resp = await client.post(
                self._webhook_url,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and resp.text == "ok":
                return True
            if resp.status_code == 429:
                raise NotificationError("Slack rate limited", retryable=True)
            raise NotificationError(f"Slack HTTP {resp.status_code}: {resp.text[:100]}")
        except httpx.HTTPError as e:
            raise NotificationError(f"Slack error: {e}", retryable=True)

    async def test(self) -> dict[str, Any]:
        try:
            result = await self.send(
                {
                    "rule_name": "phantex_test",
                    "severity": "info",
                    "agent_id": "test-agent",
                    "message": "This is a Phantex test notification",
                }
            )
            return {"success": result, "message": "Slack test sent successfully"}
        except NotificationError as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

def _build_slack_blocks(alert: dict[str, Any]) -> dict:
    """Build Slack Block Kit message from alert."""
    severity = alert.get("severity", "info")
    emoji, color = _SEVERITY_BADGE.get(severity, (":white_circle:", "#cccccc"))
    rule_name = alert.get("rule_name", "Unknown Rule")
    agent_id = alert.get("agent_id", "N/A")
    message = alert.get("message", alert.get("description", ""))

    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} Phantex Alert: {rule_name}",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Agent:*\n`{agent_id}`"},
                            {"type": "mrkdwn", "text": f"*Attack Class:*\n{alert.get('attack_class', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*Framework:*\n{alert.get('framework', 'N/A')}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"```{message[:500]}```" if message else "_No description_",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Alert ID: `{alert.get('alert_id', 'N/A')}` | Tenant: `{alert.get('tenant_id', 'N/A')}`",
                            }
                        ],
                    },
                ],
            }
        ]
    }
