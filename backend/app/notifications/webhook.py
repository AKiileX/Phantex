# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Generic Webhook Notification Channel (N2).

HTTP POST with HMAC-SHA256 signature for payload verification.
Supports custom URL and optional custom headers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import structlog

from app.notifications.base import BaseNotificationChannel, NotificationError

logger = structlog.get_logger("phantex.notification.webhook")

class WebhookChannel(BaseNotificationChannel):
    """Generic webhook notification channel with HMAC signing."""

    channel_type = "webhook"

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._url = config.get("url", "")
        self._secret = config.get("secret", "")
        self._custom_headers = config.get("headers", {})

        if not self._url:
            raise NotificationError("Webhook URL required", retryable=False)
        if not self._url.startswith("https://"):
            raise NotificationError("Webhook URL must use HTTPS", retryable=False)

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        return self._client

    async def send(self, alert: dict[str, Any]) -> bool:
        self._check_rate_limit()
        client = await self._get_client()

        body = json.dumps(alert, default=str)
        timestamp = str(int(time.time()))

        headers = {
            "Content-Type": "application/json",
            "X-Phantex-Timestamp": timestamp,
        }

        # HMAC-SHA256 signature if secret is configured
        if self._secret:
            sig_payload = f"{timestamp}.{body}"
            signature = hmac.new(
                self._secret.encode("utf-8"),
                sig_payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Phantex-Signature"] = f"sha256={signature}"

        # Merge custom headers — block security-sensitive overrides
        _BLOCKED_HEADERS = frozenset(
            {
                "x-phantex-signature",
                "x-phantex-timestamp",
                "authorization",
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
            }
        )
        for k, v in self._custom_headers.items():
            if k.lower() not in _BLOCKED_HEADERS:
                headers[k] = v

        try:
            resp = await client.post(self._url, content=body, headers=headers)
            if 200 <= resp.status_code < 300:
                return True
            if resp.status_code == 429:
                raise NotificationError("Webhook rate limited", retryable=True)
            raise NotificationError(f"Webhook HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise NotificationError(f"Webhook error: {e}", retryable=True)

    async def test(self) -> dict[str, Any]:
        try:
            result = await self.send(
                {
                    "type": "test",
                    "source": "phantex",
                    "message": "Phantex webhook connectivity test",
                    "timestamp": time.time(),
                }
            )
            return {"success": result, "message": "Webhook test delivered"}
        except NotificationError as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
