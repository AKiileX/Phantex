# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — CrowdStrike Falcon LogScale Integration (N1-P0).

LogScale Ingest API client with:
  - Bearer token authentication (ingest token)
  - Batched JSON delivery
  - Tag-based source identification
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import to_logscale

logger = structlog.get_logger("phantex.integration.logscale")

class CrowdStrikeLogScaleIntegration(BaseSIEMIntegration):
    """CrowdStrike Falcon LogScale (Humio) Ingest API integration."""

    platform_name = "crowdstrike_logscale"
    max_batch_size = 500

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._endpoint = config.get("endpoint", "https://cloud.humio.com").rstrip("/")
        self._ingest_token = config.get("ingest_token", "")
        self._verify_ssl = config.get("verify_ssl", True)

        self._require_https(self._endpoint)

        if not self._ingest_token:
            raise IntegrationError(
                "CrowdStrike LogScale requires ingest_token",
                retryable=False,
            )

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                verify=self._verify_ssl,
                headers={
                    "Authorization": f"Bearer {self._ingest_token}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def send_batch(self, events: list[dict[str, Any]]) -> int:
        """Send events to LogScale via Ingest API."""
        if not events:
            return 0

        self._check_rate_limit(len(events))
        client = await self._get_client()
        payload = to_logscale(events)
        body = json.dumps(payload, default=str)

        url = f"{self._endpoint}/api/v1/ingest/json"

        try:
            resp = await client.post(url, content=body)
            if resp.status_code == 200:
                return len(events)
            elif resp.status_code == 401:
                raise IntegrationError(
                    "LogScale auth failed — check ingest_token",
                    retryable=False,
                )
            elif resp.status_code == 429:
                raise IntegrationError(
                    "LogScale rate limited",
                    retryable=True,
                )
            else:
                raise IntegrationError(f"LogScale HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise IntegrationError(f"LogScale connection error: {e}", retryable=True)

    async def test_connection(self) -> dict[str, Any]:
        """Test LogScale connection with a minimal event."""
        try:
            sent = await self.send_batch(
                [
                    {
                        "event_id": "test",
                        "severity": "info",
                        "rule_name": "phantex_connection_test",
                    }
                ]
            )
            if sent > 0:
                return {"success": True, "message": "LogScale connection successful"}
            return {"success": False, "message": "Failed to send test event"}
        except IntegrationError as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
