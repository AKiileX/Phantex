# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Azure Sentinel Integration (N1-P0).

Azure Log Analytics Data Collector API client with:
  - HMAC-SHA256 signature authentication
  - Batched JSON array delivery
  - Custom log type (table) support
  - Input validation (TLS required)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
from typing import Any

import httpx
import structlog

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import to_azure_sentinel_batch

logger = structlog.get_logger("phantex.integration.sentinel")

class AzureSentinelIntegration(BaseSIEMIntegration):
    """Azure Sentinel (Log Analytics Data Collector API) integration."""

    platform_name = "azure_sentinel"
    max_batch_size = 200

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._workspace_id = config.get("workspace_id", "")
        self._shared_key = config.get("shared_key", "")
        self._log_type = config.get("log_type", "PhantexAlerts")
        self._verify_ssl = config.get("verify_ssl", True)

        if not self._workspace_id or not self._shared_key:
            raise IntegrationError(
                "Azure Sentinel requires workspace_id and shared_key",
                retryable=False,
            )

        # F1-SSRF: workspace_id is used as a URL subdomain — validate that
        # it contains only safe characters (alphanumeric + hyphens) to
        # prevent SSRF via path-traversal or host injection.
        import re as _re

        if not _re.fullmatch(r"[a-zA-Z0-9-]+", self._workspace_id):
            raise IntegrationError(
                "Azure Sentinel workspace_id must be alphanumeric/hyphens only",
                retryable=False,
            )

        self._endpoint = f"https://{self._workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        self._client: httpx.AsyncClient | None = None

    def _build_signature(self, body: str, date: str) -> str:
        """Build HMAC-SHA256 authorization signature per Azure spec."""
        content_length = len(body.encode("utf-8"))
        string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
        decoded_key = base64.b64decode(self._shared_key)
        signature = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self._workspace_id}:{signature}"

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0),
                verify=self._verify_ssl,
            )
        return self._client

    async def send_batch(self, events: list[dict[str, Any]]) -> int:
        """Send events to Azure Sentinel via Data Collector API."""
        if not events:
            return 0

        self._check_rate_limit(len(events))
        client = await self._get_client()
        body = to_azure_sentinel_batch(events)

        rfc1123_date = datetime.datetime.now(datetime.UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
        auth = self._build_signature(body, rfc1123_date)

        headers = {
            "Content-Type": "application/json",
            "Authorization": auth,
            "Log-Type": self._log_type,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "TimeGenerated",
        }

        try:
            resp = await client.post(self._endpoint, content=body, headers=headers)
            if resp.status_code == 200:
                return len(events)
            elif resp.status_code == 401:
                raise IntegrationError(
                    "Azure Sentinel auth failed — check workspace_id/shared_key",
                    retryable=False,
                )
            elif resp.status_code == 429:
                raise IntegrationError("Azure Sentinel rate limited", retryable=True)
            else:
                raise IntegrationError(f"Azure Sentinel HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise IntegrationError(f"Azure Sentinel connection error: {e}", retryable=True)

    async def test_connection(self) -> dict[str, Any]:
        """Test Azure Sentinel connection with a minimal payload."""
        try:
            sent = await self.send_batch(
                [
                    {
                        "event_id": "test",
                        "severity": "info",
                        "rule_name": "phantex_connection_test",
                        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                    }
                ]
            )
            if sent > 0:
                return {"success": True, "message": "Azure Sentinel connection successful"}
            return {"success": False, "message": "Failed to send test event"}
        except IntegrationError as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
