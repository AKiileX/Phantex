# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Splunk HEC Integration (N1-P0).

HTTP Event Collector client with:
  - Batched delivery (NDJSON)
  - Automatic retry with exponential backoff
  - Token-based auth (Splunk HEC token)
  - Input validation (TLS required)
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import to_splunk_hec_batch

logger = structlog.get_logger("phantex.integration.splunk")

class SplunkHECIntegration(BaseSIEMIntegration):
    """Splunk HTTP Event Collector integration."""

    platform_name = "splunk_hec"
    max_batch_size = 500  # Splunk HEC handles large batches well

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._endpoint = config.get("endpoint", "").rstrip("/")
        self._token = config.get("hec_token", "")
        self._index = config.get("index", "phantex")
        self._sourcetype = config.get("sourcetype", "phantex:alert")
        self._verify_ssl = config.get("verify_ssl", True)

        self._require_https(self._endpoint)

        if not self._token:
            raise IntegrationError("Splunk HEC token is required", retryable=False)

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                verify=self._verify_ssl,
                headers={
                    "Authorization": f"Splunk {self._token}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def send_batch(self, events: list[dict[str, Any]]) -> int:
        """Send events to Splunk HEC as NDJSON batch."""
        if not events:
            return 0

        self._check_rate_limit(len(events))
        client = await self._get_client()
        body = to_splunk_hec_batch(events)

        url = f"{self._endpoint}/services/collector/event"

        try:
            resp = await client.post(url, content=body)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") == 0:
                    return len(events)
                raise IntegrationError(f"Splunk HEC error: {data.get('text', 'unknown')}")
            elif resp.status_code == 503:
                raise IntegrationError("Splunk HEC service unavailable", retryable=True)
            elif resp.status_code == 401:
                raise IntegrationError("Splunk HEC auth failed — check token", retryable=False)
            else:
                raise IntegrationError(f"Splunk HEC HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise IntegrationError(f"Splunk HEC connection error: {e}", retryable=True)

    async def test_connection(self) -> dict[str, Any]:
        """Test Splunk HEC endpoint by sending a test event."""
        try:
            client = await self._get_client()
            url = f"{self._endpoint}/services/collector/event"

            test_payload = (
                '{"time": 0, "sourcetype": "phantex:test", "source": "phantex-backend", "event": {"test": true}}'
            )

            resp = await client.post(url, content=test_payload)
            if resp.status_code == 200:
                return {"success": True, "message": "Splunk HEC connection successful"}
            return {
                "success": False,
                "message": f"Splunk HEC returned HTTP {resp.status_code}",
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
