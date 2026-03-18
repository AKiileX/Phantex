# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Elastic SIEM Integration (N1-P0).

Elasticsearch Bulk Index API client with:
  - API key authentication (base64-encoded id:api_key)
  - NDJSON bulk format
  - Configurable index name
  - Key rotation support (store key ID + secret separately)
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import structlog

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import to_elastic_ndjson

logger = structlog.get_logger("phantex.integration.elastic")

class ElasticSIEMIntegration(BaseSIEMIntegration):
    """Elastic SIEM (Elasticsearch Bulk Index API) integration."""

    platform_name = "elastic_siem"
    max_batch_size = 500

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._endpoint = config.get("endpoint", "").rstrip("/")
        self._api_key_id = config.get("api_key_id", "")
        self._api_key_secret = config.get("api_key_secret", "")
        self._index = config.get("index", "phantex-alerts")
        self._verify_ssl = config.get("verify_ssl", True)

        self._require_https(self._endpoint)

        if not self._api_key_id or not self._api_key_secret:
            raise IntegrationError(
                "Elastic SIEM requires api_key_id and api_key_secret",
                retryable=False,
            )

        # Build API key header: base64(id:api_key)
        self._auth_header = "ApiKey " + base64.b64encode(f"{self._api_key_id}:{self._api_key_secret}".encode()).decode()

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                verify=self._verify_ssl,
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/x-ndjson",
                },
            )
        return self._client

    async def send_batch(self, events: list[dict[str, Any]]) -> int:
        """Send events to Elasticsearch via Bulk API."""
        if not events:
            return 0

        self._check_rate_limit(len(events))
        client = await self._get_client()
        body = to_elastic_ndjson(events, index=self._index)

        url = f"{self._endpoint}/_bulk"

        try:
            resp = await client.post(url, content=body)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("errors"):
                    # Some items may have failed
                    failed = sum(1 for item in data.get("items", []) if "error" in item.get("index", {}))
                    succeeded = len(events) - failed
                    if succeeded == 0:
                        raise IntegrationError(f"All {failed} events failed in Elastic bulk")
                    logger.warning(
                        "elastic_partial_failure",
                        succeeded=succeeded,
                        failed=failed,
                    )
                    return succeeded
                return len(events)
            elif resp.status_code == 401:
                raise IntegrationError(
                    "Elastic auth failed — check API key",
                    retryable=False,
                )
            elif resp.status_code == 429:
                raise IntegrationError(
                    "Elastic bulk rate limited",
                    retryable=True,
                )
            else:
                raise IntegrationError(f"Elastic HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise IntegrationError(f"Elastic connection error: {e}", retryable=True)

    async def test_connection(self) -> dict[str, Any]:
        """Test Elastic connection by checking cluster health."""
        try:
            client = await self._get_client()
            # Use cluster health endpoint (read-only)
            resp = await client.get(
                f"{self._endpoint}/_cluster/health",
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code == 200:
                health = resp.json()
                return {
                    "success": True,
                    "message": f"Elastic connected — cluster status: {health.get('status', 'unknown')}",
                }
            return {
                "success": False,
                "message": f"Elastic returned HTTP {resp.status_code}",
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
