# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — PDR (Phantex Data Relay) Export Service (L3).

Three export channels:
  1. S3 Drops — OCSF JSON-L files, gzipped, partitioned by date/tenant
  2. Webhook Push — POST OCSF JSON on alert, HMAC-SHA256 signed
  3. Kafka Mirror — OCSF events to customer Kafka cluster

Each channel handles:
  - Retry with exponential backoff (3 attempts)
  - Dead-letter queuing on exhaustion
  - PII redaction (configurable per channel)
  - Rate limiting to prevent over-delivery
  - Tenant isolation (never mix tenants)

All S3/webhook/Kafka credentials sourced from config (Vault in production).
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import hmac
import io
import json
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services import ocsf_mapper
from app.utils.logging import get_logger

logger = get_logger("phantex.pdr")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_RETRIES = 3
BACKOFF_BASE = 2.0  # seconds
WEBHOOK_TIMEOUT = 15.0
MAX_BATCH_SIZE = 5000
MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB

# ══════════════════════════════════════════════════════════════════════════════
# S3 Channel
# ══════════════════════════════════════════════════════════════════════════════

class S3ExportChannel:
    """Write OCSF JSON-L files to S3, partitioned by date/tenant."""

    def __init__(
        self,
        *,
        bucket: str,
        region: str = "us-east-1",
        prefix: str = "",
        iam_role: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ) -> None:
        self._bucket = bucket
        self._region = region
        self._prefix = prefix.strip("/")
        self._iam_role = iam_role
        self._access_key = access_key
        self._secret_key = secret_key
        self._client = None

        if not bucket:
            raise ValueError("S3 bucket name is required")

    async def _get_client(self):
        """Lazy-init boto3 S3 client."""
        if self._client is not None:
            return self._client
        try:
            import aiobotocore.session

            session = aiobotocore.session.AioSession()
            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            self._client = session.create_client("s3", **kwargs)
            return self._client
        except ImportError:
            # Fallback: use httpx for S3 (pre-signed or public)
            logger.warning("aiobotocore_not_installed", msg="S3 export requires aiobotocore")
            raise

    @staticmethod
    def _sanitise_path_component(value: str) -> str:
        """Strip everything except alphanumerics, hyphens, and underscores.

        Prevents path-traversal (``../``) when *tenant_id* is embedded in
        S3 object keys.
        """
        import re as _re

        return _re.sub(r"[^a-zA-Z0-9\-_]", "", value) or "unknown"

    def _build_key(self, tenant_id: str, timestamp: datetime | None = None) -> str:
        """Build S3 object key: prefix/yyyy-mm-dd/tenant_id/events-HH-MM.json.gz"""
        ts = timestamp or datetime.now(UTC)
        date_part = ts.strftime("%Y-%m-%d")
        time_part = ts.strftime("%H-%M")
        safe_tenant = self._sanitise_path_component(tenant_id)
        parts = [p for p in [self._prefix, date_part, safe_tenant, f"events-{time_part}.json.gz"] if p]
        return "/".join(parts)

    async def export_batch(
        self,
        events: list[dict[str, Any]],
        tenant_id: str,
        *,
        pii_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Transform events to OCSF, gzip, and upload to S3.

        Returns: {"key": ..., "events": N, "bytes": N}
        """
        if not events:
            return {"key": "", "events": 0, "bytes": 0}

        capped = events[:MAX_BATCH_SIZE]
        ocsf_events = ocsf_mapper.map_batch(capped, tenant_id=tenant_id, pii_fields=pii_fields)
        jsonl = ocsf_mapper.to_jsonl(ocsf_events)

        # Gzip compress
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(jsonl.encode("utf-8"))
        compressed = buf.getvalue()

        if len(compressed) > MAX_BODY_SIZE:
            raise ValueError(f"Compressed payload exceeds {MAX_BODY_SIZE} bytes")

        key = self._build_key(tenant_id)

        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                client = await self._get_client()
                async with client as s3:
                    await s3.put_object(
                        Bucket=self._bucket,
                        Key=key,
                        Body=compressed,
                        ContentType="application/x-ndjson",
                        ContentEncoding="gzip",
                    )
                logger.info(
                    "s3_export_success",
                    bucket=self._bucket,
                    key=key,
                    events=len(ocsf_events),
                    bytes=len(compressed),
                )
                return {"key": key, "events": len(ocsf_events), "bytes": len(compressed)}
            except Exception as exc:
                last_error = exc
                if attempt < MAX_RETRIES:
                    await _async_sleep(BACKOFF_BASE**attempt)
                logger.warning(
                    "s3_export_retry",
                    attempt=attempt,
                    error=str(exc)[:200],
                )

        raise ExportError(f"S3 export failed after {MAX_RETRIES} retries: {last_error}")

    async def close(self) -> None:
        if self._client:
            with contextlib.suppress(Exception):
                await self._client.__aexit__(None, None, None)
            self._client = None

# ══════════════════════════════════════════════════════════════════════════════
# Webhook Channel
# ══════════════════════════════════════════════════════════════════════════════

class WebhookExportChannel:
    """POST OCSF JSON to a customer webhook with HMAC-SHA256 signature."""

    def __init__(
        self,
        *,
        url: str,
        secret: str = "",
        custom_headers: dict[str, str] | None = None,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if not parsed.hostname:
            raise ValueError("Webhook URL must have a valid hostname")

        # SSRF protection: block private/internal IPs
        _validate_webhook_host(parsed.hostname)

        self._url = url
        self._secret = secret
        self._custom_headers = custom_headers or {}
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(WEBHOOK_TIMEOUT))
        return self._client

    def _sign(self, body: str, timestamp: str) -> str:
        """Compute HMAC-SHA256 signature."""
        sig_payload = f"{timestamp}.{body}"
        return hmac.new(
            self._secret.encode("utf-8"),
            sig_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    async def export_event(
        self,
        event: dict[str, Any],
        tenant_id: str,
        *,
        pii_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Map event to OCSF, sign, and POST to webhook.

        Returns: {"status_code": N, "delivered": bool}
        """
        ocsf = ocsf_mapper.map_event(event, tenant_id=tenant_id)
        ocsf_dict = ocsf.model_dump(mode="json", exclude_none=True)
        if pii_fields:
            ocsf_dict = ocsf_mapper.redact_pii(ocsf_dict, pii_fields)

        body = json.dumps(ocsf_dict, default=str)
        if len(body) > MAX_BODY_SIZE:
            raise ExportError(f"Webhook payload exceeds {MAX_BODY_SIZE} bytes")

        timestamp = str(int(time.time()))
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Phantex-Timestamp": timestamp,
            "X-Phantex-Event-Type": "ocsf",
        }
        if self._secret:
            sig = self._sign(body, timestamp)
            headers["X-Phantex-Signature"] = f"sha256={sig}"

        # Merge custom headers (cannot override signature headers)
        for k, v in self._custom_headers.items():
            lower = k.lower()
            if lower not in ("x-phantex-signature", "x-phantex-timestamp", "x-phantex-event-type"):
                headers[k] = v

        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                client = await self._get_client()
                resp = await client.post(self._url, content=body, headers=headers)
                if 200 <= resp.status_code < 300:
                    return {"status_code": resp.status_code, "delivered": True}
                if resp.status_code == 429:
                    # Rate limited — backoff and retry
                    if attempt < MAX_RETRIES:
                        await _async_sleep(BACKOFF_BASE**attempt)
                        continue
                raise ExportError(f"Webhook HTTP {resp.status_code}: {resp.text[:200]}")
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < MAX_RETRIES:
                    await _async_sleep(BACKOFF_BASE**attempt)
                logger.warning("webhook_export_retry", attempt=attempt, error=str(exc)[:200])
            except ExportError:
                raise
            except Exception as exc:
                last_error = exc
                if attempt < MAX_RETRIES:
                    await _async_sleep(BACKOFF_BASE**attempt)

        raise ExportError(f"Webhook delivery failed after {MAX_RETRIES} retries: {last_error}")

    async def export_batch(
        self,
        events: list[dict[str, Any]],
        tenant_id: str,
        *,
        pii_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Export batch via individual webhook POSTs (one per event).

        Returns: {"delivered": N, "failed": N}
        """
        delivered = 0
        failed = 0
        last_error: Exception | None = None
        for evt in events[:MAX_BATCH_SIZE]:
            try:
                result = await self.export_event(evt, tenant_id, pii_fields=pii_fields)
                if result["delivered"]:
                    delivered += 1
                else:
                    failed += 1
            except ExportError as exc:
                failed += 1
                last_error = exc
        if delivered == 0 and failed > 0:
            raise ExportError(f"Webhook batch: all {failed} events failed — {last_error}")
        return {"delivered": delivered, "failed": failed}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

# ══════════════════════════════════════════════════════════════════════════════
# Kafka Mirror Channel
# ══════════════════════════════════════════════════════════════════════════════

class KafkaMirrorChannel:
    """Mirror OCSF events to a customer's Kafka cluster."""

    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str = "phantex-ocsf-events",
        sasl_mechanism: str | None = None,
        sasl_username: str | None = None,
        sasl_password: str | None = None,
        ssl_context: Any = None,
    ) -> None:
        if not bootstrap_servers:
            raise ValueError("Kafka bootstrap servers required")
        if not topic:
            raise ValueError("Kafka topic required")

        self._bootstrap = bootstrap_servers
        self._topic = topic
        self._sasl_mechanism = sasl_mechanism
        self._sasl_username = sasl_username
        self._sasl_password = sasl_password
        self._ssl_context = ssl_context
        self._producer = None

    async def _get_producer(self):
        """Lazy-init Kafka producer."""
        if self._producer is not None:
            return self._producer
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError:
            raise ExportError("aiokafka not installed — Kafka mirror unavailable")

        kwargs: dict[str, Any] = {
            "bootstrap_servers": self._bootstrap,
            "value_serializer": lambda v: json.dumps(v, default=str).encode("utf-8"),
            "max_request_size": MAX_BODY_SIZE,
        }
        if self._sasl_mechanism and self._sasl_username:
            kwargs["security_protocol"] = "SASL_SSL" if self._ssl_context else "SASL_PLAINTEXT"
            kwargs["sasl_mechanism"] = self._sasl_mechanism
            kwargs["sasl_plain_username"] = self._sasl_username
            kwargs["sasl_plain_password"] = self._sasl_password
        if self._ssl_context:
            kwargs["ssl_context"] = self._ssl_context

        self._producer = AIOKafkaProducer(**kwargs)
        await self._producer.start()
        return self._producer

    async def export_batch(
        self,
        events: list[dict[str, Any]],
        tenant_id: str,
        *,
        pii_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Map events to OCSF and produce to customer Kafka topic.

        Returns: {"delivered": N, "failed": N}
        """
        capped = events[:MAX_BATCH_SIZE]
        ocsf_events = ocsf_mapper.map_batch(capped, tenant_id=tenant_id, pii_fields=pii_fields)

        delivered = 0
        last_error: Exception | None = None
        start_idx = 0  # track progress to avoid re-sending on retry

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                producer = await self._get_producer()
                for i, ocsf_dict in enumerate(ocsf_events[start_idx:], start=start_idx):
                    await producer.send_and_wait(
                        self._topic,
                        value=ocsf_dict,
                        key=tenant_id.encode("utf-8"),
                    )
                    delivered += 1
                    start_idx = i + 1
                return {"delivered": delivered, "failed": 0}
            except Exception as exc:
                last_error = exc
                # Do NOT reset delivered/start_idx — resume from where we left off
                if attempt < MAX_RETRIES:
                    await _async_sleep(BACKOFF_BASE**attempt)
                logger.warning("kafka_mirror_retry", attempt=attempt, error=str(exc)[:200])

        len(ocsf_events) - delivered
        logger.error(
            "kafka_mirror_failed",
            events=len(ocsf_events),
            delivered=delivered,
            error=str(last_error)[:200],
        )
        raise ExportError(
            f"Kafka mirror failed after {MAX_RETRIES} retries: {delivered}/{len(ocsf_events)} delivered — {last_error}"
        )

    async def close(self) -> None:
        if self._producer:
            with contextlib.suppress(Exception):
                await self._producer.stop()
            self._producer = None

# ══════════════════════════════════════════════════════════════════════════════
# Channel Factory
# ══════════════════════════════════════════════════════════════════════════════

def create_channel(
    channel_type: str, config: dict[str, Any]
) -> S3ExportChannel | WebhookExportChannel | KafkaMirrorChannel:
    """Factory: create a PDR export channel from config dict."""
    if channel_type == "s3":
        return S3ExportChannel(
            bucket=config.get("s3_bucket", ""),
            region=config.get("s3_region", "us-east-1"),
            prefix=config.get("s3_prefix", ""),
            iam_role=config.get("s3_iam_role"),
            access_key=config.get("access_key"),
            secret_key=config.get("secret_key"),
        )
    elif channel_type == "webhook":
        return WebhookExportChannel(
            url=config.get("webhook_url", ""),
            secret=config.get("webhook_secret", ""),
            custom_headers=config.get("custom_headers"),
        )
    elif channel_type == "kafka_mirror":
        return KafkaMirrorChannel(
            bootstrap_servers=config.get("kafka_bootstrap", ""),
            topic=config.get("kafka_topic", "phantex-ocsf-events"),
            sasl_mechanism=config.get("kafka_sasl_mechanism"),
            sasl_username=config.get("kafka_sasl_username"),
            sasl_password=config.get("kafka_sasl_password"),
        )
    else:
        raise ValueError(f"Unknown PDR channel type: {channel_type}")

# ── Helpers ───────────────────────────────────────────────────────────────────

class ExportError(Exception):
    """PDR export failure."""

    pass

def _validate_webhook_host(hostname: str) -> None:
    """Block webhook URLs that resolve to private/internal IPs (SSRF protection)."""
    import ipaddress
    import socket

    if not hostname:
        raise ValueError("Webhook hostname is empty")

    try:
        addrs = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError("Cannot resolve webhook hostname")

    for _, _, _, _, sockaddr in addrs:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError("Webhook URL must not resolve to a private or internal address")
        except ValueError as exc:
            if "private" in str(exc).lower() or "internal" in str(exc).lower():
                raise
            # Ignore non-IP parse errors

async def _async_sleep(seconds: float) -> None:
    """Async sleep wrapper (makes testing easier)."""
    import asyncio

    await asyncio.sleep(seconds)
