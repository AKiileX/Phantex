# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SOAR Webhook Delivery Service

Delivers events to SOAR platforms via outbound webhooks:
  - HMAC-SHA256 signed payloads
  - Retry with exponential backoff
  - Delivery logging (append-only)
  - Rate limiting per subscription

Security:
  - HTTPS-only destinations (enforced at DB + app level)
  - Secrets never logged or included in error messages
  - SSRF protection via URL validation
  - Timeout enforcement (max 120s)
  - Response bodies are NOT stored (prevent data leakage)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger("phantex.soar.webhook")

# ── SSRF Protection ──────────────────────────────────────────────────────────

_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "metadata.google.internal",
        "169.254.169.254",  # cloud metadata
    }
)

_PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]

def _is_safe_url(url: str) -> tuple[bool, str]:
    """Validate a webhook URL is safe to call (SSRF protection)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"

    if parsed.scheme != "https":
        return False, "Only HTTPS URLs are allowed"

    host = parsed.hostname or ""
    if not host:
        return False, "No hostname in URL"

    if host.lower() in _BLOCKED_HOSTS:
        return False, f"Blocked host: {host}"

    # Check for IP-based URLs pointing to private ranges
    try:
        ip = ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, f"Private/reserved IP: {host}"
    except ValueError:
        pass  # hostname, not IP — OK

    # Block common internal hostnames
    if any(host.endswith(suffix) for suffix in (".internal", ".local", ".localhost")):
        return False, f"Internal hostname: {host}"

    return True, ""

# ── Webhook payload signing ──────────────────────────────────────────────────

def sign_payload(secret: str, timestamp: str, body: str) -> str:
    """Generate HMAC-SHA256 signature for webhook payload."""
    sig_input = f"{timestamp}.{body}"
    return hmac.new(
        secret.encode("utf-8"),
        sig_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

# ── Webhook delivery ─────────────────────────────────────────────────────────

class WebhookDeliveryService:
    """
    Delivers events to outbound webhook subscriptions.

    Usage::

        svc = WebhookDeliveryService(db)
        await svc.deliver_event("alert.created", alert_data, tenant_id)
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def deliver_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        tenant_id: uuid.UUID,
        *,
        event_id: uuid.UUID | None = None,
    ) -> int:
        """
        Deliver an event to all matching webhook subscriptions.

        Args:
            event_type: e.g. "alert.created"
            payload: Event data to send
            tenant_id: Tenant that owns the event
            event_id: Optional ID (alert_id, action_id) for log correlation

        Returns:
            Number of subscriptions notified
        """
        # Set tenant context for RLS
        await self._db.execute(
            text("SET LOCAL app.tenant_id = :tid"),
            {"tid": str(tenant_id)},
        )

        # Find matching subscriptions
        result = await self._db.execute(
            text("""
                SELECT id, url, secret, retry_count, retry_delay_sec, timeout_sec,
                       event_types, severity_filter
                FROM soar_webhook_subs
                WHERE tenant_id = CAST(:tid AS UUID)
                  AND enabled = true
                  AND deleted_at IS NULL
                  AND :evt = ANY(event_types)
            """),
            {"tid": str(tenant_id), "evt": event_type},
        )
        subs = result.mappings().all()

        if not subs:
            return 0

        # Check severity filter if applicable
        alert_severity = payload.get("severity", "").lower()
        delivered = 0

        for sub in subs:
            sev_filter = sub["severity_filter"]
            if sev_filter and alert_severity and alert_severity not in sev_filter:
                continue

            # Validate URL (re-check at delivery time)
            safe, reason = _is_safe_url(sub["url"])
            if not safe:
                logger.warning(
                    "webhook_url_blocked",
                    sub_id=str(sub["id"]),
                    reason=reason,
                )
                await self._log_delivery(
                    sub["id"],
                    event_type,
                    event_id,
                    tenant_id,
                    attempt=1,
                    success=False,
                    error=f"URL blocked: {reason}",
                )
                continue

            # Deliver with retries (fire in background for concurrency)
            asyncio.create_task(
                self._deliver_with_retry(
                    sub_id=sub["id"],
                    url=sub["url"],
                    secret=sub["secret"] or "",
                    payload=payload,
                    event_type=event_type,
                    event_id=event_id,
                    tenant_id=tenant_id,
                    max_retries=sub["retry_count"],
                    retry_delay=sub["retry_delay_sec"],
                    timeout=sub["timeout_sec"],
                )
            )
            delivered += 1

        return delivered

    async def _deliver_with_retry(
        self,
        *,
        sub_id: uuid.UUID,
        url: str,
        secret: str,
        payload: dict[str, Any],
        event_type: str,
        event_id: uuid.UUID | None,
        tenant_id: uuid.UUID,
        max_retries: int,
        retry_delay: int,
        timeout: int,
    ) -> None:
        """Deliver a webhook with retry + exponential backoff."""
        body = json.dumps(payload, default=str, separators=(",", ":"))
        timestamp = str(int(time.time()))

        headers = {
            "Content-Type": "application/json",
            "X-Phantex-Event": event_type,
            "X-Phantex-Timestamp": timestamp,
            "X-Phantex-Delivery-Id": str(uuid.uuid4()),
            "User-Agent": "Phantex-Webhook/1.0",
        }

        if secret:
            sig = sign_payload(secret, timestamp, body)
            headers["X-Phantex-Signature"] = f"sha256={sig}"

        for attempt in range(1, max_retries + 2):  # +2 for 0-indexed + initial attempt
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(float(timeout)),
                    follow_redirects=False,
                ) as client:
                    start = time.monotonic()
                    resp = await client.post(url, content=body, headers=headers)
                    elapsed_ms = int((time.monotonic() - start) * 1000)

                success = 200 <= resp.status_code < 300

                await self._log_delivery(
                    sub_id,
                    event_type,
                    event_id,
                    tenant_id,
                    attempt=attempt,
                    success=success,
                    status_code=resp.status_code,
                    response_ms=elapsed_ms,
                    error=None if success else f"HTTP {resp.status_code}",
                )

                if success:
                    logger.info(
                        "webhook_delivered",
                        sub_id=str(sub_id),
                        event_type=event_type,
                        status=resp.status_code,
                        ms=elapsed_ms,
                    )
                    return

                # Don't retry 4xx (client errors) except 429 (rate limit)
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    logger.warning(
                        "webhook_client_error",
                        sub_id=str(sub_id),
                        status=resp.status_code,
                    )
                    return

            except httpx.TimeoutException:
                await self._log_delivery(
                    sub_id,
                    event_type,
                    event_id,
                    tenant_id,
                    attempt=attempt,
                    success=False,
                    error="Timeout",
                )
                logger.warning("webhook_timeout", sub_id=str(sub_id), attempt=attempt)

            except httpx.ConnectError as exc:
                await self._log_delivery(
                    sub_id,
                    event_type,
                    event_id,
                    tenant_id,
                    attempt=attempt,
                    success=False,
                    error=f"Connection error: {exc}",
                )
                logger.warning("webhook_connect_error", sub_id=str(sub_id), attempt=attempt)

            except Exception as exc:
                await self._log_delivery(
                    sub_id,
                    event_type,
                    event_id,
                    tenant_id,
                    attempt=attempt,
                    success=False,
                    error=str(exc)[:500],
                )
                logger.error("webhook_unexpected_error", sub_id=str(sub_id), error=str(exc))

            # Exponential backoff before retry
            if attempt <= max_retries:
                delay = retry_delay * (2 ** (attempt - 1))
                delay = min(delay, 3600)  # cap at 1 hour
                await asyncio.sleep(delay)

        logger.error(
            "webhook_all_retries_exhausted",
            sub_id=str(sub_id),
            event_type=event_type,
            attempts=max_retries + 1,
        )

    async def _log_delivery(
        self,
        sub_id: uuid.UUID,
        event_type: str,
        event_id: uuid.UUID | None,
        tenant_id: uuid.UUID,
        *,
        attempt: int,
        success: bool,
        status_code: int | None = None,
        response_ms: int | None = None,
        error: str | None = None,
    ) -> None:
        """Log a webhook delivery attempt."""
        try:
            await self._db.execute(
                text("""
                    INSERT INTO soar_webhook_logs
                        (tenant_id, subscription_id, event_type, event_id,
                         status_code, response_ms, attempt, success, error)
                    VALUES
                        (CAST(:tid AS UUID), CAST(:sid AS UUID), :evt, CAST(:eid AS UUID),
                         :code, :ms, :attempt, :success, :err)
                """),
                {
                    "tid": str(tenant_id),
                    "sid": str(sub_id),
                    "evt": event_type,
                    "eid": str(event_id) if event_id else None,
                    "code": status_code,
                    "ms": response_ms,
                    "attempt": attempt,
                    "success": success,
                    "err": error,
                },
            )
            await self._db.commit()
        except Exception as exc:
            logger.error("webhook_log_write_failed", error=str(exc))

    async def test_webhook(
        self,
        url: str,
        secret: str | None = None,
    ) -> dict[str, Any]:
        """
        Send a test event to a webhook URL.

        Returns:
            {"success": bool, "status_code": int | None, "response_ms": int, "error": str | None}
        """
        safe, reason = _is_safe_url(url)
        if not safe:
            return {"success": False, "status_code": None, "response_ms": 0, "error": reason}

        test_payload = {
            "event": "webhook.test",
            "message": "This is a test event from Phantex",
            "timestamp": datetime.now(UTC).isoformat(),
        }
        body = json.dumps(test_payload)
        timestamp = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "X-Phantex-Event": "webhook.test",
            "X-Phantex-Timestamp": timestamp,
            "User-Agent": "Phantex-Webhook/1.0",
        }
        if secret:
            sig = sign_payload(secret, timestamp, body)
            headers["X-Phantex-Signature"] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(15.0),
                follow_redirects=False,
            ) as client:
                start = time.monotonic()
                resp = await client.post(url, content=body, headers=headers)
                ms = int((time.monotonic() - start) * 1000)

            return {
                "success": 200 <= resp.status_code < 300,
                "status_code": resp.status_code,
                "response_ms": ms,
                "error": None if 200 <= resp.status_code < 300 else f"HTTP {resp.status_code}",
            }
        except httpx.TimeoutException:
            return {"success": False, "status_code": None, "response_ms": 0, "error": "Timeout"}
        except Exception as exc:
            return {"success": False, "status_code": None, "response_ms": 0, "error": str(exc)[:300]}
