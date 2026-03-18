# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Email Notification Channel (N2).

Sends alert notifications via SMTP or SendGrid API.
Uses HTML template for rich formatting.
"""

from __future__ import annotations

import json
import smtplib
import ssl as ssl_module
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import structlog

from app.notifications.base import BaseNotificationChannel, NotificationError

logger = structlog.get_logger("phantex.notification.email")

# Severity → color for HTML
_SEVERITY_COLOR = {
    "critical": "#e01e5a",
    "high": "#ff6600",
    "medium": "#ecb22e",
    "low": "#36a64f",
    "info": "#cccccc",
}

class EmailChannel(BaseNotificationChannel):
    """Email notification channel (SMTP or SendGrid)."""

    channel_type = "email"

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._mode = config.get("mode", "smtp")  # "smtp" or "sendgrid"
        self._from_addr = config.get("from_address", "alerts@localhost")
        self._to_addrs = config.get("to_addresses", [])

        if not self._to_addrs:
            raise NotificationError("Email to_addresses required", retryable=False)

        # F3: Validate email addresses to prevent SMTP header injection
        for addr in self._to_addrs:
            if not isinstance(addr, str) or "\n" in addr or "\r" in addr:
                raise NotificationError(
                    "Email address contains invalid characters (CR/LF)",
                    retryable=False,
                )
        if not isinstance(self._from_addr, str) or "\n" in self._from_addr or "\r" in self._from_addr:
            raise NotificationError(
                "From address contains invalid characters (CR/LF)",
                retryable=False,
            )

        # SMTP config
        self._smtp_host = config.get("smtp_host", "")
        try:
            self._smtp_port = int(config.get("smtp_port", 587))
        except (ValueError, TypeError):
            raise NotificationError(
                f"SMTP port must be numeric (got {str(config.get('smtp_port'))[:20]})",
                retryable=False,
            )
        self._smtp_user = config.get("smtp_user", "")
        self._smtp_pass = config.get("smtp_password", "")
        self._smtp_tls = config.get("smtp_tls", True)

        # SendGrid config
        self._sendgrid_key = config.get("sendgrid_api_key", "")

        if self._mode == "smtp" and not self._smtp_host:
            raise NotificationError("SMTP host required", retryable=False)
        if self._mode == "sendgrid" and not self._sendgrid_key:
            raise NotificationError("SendGrid API key required", retryable=False)

    async def send(self, alert: dict[str, Any]) -> bool:
        self._check_rate_limit()

        if self._mode == "sendgrid":
            return await self._send_sendgrid(alert)
        return await self._send_smtp(alert)

    async def _send_smtp(self, alert: dict[str, Any]) -> bool:
        """Send via SMTP (runs in thread to avoid blocking)."""
        import asyncio

        try:
            await asyncio.get_event_loop().run_in_executor(None, self._smtp_send_sync, alert)
            return True
        except Exception as e:
            raise NotificationError(f"SMTP error: {e}", retryable=True)

    def _smtp_send_sync(self, alert: dict[str, Any]) -> None:
        """Synchronous SMTP send."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = _build_subject(alert)
        msg["From"] = self._from_addr
        msg["To"] = ", ".join(self._to_addrs)

        html = _build_html(alert)
        msg.attach(MIMEText(html, "html"))

        if self._smtp_tls:
            ctx = ssl_module.create_default_context()
            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                server.ehlo()
                server.starttls(context=ctx)
                if self._smtp_user:
                    server.login(self._smtp_user, self._smtp_pass)
                server.sendmail(self._from_addr, self._to_addrs, msg.as_string())
        else:
            # F8: Warn when sending credentials over plaintext SMTP
            if self._smtp_user:
                logger.warning(
                    "smtp_plaintext_login",
                    host=self._smtp_host,
                    port=self._smtp_port,
                    msg="SMTP credentials sent without TLS — consider enabling smtp_tls",
                )
            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                if self._smtp_user:
                    server.login(self._smtp_user, self._smtp_pass)
                server.sendmail(self._from_addr, self._to_addrs, msg.as_string())

    async def _send_sendgrid(self, alert: dict[str, Any]) -> bool:
        """Send via SendGrid API."""
        import httpx

        payload = {
            "personalizations": [{"to": [{"email": addr} for addr in self._to_addrs]}],
            "from": {"email": self._from_addr},
            "subject": _build_subject(alert),
            "content": [{"type": "text/html", "value": _build_html(alert)}],
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.sendgrid.com/v3/mail/send",
                    content=json.dumps(payload),
                    headers={
                        "Authorization": f"Bearer {self._sendgrid_key}",
                        "Content-Type": "application/json",
                    },
                )
                if resp.status_code in (200, 202):
                    return True
                raise NotificationError(f"SendGrid HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.HTTPError as e:
            raise NotificationError(f"SendGrid error: {e}", retryable=True)

    async def test(self) -> dict[str, Any]:
        try:
            result = await self.send(
                {
                    "rule_name": "phantex_test",
                    "severity": "info",
                    "agent_id": "test-agent",
                    "message": "Phantex email connectivity test",
                }
            )
            return {"success": result, "message": "Test email sent"}
        except NotificationError as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        pass  # SMTP connections are opened/closed per send

# ── Templates ────────────────────────────────────────────────────────────────

def _build_subject(alert: dict[str, Any]) -> str:
    severity = alert.get("severity", "info").upper()
    rule_name = alert.get("rule_name", "Alert")
    return f"[Phantex {severity}] {rule_name}"

def _build_html(alert: dict[str, Any]) -> str:
    severity = alert.get("severity", "info")
    color = _SEVERITY_COLOR.get(severity, "#cccccc")
    rule_name = alert.get("rule_name", "Unknown")
    agent_id = alert.get("agent_id", "N/A")
    message = alert.get("message", alert.get("description", "No details"))
    attack_class = alert.get("attack_class", "N/A")
    alert_id = alert.get("alert_id", "N/A")
    tenant_id = alert.get("tenant_id", "N/A")

    return f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: {color}; color: white; padding: 16px 20px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Phantex Alert: {_html_escape(rule_name)}</h2>
            <p style="margin: 4px 0 0; opacity: 0.9;">Severity: {severity.upper()}</p>
        </div>
        <div style="border: 1px solid #e0e0e0; border-top: 0; padding: 20px; border-radius: 0 0 8px 8px;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px 0; color: #666;">Agent</td><td style="padding: 8px 0;"><code>{_html_escape(str(agent_id))}</code></td></tr>
                <tr><td style="padding: 8px 0; color: #666;">Attack Class</td><td style="padding: 8px 0;">{_html_escape(str(attack_class))}</td></tr>
                <tr><td style="padding: 8px 0; color: #666;">Alert ID</td><td style="padding: 8px 0;"><code>{_html_escape(str(alert_id))}</code></td></tr>
                <tr><td style="padding: 8px 0; color: #666;">Tenant</td><td style="padding: 8px 0;"><code>{_html_escape(str(tenant_id))}</code></td></tr>
            </table>
            <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 16px 0;">
            <p style="color: #333;">{_html_escape(str(message)[:2000])}</p>
            <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 16px 0;">
            <p style="color: #999; font-size: 12px;">This alert was generated by Phantex AI Security Platform.</p>
        </div>
    </div>
    """

def _html_escape(s: str) -> str:
    """Basic HTML escaping to prevent XSS in email templates."""
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    )
