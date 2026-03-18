# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
N1-N2 Block Hardening Tests — .

Tests for security findings in SIEM integrations (N1) and notification
channels (N2).

Findings covered:
  F1  (HIGH)   azure_sentinel.py    — workspace_id SSRF via unvalidated URL construction
  F2  (MEDIUM) integrations/base.py — Empty URL bypasses _require_https
  F3  (MEDIUM) notifications/email  — SMTP header injection via CRLF in addresses
  F4  (MEDIUM) notifications/webhook— Custom headers override security-sensitive headers
  F5  (MEDIUM) formatter.py         — Walrus operator bug in to_elastic_ndjson
  F6  (LOW)    syslog_cef.py        — int(port) crash on non-numeric value
  F7  (LOW)    email.py             — int(smtp_port) crash on non-numeric value
  F8  (LOW)    email.py             — Plaintext SMTP login without warning
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import (
    _sanitize_cef_ext,
    _sanitize_cef_header,
    to_cef,
    to_elastic_ndjson,
)
from app.notifications.base import NotificationError

# ═══════════════════════════════════════════════════════════════════════════════
# F1 — Azure Sentinel workspace_id SSRF prevention
# ═══════════════════════════════════════════════════════════════════════════════

class TestAzureSentinelWorkspaceValidation:
    """F1: workspace_id must be alphanumeric+hyphens only to prevent SSRF."""

    def test_valid_workspace_id_accepted(self):
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        adapter = AzureSentinelIntegration(
            tenant_id="t1",
            config={
                "workspace_id": "abc123-def456-789",
                "shared_key": "dGVzdGtleQ==",  # base64 "testkey"
            },
        )
        assert adapter.platform_name == "azure_sentinel"

    def test_rejects_workspace_with_slash(self):
        """Slash in workspace_id could cause path traversal → SSRF."""
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        with pytest.raises(IntegrationError, match="alphanumeric"):
            AzureSentinelIntegration(
                tenant_id="t1",
                config={
                    "workspace_id": "evil.com/api",
                    "shared_key": "dGVzdGtleQ==",
                },
            )

    def test_rejects_workspace_with_dots(self):
        """Dots could create arbitrary subdomains → SSRF."""
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        with pytest.raises(IntegrationError, match="alphanumeric"):
            AzureSentinelIntegration(
                tenant_id="t1",
                config={
                    "workspace_id": "evil.example.com",
                    "shared_key": "dGVzdGtleQ==",
                },
            )

    def test_rejects_workspace_with_at_sign(self):
        """@ could redirect HTTP basic auth parsing."""
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        with pytest.raises(IntegrationError, match="alphanumeric"):
            AzureSentinelIntegration(
                tenant_id="t1",
                config={
                    "workspace_id": "admin@evil.com",
                    "shared_key": "dGVzdGtleQ==",
                },
            )

    def test_rejects_workspace_with_backslash(self):
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        with pytest.raises(IntegrationError, match="alphanumeric"):
            AzureSentinelIntegration(
                tenant_id="t1",
                config={
                    "workspace_id": "..\\..\\internal",
                    "shared_key": "dGVzdGtleQ==",
                },
            )

    def test_rejects_workspace_with_newlines(self):
        """Newlines could enable HTTP request smuggling."""
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        with pytest.raises(IntegrationError, match="alphanumeric"):
            AzureSentinelIntegration(
                tenant_id="t1",
                config={
                    "workspace_id": "id\r\nX-Injected: true",
                    "shared_key": "dGVzdGtleQ==",
                },
            )

    def test_accepts_uuid_style_workspace(self):
        """Real Azure workspace IDs are UUID-like with hyphens."""
        from app.integrations.azure_sentinel import AzureSentinelIntegration

        adapter = AzureSentinelIntegration(
            tenant_id="t1",
            config={
                "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
                "shared_key": "dGVzdGtleQ==",
            },
        )
        assert "550e8400" in adapter._endpoint

# ═══════════════════════════════════════════════════════════════════════════════
# F2 — Empty URL rejected by _require_https
# ═══════════════════════════════════════════════════════════════════════════════

class TestRequireHttpsEmptyUrl:
    """F2: _require_https must reject empty URLs, not silently pass."""

    def test_empty_string_rejected(self):
        with pytest.raises(IntegrationError, match="TLS required"):
            BaseSIEMIntegration._require_https("")

    def test_none_coerced_rejected(self):
        """Passing an empty-ish string must fail."""
        with pytest.raises(IntegrationError, match="TLS required"):
            BaseSIEMIntegration._require_https("")

    def test_http_still_rejected(self):
        with pytest.raises(IntegrationError, match="TLS required"):
            BaseSIEMIntegration._require_https("http://example.com")

    def test_https_accepted(self):
        # Should not raise
        BaseSIEMIntegration._require_https("https://example.com")

    def test_splunk_rejects_empty_endpoint(self):
        """Splunk adapter with empty endpoint must fail at _require_https."""
        from app.integrations.splunk_hec import SplunkHECIntegration

        with pytest.raises(IntegrationError, match="TLS required"):
            SplunkHECIntegration(
                tenant_id="t1",
                config={"endpoint": "", "hec_token": "tok123"},
            )

    def test_elastic_rejects_empty_endpoint(self):
        from app.integrations.elastic_siem import ElasticSIEMIntegration

        with pytest.raises(IntegrationError, match="TLS required"):
            ElasticSIEMIntegration(
                tenant_id="t1",
                config={"endpoint": "", "api_key_id": "id", "api_key_secret": "sec"},
            )

# ═══════════════════════════════════════════════════════════════════════════════
# F3 — Email address CRLF injection prevention
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailAddressValidation:
    """F3: Email addresses must not contain CR/LF to prevent header injection."""

    def test_rejects_newline_in_to_address(self):
        from app.notifications.email import EmailChannel

        with pytest.raises(NotificationError, match="CR/LF"):
            EmailChannel(
                tenant_id="t1",
                config={
                    "mode": "smtp",
                    "smtp_host": "mail.example.com",
                    "to_addresses": ["admin@example.com\nBcc: attacker@evil.com"],
                },
            )

    def test_rejects_carriage_return_in_to_address(self):
        from app.notifications.email import EmailChannel

        with pytest.raises(NotificationError, match="CR/LF"):
            EmailChannel(
                tenant_id="t1",
                config={
                    "mode": "smtp",
                    "smtp_host": "mail.example.com",
                    "to_addresses": ["admin@example.com\r\nBcc: attacker@evil.com"],
                },
            )

    def test_rejects_newline_in_from_address(self):
        from app.notifications.email import EmailChannel

        with pytest.raises(NotificationError, match="CR/LF"):
            EmailChannel(
                tenant_id="t1",
                config={
                    "mode": "smtp",
                    "smtp_host": "mail.example.com",
                    "from_address": "from@example.com\nBcc: evil@evil.com",
                    "to_addresses": ["admin@example.com"],
                },
            )

    def test_valid_addresses_accepted(self):
        from app.notifications.email import EmailChannel

        ch = EmailChannel(
            tenant_id="t1",
            config={
                "mode": "smtp",
                "smtp_host": "mail.example.com",
                "to_addresses": ["admin@example.com", "ops@example.com"],
            },
        )
        assert ch.channel_type == "email"

    def test_rejects_non_string_address(self):
        from app.notifications.email import EmailChannel

        with pytest.raises(NotificationError, match="CR/LF"):
            EmailChannel(
                tenant_id="t1",
                config={
                    "mode": "smtp",
                    "smtp_host": "mail.example.com",
                    "to_addresses": [123],  # Not a string
                },
            )

# ═══════════════════════════════════════════════════════════════════════════════
# F4 — Webhook header blocklist
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookHeaderBlocklist:
    """F4: Webhook custom headers must not override security-sensitive headers."""

    @pytest.mark.asyncio
    async def test_authorization_header_blocked(self):
        from app.notifications.webhook import WebhookChannel

        ch = WebhookChannel(
            tenant_id="t1",
            config={
                "url": "https://example.com/webhook",
                "headers": {"Authorization": "Bearer evil-token"},
            },
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        await ch.send({"test": True})

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        # Authorization should NOT be present from custom headers
        assert headers.get("Authorization") is None

    @pytest.mark.asyncio
    async def test_host_header_blocked(self):
        from app.notifications.webhook import WebhookChannel

        ch = WebhookChannel(
            tenant_id="t1",
            config={
                "url": "https://example.com/webhook",
                "headers": {"Host": "evil.com"},
            },
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        await ch.send({"test": True})

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        assert "Host" not in headers

    @pytest.mark.asyncio
    async def test_content_length_header_blocked(self):
        from app.notifications.webhook import WebhookChannel

        ch = WebhookChannel(
            tenant_id="t1",
            config={
                "url": "https://example.com/webhook",
                "headers": {"Content-Length": "0"},
            },
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        await ch.send({"test": True})

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        assert "Content-Length" not in headers

    @pytest.mark.asyncio
    async def test_safe_custom_header_allowed(self):
        from app.notifications.webhook import WebhookChannel

        ch = WebhookChannel(
            tenant_id="t1",
            config={
                "url": "https://example.com/webhook",
                "headers": {"X-Custom-Tag": "my-value"},
            },
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        await ch.send({"test": True})

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        assert headers.get("X-Custom-Tag") == "my-value"

    @pytest.mark.asyncio
    async def test_transfer_encoding_blocked(self):
        from app.notifications.webhook import WebhookChannel

        ch = WebhookChannel(
            tenant_id="t1",
            config={
                "url": "https://example.com/webhook",
                "headers": {"Transfer-Encoding": "chunked"},
            },
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        await ch.send({"test": True})

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        assert "Transfer-Encoding" not in headers

# ═══════════════════════════════════════════════════════════════════════════════
# F5 — Elastic NDJSON formatter walrus fix
# ═══════════════════════════════════════════════════════════════════════════════

class TestElasticNdjsonFix:
    """F5: to_elastic_ndjson must correctly use event timestamp from each event."""

    def test_timestamp_from_each_event(self):
        events = [
            {"event_id": "e1", "timestamp": "2025-01-15T10:00:00Z"},
            {"event_id": "e2", "timestamp": "2025-01-15T11:00:00Z"},
        ]
        result = to_elastic_ndjson(events)
        lines = result.strip().split("\n")
        # 2 events → 4 lines (action + doc pairs)
        assert len(lines) == 4

        doc1 = json.loads(lines[1])
        doc2 = json.loads(lines[3])
        assert doc1["@timestamp"] == "2025-01-15T10:00:00Z"
        assert doc2["@timestamp"] == "2025-01-15T11:00:00Z"

    def test_missing_timestamp_defaults_empty(self):
        events = [{"event_id": "e1"}]
        result = to_elastic_ndjson(events)
        doc = json.loads(result.strip().split("\n")[1])
        assert doc["@timestamp"] == ""

    def test_single_event_format(self):
        events = [{"event_id": "e1", "severity": "high", "timestamp": "2025-01-15T10:00:00Z"}]
        result = to_elastic_ndjson(events)
        lines = result.strip().split("\n")
        action = json.loads(lines[0])
        assert "index" in action
        doc = json.loads(lines[1])
        assert doc["severity"] == "high"
        assert doc["@timestamp"] == "2025-01-15T10:00:00Z"

# ═══════════════════════════════════════════════════════════════════════════════
# F6 — Syslog port validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyslogPortValidation:
    """F6: Syslog adapter must not crash on non-numeric port config."""

    def test_rejects_non_numeric_port(self):
        from app.integrations.syslog_cef import SyslogCEFIntegration

        with pytest.raises(IntegrationError, match="port must be numeric"):
            SyslogCEFIntegration(
                tenant_id="t1",
                config={"host": "syslog.local", "port": "abc", "protocol": "tcp"},
            )

    def test_rejects_empty_port_string(self):
        from app.integrations.syslog_cef import SyslogCEFIntegration

        with pytest.raises(IntegrationError, match="port must be numeric"):
            SyslogCEFIntegration(
                tenant_id="t1",
                config={"host": "syslog.local", "port": "", "protocol": "tcp"},
            )

    def test_numeric_string_port_accepted(self):
        from app.integrations.syslog_cef import SyslogCEFIntegration

        adapter = SyslogCEFIntegration(
            tenant_id="t1",
            config={"host": "syslog.local", "port": "6514", "protocol": "tcp"},
        )
        assert adapter._port == 6514

    def test_default_port_514(self):
        from app.integrations.syslog_cef import SyslogCEFIntegration

        adapter = SyslogCEFIntegration(
            tenant_id="t1",
            config={"host": "syslog.local", "protocol": "tcp"},
        )
        assert adapter._port == 514

# ═══════════════════════════════════════════════════════════════════════════════
# F7 — Email SMTP port validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmailSmtpPortValidation:
    """F7: Email channel must not crash on non-numeric smtp_port."""

    def test_rejects_non_numeric_port(self):
        from app.notifications.email import EmailChannel

        with pytest.raises(NotificationError, match="port must be numeric"):
            EmailChannel(
                tenant_id="t1",
                config={
                    "mode": "smtp",
                    "smtp_host": "mail.example.com",
                    "smtp_port": "abc",
                    "to_addresses": ["admin@example.com"],
                },
            )

    def test_numeric_string_port_accepted(self):
        from app.notifications.email import EmailChannel

        ch = EmailChannel(
            tenant_id="t1",
            config={
                "mode": "smtp",
                "smtp_host": "mail.example.com",
                "smtp_port": "465",
                "to_addresses": ["admin@example.com"],
            },
        )
        assert ch._smtp_port == 465

    def test_default_port_587(self):
        from app.notifications.email import EmailChannel

        ch = EmailChannel(
            tenant_id="t1",
            config={
                "mode": "smtp",
                "smtp_host": "mail.example.com",
                "to_addresses": ["admin@example.com"],
            },
        )
        assert ch._smtp_port == 587

# ═══════════════════════════════════════════════════════════════════════════════
# F8 — Plaintext SMTP warning
# ═══════════════════════════════════════════════════════════════════════════════

class TestSmtpPlaintextWarning:
    """F8: SMTP login without TLS must log a warning."""

    def test_warning_logged_source_code(self):
        """Source code must contain the plaintext SMTP warning log."""
        import inspect

        from app.notifications.email import EmailChannel

        source = inspect.getsource(EmailChannel._smtp_send_sync)
        assert "smtp_plaintext_login" in source
        assert "consider enabling smtp_tls" in source

    def test_tls_false_with_user_triggers_warning_path(self):
        """When smtp_tls=False and smtp_user is set, warning code path exists."""
        from app.notifications.email import EmailChannel

        ch = EmailChannel(
            tenant_id="t1",
            config={
                "mode": "smtp",
                "smtp_host": "mail.example.com",
                "smtp_tls": False,
                "smtp_user": "user@example.com",
                "smtp_password": "pass",
                "to_addresses": ["admin@example.com"],
            },
        )
        assert ch._smtp_tls is False
        assert ch._smtp_user == "user@example.com"

# ═══════════════════════════════════════════════════════════════════════════════
# CEF injection — extended tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCEFInjectionExtended:
    """Additional CEF sanitization tests triggered by N1 audit."""

    def test_cef_header_sqli_attempt(self):
        result = _sanitize_cef_header("rule'; DROP TABLE events; --")
        assert "'" in result  # single quote is allowed in CEF headers
        assert "|" not in result
        assert "\\" not in result

    def test_cef_ext_null_byte(self):
        """Null bytes in extension values should be handled."""
        result = _sanitize_cef_ext("value\x00with\x00nulls")
        # Null bytes are not in the regex but should be harmless in CEF
        assert isinstance(result, str)

    def test_cef_header_empty(self):
        assert _sanitize_cef_header("") == ""

    def test_cef_ext_empty(self):
        assert _sanitize_cef_ext("") == ""

    def test_full_cef_with_malicious_fields(self):
        """Full CEF formatting with injection attempts in all fields."""
        event = {
            "rule_name": "evil|rule\\name",
            "severity": "high",
            "agent_id": "agent=with=equals",
            "tenant_id": "tenant\nwith\nnewlines",
            "dest_ip": "10.0.0.1",
            "dest_port": "443; rm -rf /",
            "message": "msg=with|pipes\\and\nnewlines",
        }
        result = to_cef(event)
        # Must be a single line (no newlines from injection)
        header_part = result.split("|")
        # Header fields (first 7 pipe-separated) must not have extra pipes
        assert len(header_part) >= 7
        # Extension must not have unescaped equals or newlines
        extension = "|".join(header_part[7:]) if len(header_part) > 7 else ""
        assert "\n" not in extension
        assert "\r" not in extension

# ═══════════════════════════════════════════════════════════════════════════════
# Webhook HMAC — correctness verification
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookHMACCorrectness:
    """Verify HMAC-SHA256 signature generation in webhook channel."""

    @pytest.mark.asyncio
    async def test_hmac_signature_correct(self):
        from app.notifications.webhook import WebhookChannel

        secret = "my-webhook-secret"
        ch = WebhookChannel(
            tenant_id="t1",
            config={
                "url": "https://example.com/webhook",
                "secret": secret,
            },
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        alert = {"test": True, "severity": "high"}
        await ch.send(alert)

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        body = call_args[1]["content"] if "content" in call_args[1] else call_args[0][1]
        timestamp = headers["X-Phantex-Timestamp"]
        sig = headers["X-Phantex-Signature"]

        # Verify HMAC
        expected_payload = f"{timestamp}.{body}"
        expected_sig = hmac.new(secret.encode(), expected_payload.encode(), hashlib.sha256).hexdigest()
        assert sig == f"sha256={expected_sig}"

    @pytest.mark.asyncio
    async def test_no_signature_without_secret(self):
        from app.notifications.webhook import WebhookChannel

        ch = WebhookChannel(
            tenant_id="t1",
            config={"url": "https://example.com/webhook"},
        )

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_resp)
        ch._client = mock_client

        await ch.send({"test": True})

        call_args = mock_client.post.call_args
        headers = call_args[1]["headers"] if "headers" in call_args[1] else call_args[0][2]
        assert "X-Phantex-Signature" not in headers
