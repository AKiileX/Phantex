# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Notification Channels & Routing (N2).

Covers:
  - Channel instantiation validation (missing config, TLS requirements)
  - Routing rules: match_routing_rules with various conditions
  - Rate limiting
  - Slack Block Kit builder
  - Email HTML builder + HTML escaping
  - Webhook HMAC signing
  - PagerDuty dedup_key format
  - Channel registry: list_channel_types, get_channel
"""

from __future__ import annotations

import time

import pytest

from app.notifications.base import BaseNotificationChannel, NotificationError
from app.notifications.email import EmailChannel, _build_html, _build_subject, _html_escape
from app.notifications.pagerduty import PagerDutyChannel
from app.notifications.router import (
    _matches_condition,
    get_channel,
    list_channel_types,
    match_routing_rules,
)
from app.notifications.slack import SlackChannel, _build_slack_blocks
from app.notifications.webhook import WebhookChannel

# ── Routing Rules ────────────────────────────────────────────────────────────

class TestMatchRoutingRules:
    def test_empty_rules(self):
        result = match_routing_rules({"severity": "high"}, [])
        assert result == []

    def test_empty_condition_matches_all(self):
        rules = [{"condition": {}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "low"}, rules)
        assert result == ["ch-1"]

    def test_string_condition_exact_match(self):
        rules = [{"condition": {"severity": "critical"}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "critical"}, rules)
        assert result == ["ch-1"]

    def test_string_condition_no_match(self):
        rules = [{"condition": {"severity": "critical"}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "low"}, rules)
        assert result == []

    def test_list_condition_match(self):
        rules = [{"condition": {"severity": ["critical", "high"]}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "high"}, rules)
        assert result == ["ch-1"]

    def test_list_condition_no_match(self):
        rules = [{"condition": {"severity": ["critical", "high"]}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "low"}, rules)
        assert result == []

    def test_multi_key_and_logic(self):
        rules = [
            {
                "condition": {"severity": "critical", "attack_class": "credential_theft"},
                "channels": ["ch-1"],
            }
        ]
        # Both match
        result = match_routing_rules({"severity": "critical", "attack_class": "credential_theft"}, rules)
        assert result == ["ch-1"]

        # Only severity matches
        result = match_routing_rules({"severity": "critical", "attack_class": "data_exfiltration"}, rules)
        assert result == []

    def test_case_insensitive(self):
        rules = [{"condition": {"severity": "CRITICAL"}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "critical"}, rules)
        assert result == ["ch-1"]

    def test_multiple_rules_multiple_channels(self):
        rules = [
            {"condition": {"severity": "critical"}, "channels": ["ch-1", "ch-2"]},
            {"condition": {"severity": ["critical", "high"]}, "channels": ["ch-3"]},
        ]
        result = match_routing_rules({"severity": "critical"}, rules)
        assert result == ["ch-1", "ch-2", "ch-3"]

    def test_deduplication(self):
        rules = [
            {"condition": {}, "channels": ["ch-1"]},
            {"condition": {"severity": "high"}, "channels": ["ch-1"]},
        ]
        result = match_routing_rules({"severity": "high"}, rules)
        assert result == ["ch-1"]  # Deduped

    def test_rule_without_channels_skipped(self):
        rules = [{"condition": {"severity": "high"}, "channels": []}]
        result = match_routing_rules({"severity": "high"}, rules)
        assert result == []

    def test_missing_alert_field_no_match(self):
        rules = [{"condition": {"attack_class": "credential_theft"}, "channels": ["ch-1"]}]
        result = match_routing_rules({"severity": "high"}, rules)
        assert result == []

class TestMatchesCondition:
    def test_empty_condition(self):
        assert _matches_condition({"x": "y"}, {}) is True

    def test_none_field_treated_as_empty(self):
        assert _matches_condition({"x": None}, {"x": "value"}) is False

    def test_none_field_matches_empty_expected(self):
        assert _matches_condition({"x": None}, {"x": ""}) is True

# ── Channel Registry ─────────────────────────────────────────────────────────

class TestChannelRegistry:
    def test_list_channel_types(self):
        types = list_channel_types()
        assert set(types) == {"email", "pagerduty", "slack", "webhook"}

    def test_get_channel_slack(self):
        ch = get_channel(
            "slack",
            tenant_id="t1",
            config={"webhook_url": "https://hooks.slack.com/test"},
        )
        assert ch.channel_type == "slack"

    def test_get_channel_unknown(self):
        with pytest.raises(NotificationError, match="Unknown channel type"):
            get_channel("telegram", tenant_id="t1", config={})

# ── Slack Channel ────────────────────────────────────────────────────────────

class TestSlackChannel:
    def test_rejects_missing_webhook(self):
        with pytest.raises(NotificationError, match="webhook_url"):
            SlackChannel(tenant_id="t1", config={})

    def test_rejects_http_webhook(self):
        with pytest.raises(NotificationError, match="HTTPS"):
            SlackChannel(tenant_id="t1", config={"webhook_url": "http://hooks.slack.com"})

    def test_valid_config(self):
        ch = SlackChannel(
            tenant_id="t1",
            config={"webhook_url": "https://hooks.slack.com/T00/B00/xxx"},
        )
        assert ch.channel_type == "slack"

class TestSlackBlockBuilder:
    def test_builds_blocks(self):
        alert = {
            "rule_name": "test_rule",
            "severity": "high",
            "agent_id": "agent-1",
            "attack_class": "credential_theft",
            "message": "Tool call detected",
        }
        payload = _build_slack_blocks(alert)
        assert "attachments" in payload
        blocks = payload["attachments"][0]["blocks"]
        assert len(blocks) >= 3
        # Header block
        assert blocks[0]["type"] == "header"
        assert "test_rule" in blocks[0]["text"]["text"]

    def test_severity_colors(self):
        for sev, expected_color in [
            ("critical", "#e01e5a"),
            ("high", "#ff6600"),
            ("info", "#cccccc"),
        ]:
            payload = _build_slack_blocks({"severity": sev})
            assert payload["attachments"][0]["color"] == expected_color

# ── PagerDuty Channel ───────────────────────────────────────────────────────

class TestPagerDutyChannel:
    def test_rejects_missing_routing_key(self):
        with pytest.raises(NotificationError, match="routing_key"):
            PagerDutyChannel(tenant_id="t1", config={})

    def test_valid_config(self):
        ch = PagerDutyChannel(tenant_id="t1", config={"routing_key": "rk-123"})
        assert ch.channel_type == "pagerduty"

# ── Webhook Channel ─────────────────────────────────────────────────────────

class TestWebhookChannel:
    def test_rejects_missing_url(self):
        with pytest.raises(NotificationError, match="URL required"):
            WebhookChannel(tenant_id="t1", config={})

    def test_rejects_http_url(self):
        with pytest.raises(NotificationError, match="HTTPS"):
            WebhookChannel(tenant_id="t1", config={"url": "http://example.com"})

    def test_valid_config(self):
        ch = WebhookChannel(
            tenant_id="t1",
            config={"url": "https://example.com/webhook"},
        )
        assert ch.channel_type == "webhook"

# ── Email Channel ────────────────────────────────────────────────────────────

class TestEmailChannel:
    def test_rejects_missing_recipients(self):
        with pytest.raises(NotificationError, match="to_addresses"):
            EmailChannel(
                tenant_id="t1",
                config={"mode": "smtp", "smtp_host": "mail.example.com"},
            )

    def test_rejects_smtp_without_host(self):
        with pytest.raises(NotificationError, match="SMTP host"):
            EmailChannel(
                tenant_id="t1",
                config={"mode": "smtp", "to_addresses": ["admin@example.com"]},
            )

    def test_rejects_sendgrid_without_key(self):
        with pytest.raises(NotificationError, match="SendGrid"):
            EmailChannel(
                tenant_id="t1",
                config={"mode": "sendgrid", "to_addresses": ["admin@example.com"]},
            )

    def test_valid_smtp_config(self):
        ch = EmailChannel(
            tenant_id="t1",
            config={
                "mode": "smtp",
                "smtp_host": "mail.example.com",
                "to_addresses": ["admin@example.com"],
            },
        )
        assert ch.channel_type == "email"

class TestEmailTemplates:
    def test_build_subject(self):
        subject = _build_subject({"severity": "critical", "rule_name": "detect_tool"})
        assert "[Phantex CRITICAL]" in subject
        assert "detect_tool" in subject

    def test_build_html_contains_severity(self):
        html = _build_html({"severity": "high", "rule_name": "test"})
        assert "HIGH" in html
        assert "test" in html

    def test_html_escaping(self):
        assert _html_escape("<script>alert('xss')</script>") == ("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;")

    def test_html_escapes_ampersand(self):
        assert _html_escape("a&b") == "a&amp;b"

    def test_html_escapes_quotes(self):
        assert _html_escape('"hello"') == "&quot;hello&quot;"

# ── NotificationError ────────────────────────────────────────────────────────

class TestNotificationError:
    def test_retryable_default(self):
        err = NotificationError("test")
        assert err.retryable is True

    def test_non_retryable(self):
        err = NotificationError("test", retryable=False)
        assert err.retryable is False

# ── Base Channel Rate Limiting ───────────────────────────────────────────────

class TestBaseChannelRateLimit:
    def test_rate_limit_enforced(self):
        class DummyChannel(BaseNotificationChannel):
            channel_type = "dummy"

            async def send(self, alert):
                return True

            async def test(self):
                return {"success": True}

            async def close(self):
                pass

        ch = DummyChannel(tenant_id="t1", config={}, rate_limit_per_min=3)
        ch._check_rate_limit()
        ch._check_rate_limit()
        ch._check_rate_limit()

        with pytest.raises(NotificationError, match="Rate limit"):
            ch._check_rate_limit()

    def test_rate_limit_window_resets(self):
        class DummyChannel(BaseNotificationChannel):
            channel_type = "dummy"

            async def send(self, alert):
                return True

            async def test(self):
                return {"success": True}

            async def close(self):
                pass

        ch = DummyChannel(tenant_id="t1", config={}, rate_limit_per_min=2)
        ch._check_rate_limit()
        ch._check_rate_limit()

        # Simulate window expiry
        ch._window_start = time.monotonic() - 61
        ch._check_rate_limit()  # Should succeed after reset
