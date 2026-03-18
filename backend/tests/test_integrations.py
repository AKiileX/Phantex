# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for SIEM Integrations (N1).

Covers:
  - CEF formatter: header sanitization, extension escaping, severity mapping
  - Splunk HEC formatter
  - Elastic NDJSON formatter
  - Azure Sentinel formatter
  - LogScale formatter
  - Base class: rate limiting, TLS enforcement, credential masking
  - Registry: platform registration, factory, list_platforms
  - Adapter instantiation validation (missing config, plain HTTP)
"""

from __future__ import annotations

import json
import time

import pytest

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import (
    _base_event,
    _sanitize_cef_ext,
    _sanitize_cef_header,
    to_azure_sentinel,
    to_azure_sentinel_batch,
    to_cef,
    to_cef_batch,
    to_elastic_ndjson,
    to_logscale,
    to_splunk_hec,
    to_splunk_hec_batch,
)
from app.integrations.registry import (
    _REGISTRY,
    get_integration,
    list_platforms,
)

# ── CEF Header Sanitization ─────────────────────────────────────────────────

class TestCEFSanitization:
    def test_header_removes_pipes(self):
        assert "|" not in _sanitize_cef_header("rule|with|pipes")

    def test_header_removes_backslash(self):
        assert "\\" not in _sanitize_cef_header("rule\\with\\backslash")

    def test_header_truncates_at_63(self):
        long = "x" * 100
        assert len(_sanitize_cef_header(long)) == 63

    def test_header_preserves_safe_chars(self):
        assert _sanitize_cef_header("safe_rule-name_123") == "safe_rule-name_123"

    def test_ext_escapes_equals(self):
        result = _sanitize_cef_ext("key=value")
        assert "=" not in result

    def test_ext_escapes_newline(self):
        result = _sanitize_cef_ext("line1\nline2")
        assert "\n" not in result

    def test_ext_escapes_carriage_return(self):
        result = _sanitize_cef_ext("line1\rline2")
        assert "\r" not in result

    def test_ext_truncates_at_1024(self):
        long = "x" * 2000
        assert len(_sanitize_cef_ext(long)) == 1024

# ── CEF Formatter ────────────────────────────────────────────────────────────

class TestCEFFormatter:
    def test_basic_format(self):
        event = {"rule_name": "test_rule", "severity": "high", "agent_id": "agent-1"}
        result = to_cef(event)
        assert result.startswith("CEF:0|Phantex|Phantex|1.0|")
        assert "8|" in result  # high → CEF severity 8

    def test_severity_mapping(self):
        for sev, expected in [("critical", "10"), ("high", "8"), ("medium", "5"), ("low", "3"), ("info", "1")]:
            result = to_cef({"severity": sev, "rule_name": "test"})
            # severity number should appear in the CEF string
            parts = result.split("|")
            assert parts[6] == expected, f"severity={sev} should map to {expected}"

    def test_extension_fields(self):
        event = {
            "rule_name": "test",
            "severity": "medium",
            "agent_id": "agent-1",
            "tenant_id": "tenant-1",
            "dest_ip": "10.0.0.1",
            "dest_port": 443,
        }
        result = to_cef(event)
        assert "cs1Label=agent_id" in result
        assert "cs2Label=tenant_id" in result
        assert "dst=10.0.0.1" in result
        assert "dpt=443" in result

    def test_pipe_injection_in_rule_name(self):
        event = {"rule_name": "evil|rule|name", "severity": "high"}
        result = to_cef(event)
        # Pipe in header field should be removed
        parts = result.split("|")
        # After CEF:0, Vendor, Product, Version, there's SignatureID
        assert "evil" in parts[4]
        assert "evilrulename" in parts[4]  # pipes stripped

    def test_batch(self):
        events = [
            {"rule_name": "r1", "severity": "high"},
            {"rule_name": "r2", "severity": "low"},
        ]
        result = to_cef_batch(events)
        assert len(result) == 2
        assert all(r.startswith("CEF:0|") for r in result)

# ── Splunk HEC Formatter ────────────────────────────────────────────────────

class TestSplunkFormatter:
    def test_single_event(self):
        event = {"event_id": "e1", "severity": "high", "rule_name": "test"}
        result = to_splunk_hec(event)
        assert result["sourcetype"] == "phantex:alert"
        assert result["source"] == "phantex-backend"
        assert "event" in result
        assert result["event"]["severity"] == "high"

    def test_batch_ndjson(self):
        events = [
            {"event_id": "e1", "severity": "high"},
            {"event_id": "e2", "severity": "low"},
        ]
        result = to_splunk_hec_batch(events)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "event" in parsed

# ── Azure Sentinel Formatter ────────────────────────────────────────────────

class TestAzureSentinelFormatter:
    def test_single_event(self):
        event = {"event_id": "e1", "timestamp": "2025-01-15T10:00:00Z"}
        result = to_azure_sentinel(event)
        assert result["TimeGenerated"] == "2025-01-15T10:00:00Z"
        assert "event_id" in result

    def test_batch_is_json_array(self):
        events = [
            {"event_id": "e1", "timestamp": "t1"},
            {"event_id": "e2", "timestamp": "t2"},
        ]
        result = to_azure_sentinel_batch(events)
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

# ── Elastic NDJSON Formatter ────────────────────────────────────────────────

class TestElasticFormatter:
    def test_ndjson_format(self):
        events = [{"event_id": "e1", "timestamp": "2025-01-15T10:00:00Z"}]
        result = to_elastic_ndjson(events)
        lines = result.strip().split("\n")
        # Each event = 2 lines (action + document)
        assert len(lines) == 2
        action = json.loads(lines[0])
        assert "index" in action

    def test_custom_index(self):
        events = [{"event_id": "e1"}]
        result = to_elastic_ndjson(events, index="custom-idx")
        first_line = json.loads(result.strip().split("\n")[0])
        assert first_line["index"]["_index"] == "custom-idx"

# ── LogScale Formatter ──────────────────────────────────────────────────────

class TestLogScaleFormatter:
    def test_format(self):
        events = [{"event_id": "e1", "severity": "high"}]
        result = to_logscale(events)
        assert len(result) == 1
        assert result[0]["tags"]["source"] == "phantex"
        assert len(result[0]["events"]) == 1
        assert "attributes" in result[0]["events"][0]

    def test_multiple_events(self):
        events = [
            {"event_id": "e1"},
            {"event_id": "e2"},
        ]
        result = to_logscale(events)
        assert len(result[0]["events"]) == 2

# ── Base Event Extractor ────────────────────────────────────────────────────

class TestBaseEvent:
    def test_extracts_all_fields(self):
        event = {
            "event_id": "e1",
            "alert_id": "a1",
            "tenant_id": "t1",
            "agent_id": "ag1",
            "agent_name": "my-agent",
            "rule_name": "detect_tool",
            "severity": "high",
            "attack_class": "credential_theft",
            "framework": "langchain",
            "timestamp": "2025-01-15T10:00:00Z",
            "message": "Tool call detected",
            "dest_ip": "10.0.0.1",
            "dest_port": 443,
            "file_path": "/etc/passwd",
            "tool_name": "exec_shell",
        }
        result = _base_event(event)
        for key in event:
            assert key in result

    def test_missing_fields_default_to_empty(self):
        result = _base_event({})
        assert result["event_id"] == ""
        assert result["severity"] == "info"
        assert result["dest_port"] is None

    def test_rule_name_fallback_to_event_type(self):
        result = _base_event({"event_type": "TOOL_CALL"})
        assert result["rule_name"] == "TOOL_CALL"

# ── BaseSIEMIntegration ─────────────────────────────────────────────────────

class TestBaseSIEMIntegration:
    def test_tls_enforcement_rejects_http(self):
        with pytest.raises(IntegrationError, match="TLS required"):
            BaseSIEMIntegration._require_https("http://example.com/api")

    def test_tls_enforcement_accepts_https(self):
        # Should not raise
        BaseSIEMIntegration._require_https("https://example.com/api")

    def test_tls_enforcement_empty_url(self):
        # Empty URL must now be rejected (F2 fix)
        with pytest.raises(IntegrationError, match="TLS required"):
            BaseSIEMIntegration._require_https("")

    def test_credential_masking(self):
        assert BaseSIEMIntegration._mask_credential("abcdef12345") == "abcd***"
        assert BaseSIEMIntegration._mask_credential("ab") == "***"
        assert BaseSIEMIntegration._mask_credential("") == "***"

    def test_rate_limiting(self):
        """Create a concrete subclass to test rate limiting."""

        class DummyIntegration(BaseSIEMIntegration):
            platform_name = "dummy"

            async def send_batch(self, events):
                return len(events)

            async def test_connection(self):
                return {"success": True}

            async def close(self):
                pass

        adapter = DummyIntegration(
            tenant_id="t1",
            config={},
            rate_limit_per_min=10,
        )

        # Should succeed within limit
        adapter._check_rate_limit(5)
        adapter._check_rate_limit(5)

        # Should fail at 11
        with pytest.raises(IntegrationError, match="Rate limit"):
            adapter._check_rate_limit(1)

    def test_rate_limit_window_reset(self):
        class DummyIntegration(BaseSIEMIntegration):
            platform_name = "dummy"

            async def send_batch(self, events):
                return 0

            async def test_connection(self):
                return {"success": True}

            async def close(self):
                pass

        adapter = DummyIntegration(tenant_id="t1", config={}, rate_limit_per_min=5)
        adapter._check_rate_limit(5)

        # Simulate window expiry
        adapter._window_start = time.monotonic() - 61
        # Should succeed after reset
        adapter._check_rate_limit(5)

# ── IntegrationError ─────────────────────────────────────────────────────────

class TestIntegrationError:
    def test_retryable_default(self):
        err = IntegrationError("test")
        assert err.retryable is True

    def test_non_retryable(self):
        err = IntegrationError("test", retryable=False)
        assert err.retryable is False

    def test_message(self):
        err = IntegrationError("something broke")
        assert str(err) == "something broke"

# ── Registry ─────────────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_p0_registered(self):
        expected = {"splunk_hec", "azure_sentinel", "elastic_siem", "crowdstrike_logscale", "syslog_cef"}
        assert expected.issubset(set(_REGISTRY.keys()))

    def test_get_integration_valid(self):
        adapter = get_integration(
            "splunk_hec",
            tenant_id="t1",
            config={"endpoint": "https://splunk.example.com", "hec_token": "tok123"},
        )
        assert adapter.platform_name == "splunk_hec"

    def test_get_integration_unknown(self):
        with pytest.raises(IntegrationError, match="Unknown integration platform"):
            get_integration("nonexistent_platform", tenant_id="t1", config={})

    def test_list_platforms(self):
        platforms = list_platforms()
        assert len(platforms) >= 5
        names = [p["platform"] for p in platforms]
        assert "splunk_hec" in names
        assert "syslog_cef" in names
        for p in platforms:
            assert "max_batch_size" in p
            assert "default_rate_limit" in p

# ── Splunk HEC Adapter Validation ────────────────────────────────────────────

class TestSplunkHECAdapter:
    def test_rejects_http_endpoint(self):
        with pytest.raises(IntegrationError, match="TLS required"):
            get_integration(
                "splunk_hec",
                tenant_id="t1",
                config={"endpoint": "http://splunk.local", "hec_token": "tok"},
            )

    def test_rejects_missing_token(self):
        with pytest.raises(IntegrationError, match="token"):
            get_integration(
                "splunk_hec",
                tenant_id="t1",
                config={"endpoint": "https://splunk.local"},
            )

    def test_valid_config(self):
        adapter = get_integration(
            "splunk_hec",
            tenant_id="t1",
            config={"endpoint": "https://splunk.example.com:8088", "hec_token": "tok123"},
        )
        assert adapter.platform_name == "splunk_hec"

# ── Syslog CEF Adapter Validation ───────────────────────────────────────────

class TestSyslogCEFAdapter:
    def test_rejects_missing_host(self):
        with pytest.raises(IntegrationError, match="host"):
            get_integration("syslog_cef", tenant_id="t1", config={})

    def test_rejects_invalid_protocol(self):
        with pytest.raises(IntegrationError, match="protocol"):
            get_integration(
                "syslog_cef",
                tenant_id="t1",
                config={"host": "syslog.local", "protocol": "websocket"},
            )

    def test_tcp_valid(self):
        adapter = get_integration(
            "syslog_cef",
            tenant_id="t1",
            config={"host": "syslog.local", "protocol": "tcp"},
        )
        assert adapter.platform_name == "syslog_cef"

    def test_udp_valid(self):
        adapter = get_integration(
            "syslog_cef",
            tenant_id="t1",
            config={"host": "syslog.local", "protocol": "udp"},
        )
        assert adapter.platform_name == "syslog_cef"

# ── Elastic SIEM Adapter Validation ─────────────────────────────────────────

class TestElasticSIEMAdapter:
    def test_rejects_http_endpoint(self):
        with pytest.raises(IntegrationError, match="TLS required"):
            get_integration(
                "elastic_siem",
                tenant_id="t1",
                config={"endpoint": "http://elastic.local", "api_key_id": "id1", "api_key_secret": "sec1"},
            )

    def test_rejects_missing_api_key(self):
        with pytest.raises(IntegrationError, match="api_key_id"):
            get_integration(
                "elastic_siem",
                tenant_id="t1",
                config={"endpoint": "https://elastic.example.com"},
            )

    def test_valid_config(self):
        adapter = get_integration(
            "elastic_siem",
            tenant_id="t1",
            config={"endpoint": "https://elastic.example.com", "api_key_id": "id1", "api_key_secret": "sec1"},
        )
        assert adapter.platform_name == "elastic_siem"

# ── CrowdStrike LogScale Adapter ────────────────────────────────────────────

class TestCrowdStrikeAdapter:
    def test_rejects_http_endpoint(self):
        with pytest.raises(IntegrationError, match="TLS required"):
            get_integration(
                "crowdstrike_logscale",
                tenant_id="t1",
                config={"endpoint": "http://logscale.local", "ingest_token": "tok1"},
            )

    def test_rejects_missing_token(self):
        with pytest.raises(IntegrationError, match="ingest_token"):
            get_integration(
                "crowdstrike_logscale",
                tenant_id="t1",
                config={"endpoint": "https://logscale.example.com"},
            )

    def test_valid(self):
        adapter = get_integration(
            "crowdstrike_logscale",
            tenant_id="t1",
            config={"endpoint": "https://logscale.example.com", "ingest_token": "tok1"},
        )
        assert adapter.platform_name == "crowdstrike_logscale"
