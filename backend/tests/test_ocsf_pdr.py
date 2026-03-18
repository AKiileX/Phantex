# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for L3 — OCSF Schema Mapping + PDR Export.

Covers:
  - OCSF Mapper: all 6 event types + alert, PII redaction, batch, JSON-L,
    validation, edge cases (missing fields, bad types, ATLAS enrichment)
  - PDR Service: webhook HMAC signing, S3 key paths, channel factory,
    export error handling, retry logic
  - PDR Consumer: topic parsing, channel cache, DLQ routing
  - Exports Router: CRUD schema validation, HTTPS enforcement, config masking
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ocsf_mapper import (
    _build_api,
    _build_dns,
    _build_dst_endpoint,
    _build_file,
    _build_finding,
    _build_message,
    _build_process,
    _build_src_endpoint,
    _normalise_event_type,
    _severity_id,
    _to_iso,
    get_supported_event_types,
    map_alert,
    map_batch,
    map_event,
    redact_pii,
    to_jsonl,
    validate_ocsf_event,
)
from app.services.pdr_service import (
    ExportError,
    KafkaMirrorChannel,
    S3ExportChannel,
    WebhookExportChannel,
    create_channel,
)

# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def process_event() -> dict[str, Any]:
    return {
        "id": "evt-001",
        "event_type": "PROCESS_EXEC",
        "timestamp": "2025-01-15T10:30:00Z",
        "agent_id": "agent-a1",
        "sensor_id": "sensor-s1",
        "severity": "medium",
        "raw_data": {
            "pid": 1234,
            "comm": "python3",
            "cmdline": "python3 -m train",
        },
    }

@pytest.fixture
def file_event() -> dict[str, Any]:
    return {
        "id": "evt-002",
        "event_type": "FILE_OPEN",
        "timestamp": "2025-01-15T10:31:00Z",
        "agent_id": "agent-a1",
        "severity": "low",
        "raw_data": {
            "path": "/data/model.pt",
            "file_name": "model.pt",
            "bytes_read": 4096,
        },
    }

@pytest.fixture
def network_event() -> dict[str, Any]:
    return {
        "id": "evt-003",
        "event_type": "NETWORK_CONNECT",
        "timestamp": "2025-01-15T10:32:00Z",
        "agent_id": "agent-a2",
        "severity": "high",
        "raw_data": {
            "src_ip": "10.0.0.1",
            "src_port": 9999,
            "dst_ip": "192.168.1.100",
            "dst_port": 443,
            "domain": "api.example.com",
        },
    }

@pytest.fixture
def tool_call_event() -> dict[str, Any]:
    return {
        "id": "evt-004",
        "event_type": "TOOL_CALL",
        "timestamp": "2025-01-15T10:33:00Z",
        "agent_id": "agent-a3",
        "severity": "info",
        "raw_data": {
            "tool_name": "read_file",
            "mcp_server": "fs-server",
            "input": {"path": "/etc/passwd"},
            "output": {"content": "root:x:0:0:..."},
        },
    }

@pytest.fixture
def dns_event() -> dict[str, Any]:
    return {
        "id": "evt-005",
        "event_type": "DNS_QUERY",
        "timestamp": "2025-01-15T10:34:00Z",
        "agent_id": "agent-a1",
        "severity": "info",
        "raw_data": {
            "query": "evil.example.com",
            "query_type": "A",
            "answers": ["1.2.3.4", "5.6.7.8"],
        },
    }

@pytest.fixture
def alert_event() -> dict[str, Any]:
    return {
        "id": "alert-001",
        "event_type": "alert",
        "timestamp": "2025-01-15T10:35:00Z",
        "title": "Prompt Injection Detected",
        "description": "Agent received a prompt with embedded injection payload",
        "severity": "critical",
        "status": "open",
        "agent_id": "agent-a3",
        "rule_id": "rule-42",
        "attack_class": "prompt_injection",
        "context": {
            "attack_class": "prompt_injection",
        },
        "atlas_techniques": [
            {"id": "AML.T0051", "name": "LLM Prompt Injection"},
        ],
    }

@pytest.fixture
def tenant_id() -> str:
    return "00000000-0000-0000-0000-000000000001"

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Event Type Normalisation
# ══════════════════════════════════════════════════════════════════════════════

class TestEventTypeNormalisation:
    def test_uppercase_process_exec(self):
        assert _normalise_event_type({"event_type": "PROCESS_EXEC"}) == "PROCESS_EXEC"

    def test_lowercase_normalised(self):
        assert _normalise_event_type({"event_type": "process_exec"}) == "PROCESS_EXEC"

    def test_alert_prefix(self):
        assert _normalise_event_type({"event_type": "alert:open"}) == "alert"

    def test_alert_prefix_resolved(self):
        assert _normalise_event_type({"event_type": "alert:resolved"}) == "alert"

    def test_plain_alert(self):
        assert _normalise_event_type({"event_type": "alert"}) == "ALERT"

    def test_detect_alert_by_fields(self):
        assert _normalise_event_type({"event_type": "", "title": "X", "status": "open"}) == "alert"

    def test_file_open(self):
        assert _normalise_event_type({"event_type": "file_open"}) == "FILE_OPEN"

    def test_network_connect(self):
        assert _normalise_event_type({"event_type": "network_connect"}) == "NETWORK_CONNECT"

    def test_tool_call(self):
        assert _normalise_event_type({"event_type": "TOOL_CALL"}) == "TOOL_CALL"

    def test_dns_query(self):
        assert _normalise_event_type({"event_type": "dns_query"}) == "DNS_QUERY"

    def test_unknown_type(self):
        assert _normalise_event_type({"event_type": "CUSTOM_THING"}) == "CUSTOM_THING"

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Core Mapping (all 6 event types + alert)
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessEventMapping:
    def test_class_uid(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 1007

    def test_class_name(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.class_name == "Process Activity"

    def test_process_populated(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.process is not None
        assert ocsf.process.pid == 1234
        assert ocsf.process.name == "python3"
        assert ocsf.process.cmd_line == "python3 -m train"

    def test_severity_mapping(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.severity_id == 3  # medium
        assert ocsf.severity == "Medium"

    def test_metadata_tenant(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.metadata.tenant_uid == tenant_id

    def test_metadata_uid(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.metadata.uid == "evt-001"

    def test_actor_populated(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.actor is not None

    def test_unmapped_extensions(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert ocsf.unmapped["agent_id"] == "agent-a1"
        assert ocsf.unmapped["sensor_id"] == "sensor-s1"

    def test_time_field(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        assert "2025-01-15" in ocsf.time

class TestFileEventMapping:
    def test_class_uid(self, file_event, tenant_id):
        ocsf = map_event(file_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 1001

    def test_file_populated(self, file_event, tenant_id):
        ocsf = map_event(file_event, tenant_id=tenant_id)
        assert ocsf.file is not None
        assert ocsf.file.path == "/data/model.pt"
        assert ocsf.file.name == "model.pt"

    def test_severity_low(self, file_event, tenant_id):
        ocsf = map_event(file_event, tenant_id=tenant_id)
        assert ocsf.severity_id == 2  # low
        assert ocsf.severity == "Low"

class TestNetworkEventMapping:
    def test_class_uid(self, network_event, tenant_id):
        ocsf = map_event(network_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 4001

    def test_src_endpoint(self, network_event, tenant_id):
        ocsf = map_event(network_event, tenant_id=tenant_id)
        assert ocsf.src_endpoint is not None
        assert ocsf.src_endpoint.ip == "10.0.0.1"
        assert ocsf.src_endpoint.port == 9999

    def test_dst_endpoint(self, network_event, tenant_id):
        ocsf = map_event(network_event, tenant_id=tenant_id)
        assert ocsf.dst_endpoint is not None
        assert ocsf.dst_endpoint.ip == "192.168.1.100"
        assert ocsf.dst_endpoint.port == 443
        assert ocsf.dst_endpoint.domain == "api.example.com"

    def test_severity_high(self, network_event, tenant_id):
        ocsf = map_event(network_event, tenant_id=tenant_id)
        assert ocsf.severity_id == 4

class TestToolCallEventMapping:
    def test_class_uid(self, tool_call_event, tenant_id):
        ocsf = map_event(tool_call_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 6003

    def test_api_populated(self, tool_call_event, tenant_id):
        ocsf = map_event(tool_call_event, tenant_id=tenant_id)
        assert ocsf.api is not None
        assert ocsf.api.operation == "read_file"

    def test_api_service(self, tool_call_event, tenant_id):
        ocsf = map_event(tool_call_event, tenant_id=tenant_id)
        assert ocsf.api.service is not None
        assert ocsf.api.service["name"] == "fs-server"

    def test_severity_info(self, tool_call_event, tenant_id):
        ocsf = map_event(tool_call_event, tenant_id=tenant_id)
        assert ocsf.severity_id == 1

class TestDNSEventMapping:
    def test_class_uid(self, dns_event, tenant_id):
        ocsf = map_event(dns_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 4003

    def test_dns_populated(self, dns_event, tenant_id):
        ocsf = map_event(dns_event, tenant_id=tenant_id)
        assert ocsf.dns is not None
        assert ocsf.dns.query is not None
        assert ocsf.dns.query["hostname"] == "evil.example.com"

    def test_dns_answers(self, dns_event, tenant_id):
        ocsf = map_event(dns_event, tenant_id=tenant_id)
        assert len(ocsf.dns.answers) == 2

class TestAlertMapping:
    def test_class_uid(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 2001

    def test_finding_info(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert ocsf.finding_info is not None
        assert ocsf.finding_info.title == "Prompt Injection Detected"

    def test_status_id(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert ocsf.status_id is not None

    def test_severity_critical(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert ocsf.severity_id == 5
        assert ocsf.severity == "Critical"

    def test_atlas_enrichments(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert ocsf.enrichments is not None
        assert len(ocsf.enrichments) == 1
        assert ocsf.enrichments[0]["name"] == "AML.T0051"
        assert ocsf.enrichments[0]["provider"] == "MITRE ATLAS"

    def test_finding_types(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert "prompt_injection" in ocsf.finding_info.types
        assert any("AML.T0051" in t for t in ocsf.finding_info.types)

    def test_map_alert_shorthand(self, alert_event, tenant_id):
        ocsf = map_alert(alert_event, tenant_id=tenant_id)
        assert ocsf.class_uid == 2001

    def test_message_contains_title(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert "Prompt Injection" in ocsf.message

    def test_unmapped_rule_id(self, alert_event, tenant_id):
        ocsf = map_event(alert_event, tenant_id=tenant_id)
        assert ocsf.unmapped.get("rule_id") == "rule-42"

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — PII Redaction
# ══════════════════════════════════════════════════════════════════════════════

class TestPIIRedaction:
    def test_redact_top_level(self):
        event = {"message": "sensitive", "class_uid": 1007}
        result = redact_pii(event, ["message"])
        assert result["message"] == "***REDACTED***"
        assert result["class_uid"] == 1007  # unchanged

    def test_redact_nested(self):
        event = {"src_endpoint": {"ip": "10.0.0.1", "port": 80}}
        result = redact_pii(event, ["src_endpoint.ip"])
        assert result["src_endpoint"]["ip"] == "***REDACTED***"
        assert result["src_endpoint"]["port"] == 80  # unchanged

    def test_redact_deep_nested(self):
        event = {"actor": {"user": {"email_addr": "test@example.com"}}}
        result = redact_pii(event, ["actor.user.email_addr"])
        assert result["actor"]["user"]["email_addr"] == "***REDACTED***"

    def test_redact_missing_field_no_error(self):
        event = {"class_uid": 1007}
        result = redact_pii(event, ["nonexistent.field"])
        assert result == event

    def test_no_redaction_when_empty(self):
        event = {"class_uid": 1007}
        result = redact_pii(event, None)
        assert result is event  # no copy needed

    def test_original_unchanged(self):
        event = {"src_endpoint": {"ip": "10.0.0.1"}}
        result = redact_pii(event, ["src_endpoint.ip"])
        assert event["src_endpoint"]["ip"] == "10.0.0.1"  # original untouched
        assert result["src_endpoint"]["ip"] == "***REDACTED***"

    def test_multiple_fields(self):
        event = {
            "src_endpoint": {"ip": "10.0.0.1"},
            "dst_endpoint": {"ip": "192.168.1.1"},
        }
        result = redact_pii(event, ["src_endpoint.ip", "dst_endpoint.ip"])
        assert result["src_endpoint"]["ip"] == "***REDACTED***"
        assert result["dst_endpoint"]["ip"] == "***REDACTED***"

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Batch + JSON-L
# ══════════════════════════════════════════════════════════════════════════════

class TestBatchAndJSONL:
    def test_map_batch_returns_dicts(self, process_event, file_event, tenant_id):
        result = map_batch([process_event, file_event], tenant_id=tenant_id)
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)

    def test_map_batch_with_pii(self, process_event, tenant_id):
        result = map_batch(
            [process_event],
            tenant_id=tenant_id,
            pii_fields=["metadata.tenant_uid"],
        )
        assert result[0]["metadata"]["tenant_uid"] == "***REDACTED***"

    def test_map_batch_skips_bad_events(self, tenant_id):
        bad = {"event_type": None}  # Will fail
        good = {"id": "x", "event_type": "PROCESS_EXEC", "raw_data": {"pid": 1}}
        result = map_batch([good, bad], tenant_id=tenant_id)
        # Should get at least the good one
        assert len(result) >= 1

    def test_to_jsonl(self, process_event, tenant_id):
        batch = map_batch([process_event], tenant_id=tenant_id)
        jsonl = to_jsonl(batch)
        lines = jsonl.strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["class_uid"] == 1007

    def test_to_jsonl_multiple(self, process_event, file_event, tenant_id):
        batch = map_batch([process_event, file_event], tenant_id=tenant_id)
        jsonl = to_jsonl(batch)
        lines = jsonl.strip().split("\n")
        assert len(lines) == 2

    def test_empty_batch(self, tenant_id):
        result = map_batch([], tenant_id=tenant_id)
        assert result == []

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestOCSFValidation:
    def test_valid_event_no_errors(self, process_event, tenant_id):
        ocsf = map_event(process_event, tenant_id=tenant_id)
        d = ocsf.model_dump(mode="json", exclude_none=True)
        errors = validate_ocsf_event(d)
        assert len(errors) == 0

    def test_missing_required_field(self):
        d = {"class_uid": 1007}
        errors = validate_ocsf_event(d)
        assert any("Missing" in e for e in errors)

    def test_bad_severity_id(self):
        d = {
            "class_uid": 1007,
            "severity_id": 99,
            "metadata": {},
            "time": "2025-01-01",
            "category_uid": 1,
            "category_name": "Test",
            "activity_id": 1,
            "activity_name": "Test",
            "type_uid": 100701,
            "severity": "Unknown",
        }
        errors = validate_ocsf_event(d)
        assert any("severity_id" in e for e in errors)

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Edge Cases
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_raw_data_as_string(self, tenant_id):
        event = {
            "id": "e1",
            "event_type": "PROCESS_EXEC",
            "raw_data": json.dumps({"pid": 42, "comm": "bash"}),
        }
        ocsf = map_event(event, tenant_id=tenant_id)
        assert ocsf.process is not None
        assert ocsf.process.pid == 42

    def test_numeric_timestamp(self, tenant_id):
        ts = 1705315800  # 2024-01-15 epoch
        event = {
            "id": "e2",
            "event_type": "PROCESS_EXEC",
            "timestamp": ts,
            "raw_data": {},
        }
        ocsf = map_event(event, tenant_id=tenant_id)
        assert "2024" in ocsf.time

    def test_datetime_timestamp(self, tenant_id):
        dt = datetime(2025, 1, 15, 10, 30, tzinfo=UTC)
        event = {
            "id": "e3",
            "event_type": "FILE_OPEN",
            "timestamp": dt,
            "raw_data": {"path": "/tmp/test"},
        }
        ocsf = map_event(event, tenant_id=tenant_id)
        assert "2025-01-15" in ocsf.time

    def test_missing_severity_defaults(self, tenant_id):
        event = {"id": "e4", "event_type": "DNS_QUERY", "raw_data": {}}
        ocsf = map_event(event, tenant_id=tenant_id)
        assert ocsf.severity_id >= 1

    def test_no_tenant_id(self, process_event):
        ocsf = map_event(process_event, tenant_id=None)
        assert ocsf.metadata.tenant_uid is None

    def test_unknown_event_type(self, tenant_id):
        event = {"id": "e5", "event_type": "CUSTOM_THING", "raw_data": {}}
        ocsf = map_event(event, tenant_id=tenant_id)
        assert ocsf.class_uid == 0  # Unmapped

    def test_get_supported_event_types(self):
        types = get_supported_event_types()
        assert "PROCESS_EXEC" in types
        assert "alert" in types

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Severity / Timestamp Helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityMapping:
    def test_info(self):
        assert _severity_id("info") == 1

    def test_low(self):
        assert _severity_id("low") == 2

    def test_medium(self):
        assert _severity_id("medium") == 3

    def test_high(self):
        assert _severity_id("high") == 4

    def test_critical(self):
        assert _severity_id("critical") == 5

    def test_unknown_defaults_1(self):
        assert _severity_id("banana") == 1

    def test_case_insensitive(self):
        assert _severity_id("HIGH") == 4

class TestTimestampConversion:
    def test_string_passthrough(self):
        assert _to_iso("2025-01-15T10:30:00Z") == "2025-01-15T10:30:00Z"

    def test_epoch_float(self):
        result = _to_iso(1705315800.0)
        assert "2024" in result

    def test_epoch_int(self):
        result = _to_iso(1705315800)
        assert "2024" in result

    def test_datetime_object(self):
        dt = datetime(2025, 1, 15, tzinfo=UTC)
        result = _to_iso(dt)
        assert "2025-01-15" in result

    def test_none_returns_now(self):
        result = _to_iso(None)
        assert "20" in result  # year starts with 20

# ══════════════════════════════════════════════════════════════════════════════
# OCSF MAPPER — Field Builders
# ══════════════════════════════════════════════════════════════════════════════

class TestFieldBuilders:
    def test_build_process(self):
        p = _build_process({"pid": 100, "comm": "test", "cmdline": "test -v"})
        assert p.pid == 100
        assert p.name == "test"
        assert p.cmd_line == "test -v"

    def test_build_process_alt_keys(self):
        p = _build_process({"pid": 1, "process_name": "alt", "cmd_line": "alt run"})
        assert p.name == "alt"
        assert p.cmd_line == "alt run"

    def test_build_file(self):
        f = _build_file({"path": "/tmp/model.bin", "size": 1024})
        assert f.path == "/tmp/model.bin"
        assert f.name == "model.bin"
        assert f.size == 1024

    def test_build_file_alt_keys(self):
        f = _build_file({"filename": "/tmp/data.csv"})
        assert f.path == "/tmp/data.csv"
        assert f.name == "data.csv"

    def test_build_src_endpoint(self):
        ep = _build_src_endpoint({"src_ip": "10.0.0.1", "src_port": 8080})
        assert ep.ip == "10.0.0.1"
        assert ep.port == 8080

    def test_build_dst_endpoint(self):
        ep = _build_dst_endpoint({"dst_ip": "1.2.3.4", "dst_port": 443, "domain": "ex.com"})
        assert ep.ip == "1.2.3.4"
        assert ep.port == 443
        assert ep.domain == "ex.com"

    def test_build_api(self):
        api = _build_api({"tool_name": "run", "mcp_server": "srv1", "input": {"k": "v"}})
        assert api.operation == "run"
        assert api.service["name"] == "srv1"

    def test_build_dns(self):
        dns = _build_dns({"query": "test.com", "query_type": "AAAA", "answers": ["::1"]})
        assert dns.query["hostname"] == "test.com"
        assert dns.query["type"] == "AAAA"
        assert len(dns.answers) == 1

    def test_build_finding(self):
        alert = {
            "id": "a1",
            "title": "Bad",
            "description": "Very bad",
            "attack_class": "exfil",
            "atlas_techniques": [{"id": "AML.T0001"}],
        }
        f = _build_finding(alert)
        assert f.title == "Bad"
        assert "exfil" in f.types

    def test_build_message_alert(self):
        m = _build_message({"title": "Test", "description": "Desc"}, "alert")
        assert m == "Test: Desc"

    def test_build_message_alert_no_desc(self):
        m = _build_message({"title": "Test"}, "alert")
        assert m == "Test"

    def test_build_message_event(self):
        m = _build_message({}, "PROCESS_EXEC")
        assert "PROCESS_EXEC" in m

# ══════════════════════════════════════════════════════════════════════════════
# PDR SERVICE — Webhook Channel
# ══════════════════════════════════════════════════════════════════════════════

class TestWebhookChannel:
    def test_init_requires_https(self):
        with pytest.raises(ValueError, match="HTTPS"), patch("app.services.pdr_service._validate_webhook_host"):
            WebhookExportChannel(url="http://example.com/hook")

    def test_init_requires_valid_hostname(self):
        with pytest.raises(ValueError), patch("app.services.pdr_service._validate_webhook_host"):
            WebhookExportChannel(url="https:///no-host")

    def test_init_valid(self):
        with patch("app.services.pdr_service._validate_webhook_host"):
            ch = WebhookExportChannel(url="https://hooks.example.com/pdr", secret="s3cr3t")
        assert ch._url == "https://hooks.example.com/pdr"

    def test_sign_hmac(self):
        with patch("app.services.pdr_service._validate_webhook_host"):
            ch = WebhookExportChannel(url="https://hooks.example.com", secret="test-secret")
        body = '{"class_uid": 1007}'
        timestamp = "1705315800"
        sig = ch._sign(body, timestamp)

        # Verify independently
        expected = hmac.new(
            b"test-secret",
            f"{timestamp}.{body}".encode(),
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected

    @pytest.mark.asyncio
    async def test_export_event_success(self, process_event, tenant_id):
        with patch("app.services.pdr_service._validate_webhook_host"):
            ch = WebhookExportChannel(url="https://hooks.example.com", secret="s3cr3t")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        ch._client = mock_client

        result = await ch.export_event(process_event, tenant_id)
        assert result["delivered"] is True
        assert result["status_code"] == 200

        # Check that signature header was sent
        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "X-Phantex-Signature" in headers
        assert headers["X-Phantex-Signature"].startswith("sha256=")

    @pytest.mark.asyncio
    async def test_export_event_retry_on_failure(self, process_event, tenant_id):
        with patch("app.services.pdr_service._validate_webhook_host"):
            ch = WebhookExportChannel(url="https://hooks.example.com", secret="s3cr3t")
        mock_client = AsyncMock()
        mock_client.is_closed = False

        import httpx

        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("fail"))
        ch._client = mock_client

        with patch("app.services.pdr_service._async_sleep", new_callable=AsyncMock):
            with pytest.raises(ExportError, match="retries"):
                await ch.export_event(process_event, tenant_id)
        assert mock_client.post.call_count == 3  # MAX_RETRIES

    @pytest.mark.asyncio
    async def test_custom_headers_no_override_sig(self, process_event, tenant_id):
        with patch("app.services.pdr_service._validate_webhook_host"):
            ch = WebhookExportChannel(
                url="https://hooks.example.com",
                secret="s3cr3t",
                custom_headers={"X-Custom": "val", "X-Phantex-Signature": "evil"},
            )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.is_closed = False
        ch._client = mock_client

        await ch.export_event(process_event, tenant_id)

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers.get("X-Custom") == "val"
        assert headers["X-Phantex-Signature"] != "evil"

    def test_ssrf_blocks_private_ip(self):
        """SSRF protection: block webhook URLs resolving to private IPs."""
        from app.services.pdr_service import _validate_webhook_host

        # 127.0.0.1 is always loopback
        with (
            patch(
                "socket.getaddrinfo",
                return_value=[
                    (2, 1, 6, "", ("127.0.0.1", 0)),
                ],
            ),
            pytest.raises(ValueError, match="private|internal"),
        ):
            _validate_webhook_host("localhost")

    def test_ssrf_allows_public_ip(self):
        """SSRF protection: allow public IPs."""
        from app.services.pdr_service import _validate_webhook_host

        with patch(
            "socket.getaddrinfo",
            return_value=[
                (2, 1, 6, "", ("93.184.216.34", 0)),
            ],
        ):
            _validate_webhook_host("example.com")  # Should not raise

# ══════════════════════════════════════════════════════════════════════════════
# PDR SERVICE — S3 Channel
# ══════════════════════════════════════════════════════════════════════════════

class TestS3Channel:
    def test_init_requires_bucket(self):
        with pytest.raises(ValueError, match="bucket"):
            S3ExportChannel(bucket="")

    def test_key_generation(self):
        ch = S3ExportChannel(bucket="my-bucket", prefix="phantex/exports", region="eu-west-1")
        ts = datetime(2025, 1, 15, 14, 30, tzinfo=UTC)
        key = ch._build_key("tenant-123", timestamp=ts)
        assert "2025-01-15" in key
        assert "tenant-123" in key
        assert key.endswith(".json.gz")
        assert key.startswith("phantex/exports/")

    def test_key_no_prefix(self):
        ch = S3ExportChannel(bucket="my-bucket")
        ts = datetime(2025, 6, 1, 0, 0, tzinfo=UTC)
        key = ch._build_key("t1", timestamp=ts)
        assert key.startswith("2025-06-01/")

    def test_key_strips_prefix_slashes(self):
        ch = S3ExportChannel(bucket="b", prefix="/exports/")
        ts = datetime(2025, 1, 1, 0, 0, tzinfo=UTC)
        key = ch._build_key("t1", timestamp=ts)
        assert not key.startswith("//")

# ══════════════════════════════════════════════════════════════════════════════
# PDR SERVICE — Kafka Mirror Channel
# ══════════════════════════════════════════════════════════════════════════════

class TestKafkaMirrorChannel:
    def test_init_requires_bootstrap(self):
        with pytest.raises(ValueError, match="bootstrap"):
            KafkaMirrorChannel(bootstrap_servers="", topic="t")

    def test_init_requires_topic(self):
        with pytest.raises(ValueError, match="topic"):
            KafkaMirrorChannel(bootstrap_servers="localhost:9092", topic="")

    def test_init_valid(self):
        ch = KafkaMirrorChannel(
            bootstrap_servers="kafka.internal:9092",
            topic="ocsf-events",
            sasl_mechanism="PLAIN",
            sasl_username="user",
            sasl_password="pass",
        )
        assert ch._topic == "ocsf-events"
        assert ch._sasl_mechanism == "PLAIN"

# ══════════════════════════════════════════════════════════════════════════════
# PDR SERVICE — Channel Factory
# ══════════════════════════════════════════════════════════════════════════════

class TestChannelFactory:
    def test_create_s3(self):
        ch = create_channel("s3", {"s3_bucket": "test-bucket", "s3_region": "us-west-2"})
        assert isinstance(ch, S3ExportChannel)

    def test_create_webhook(self):
        with patch("app.services.pdr_service._validate_webhook_host"):
            ch = create_channel("webhook", {"webhook_url": "https://hooks.example.com"})
        assert isinstance(ch, WebhookExportChannel)

    def test_create_kafka(self):
        ch = create_channel("kafka_mirror", {"kafka_bootstrap": "localhost:9092"})
        assert isinstance(ch, KafkaMirrorChannel)

    def test_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown"):
            create_channel("ftp", {})

# ══════════════════════════════════════════════════════════════════════════════
# PDR CONSUMER — Topic Parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestPDRConsumerTopicParsing:
    def test_events_topic(self):
        from app.consumers.pdr_consumer import _TOPIC_TENANT_RE

        m = _TOPIC_TENANT_RE.match("phantex.events.tenant-abc")
        assert m.group(1) == "tenant-abc"

    def test_alerts_topic(self):
        from app.consumers.pdr_consumer import _TOPIC_TENANT_RE

        m = _TOPIC_TENANT_RE.match("phantex.alerts.tenant-xyz")
        assert m.group(1) == "tenant-xyz"

    def test_no_match(self):
        from app.consumers.pdr_consumer import _TOPIC_TENANT_RE

        assert _TOPIC_TENANT_RE.match("other.topic") is None

    def test_uuid_tenant(self):
        from app.consumers.pdr_consumer import _TOPIC_TENANT_RE

        m = _TOPIC_TENANT_RE.match("phantex.events.00000000-0000-0000-0000-000000000001")
        assert m.group(1) == "00000000-0000-0000-0000-000000000001"

# ══════════════════════════════════════════════════════════════════════════════
# PDR CONSUMER — Lifecycle
# ══════════════════════════════════════════════════════════════════════════════

class TestPDRConsumerLifecycle:
    def test_init_defaults(self):
        from app.consumers.pdr_consumer import PDRExportConsumer

        pool = MagicMock()
        c = PDRExportConsumer(pool)
        assert c._consumer_group == "pdr-export"
        assert c._dlq_topic == "phantex.pdr.dlq"
        assert c.events_consumed == 0

    @pytest.mark.asyncio
    async def test_start_sets_running(self):
        from app.consumers.pdr_consumer import PDRExportConsumer

        pool = MagicMock()
        c = PDRExportConsumer(pool)
        # Patch consume loop to prevent actual Kafka connect
        with patch.object(c, "_consume_loop", new_callable=AsyncMock):
            await c.start()
            assert c._running is True
            await c.stop()

    @pytest.mark.asyncio
    async def test_double_start_noop(self):
        from app.consumers.pdr_consumer import PDRExportConsumer

        pool = MagicMock()
        c = PDRExportConsumer(pool)
        with patch.object(c, "_consume_loop", new_callable=AsyncMock):
            await c.start()
            await c.start()  # should not crash
            assert c._running is True
            await c.stop()

# ══════════════════════════════════════════════════════════════════════════════
# PDR CONSUMER — Channel Cache
# ══════════════════════════════════════════════════════════════════════════════

class TestPDRConsumerCache:
    @pytest.mark.asyncio
    async def test_get_channels_calls_db(self):
        from app.consumers.pdr_consumer import PDRExportConsumer

        pool = AsyncMock()
        pool.fetch = AsyncMock(
            return_value=[
                {
                    "id": "ch1",
                    "channel_type": "webhook",
                    "config": '{"webhook_url":"https://x.com"}',
                    "pii_fields": None,
                },
            ]
        )
        c = PDRExportConsumer(pool)
        channels = await c._get_channels("tenant-1")
        assert len(channels) == 1
        pool.fetch.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        from app.consumers.pdr_consumer import PDRExportConsumer

        pool = AsyncMock()
        pool.fetch = AsyncMock(return_value=[])
        c = PDRExportConsumer(pool)

        await c._get_channels("t1")
        await c._get_channels("t1")  # should hit cache
        assert pool.fetch.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_miss_after_ttl(self):
        from app.consumers.pdr_consumer import PDRExportConsumer

        pool = AsyncMock()
        pool.fetch = AsyncMock(return_value=[])
        c = PDRExportConsumer(pool)
        c._cache_ttl = 0  # Force cache miss

        await c._get_channels("t1")
        await c._get_channels("t1")
        assert pool.fetch.call_count == 2

# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS ROUTER — Schema Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestExportsRouterSchemas:
    def test_valid_channel_types(self):
        from app.routers.exports import PDRChannelCreate

        body = PDRChannelCreate(
            name="test",
            channel_type="s3",
            config={"s3_bucket": "my-bucket"},
        )
        assert body.channel_type == "s3"

    def test_invalid_channel_type(self):
        from app.routers.exports import PDRChannelCreate

        with pytest.raises(Exception):
            PDRChannelCreate(
                name="test",
                channel_type="ftp",
                config={},
            )

    def test_webhook_type(self):
        from app.routers.exports import PDRChannelCreate

        body = PDRChannelCreate(
            name="wh",
            channel_type="webhook",
            config={"webhook_url": "https://hook.example.com"},
        )
        assert body.channel_type == "webhook"

    def test_kafka_mirror_type(self):
        from app.routers.exports import PDRChannelCreate

        body = PDRChannelCreate(
            name="km",
            channel_type="kafka_mirror",
            config={"kafka_bootstrap": "localhost:9092"},
        )
        assert body.channel_type == "kafka_mirror"

# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS ROUTER — Config Masking
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigMasking:
    def test_masks_secret_key(self):
        from app.routers.exports import _mask_config

        config = {"s3_bucket": "my-bucket", "secret_key": "ABCD1234", "s3_region": "us-east-1"}
        masked = _mask_config(config)
        assert masked["secret_key"] == "***"
        assert masked["s3_bucket"] == "my-bucket"
        assert masked["s3_region"] == "us-east-1"

    def test_masks_webhook_secret(self):
        from app.routers.exports import _mask_config

        config = {"webhook_url": "https://x.com", "webhook_secret": "abc123"}
        masked = _mask_config(config)
        assert masked["webhook_secret"] == "***"
        assert masked["webhook_url"] == "https://x.com"

    def test_masks_kafka_password(self):
        from app.routers.exports import _mask_config

        config = {"kafka_bootstrap": "k:9092", "kafka_sasl_password": "p@ss"}
        masked = _mask_config(config)
        assert masked["kafka_sasl_password"] == "***"
        assert masked["kafka_bootstrap"] == "k:9092"

    def test_masks_none_config(self):
        from app.routers.exports import _mask_config

        assert _mask_config(None) == {}

    def test_masks_string_config(self):
        from app.routers.exports import _mask_config

        config_str = json.dumps({"secret_key": "x", "s3_bucket": "b"})
        masked = _mask_config(config_str)
        assert masked["secret_key"] == "***"
        assert masked["s3_bucket"] == "b"

    def test_empty_secret_empty_str(self):
        from app.routers.exports import _mask_config

        config = {"webhook_secret": ""}
        masked = _mask_config(config)
        assert masked["webhook_secret"] == ""

# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS ROUTER — Config Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigValidation:
    def test_s3_requires_bucket(self):
        from app.routers.exports import _validate_config

        with pytest.raises(Exception):
            _validate_config("s3", {})

    def test_webhook_requires_url(self):
        from app.routers.exports import _validate_config

        with pytest.raises(Exception):
            _validate_config("webhook", {})

    def test_webhook_requires_https(self):
        from app.routers.exports import _validate_config

        with pytest.raises(Exception):
            _validate_config("webhook", {"webhook_url": "http://insecure.com"})

    def test_kafka_requires_bootstrap(self):
        from app.routers.exports import _validate_config

        with pytest.raises(Exception):
            _validate_config("kafka_mirror", {})

    def test_s3_valid(self):
        from app.routers.exports import _validate_config

        _validate_config("s3", {"s3_bucket": "my-bucket"})  # No exception

    def test_webhook_valid(self):
        from app.routers.exports import _validate_config

        with patch("app.routers.exports._validate_webhook_host"):
            _validate_config("webhook", {"webhook_url": "https://hooks.example.com"})

    def test_kafka_valid(self):
        from app.routers.exports import _validate_config

        _validate_config("kafka_mirror", {"kafka_bootstrap": "localhost:9092"})

# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS ROUTER — Response Builder
# ══════════════════════════════════════════════════════════════════════════════

class TestResponseBuilder:
    def test_to_response(self):
        from app.routers.exports import _to_response

        row = {
            "id": "ch-1",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "name": "My S3",
            "channel_type": "s3",
            "config": json.dumps({"s3_bucket": "b", "secret_key": "x"}),
            "pii_fields": json.dumps(["src_endpoint.ip"]),
            "enabled": True,
            "created_at": "2025-01-15T00:00:00Z",
            "updated_at": "2025-01-15T00:00:00Z",
        }
        resp = _to_response(row)
        assert resp["id"] == "ch-1"
        assert resp["config_masked"]["secret_key"] == "***"
        assert resp["pii_fields"] == ["src_endpoint.ip"]

    def test_to_response_null_pii(self):
        from app.routers.exports import _to_response

        row = {
            "id": "ch-2",
            "tenant_id": "t1",
            "name": "WH",
            "channel_type": "webhook",
            "config": "{}",
            "pii_fields": None,
            "enabled": False,
            "created_at": "2025-01-01",
            "updated_at": "2025-01-01",
        }
        resp = _to_response(row)
        assert resp["pii_fields"] is None
        assert resp["enabled"] is False
