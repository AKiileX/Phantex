# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for the Rule Engine integration.

Tests the engine's evaluate_event(), load_rule(), and context building
without requiring Kafka or a database.

Covers:
  AC2: Event matching rule → alert (tested via evaluate_event returns matched rules)
  AC6: Performance — 1000 events with 50 rules < 10ms per event
  AC7: Disabled rules not evaluated
"""

import time
import uuid

import pytest

from engine.parser.parser import ParseError
from engine.rule_engine import EngineConfig, RuleEngine

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return RuleEngine(EngineConfig())

@pytest.fixture
def tool_call_event():
    return {
        "event_type": "TOOL_CALL",
        "severity": "medium",
        "agent_id": "aaaaaaaa-1111-2222-3333-444444444444",
        "sensor_id": "sensor-1",
        "timestamp": "2025-01-15T10:00:00Z",
        "raw_data": {
            "tool_name": "exec_shell",
            "tool_input": "cat /etc/passwd",
            "protocol": "langchain_tool",
        },
    }

@pytest.fixture
def heartbeat_event():
    return {
        "event_type": "HEARTBEAT",
        "severity": "info",
        "agent_id": "",
        "sensor_id": "sensor-1",
        "timestamp": "2025-01-15T10:00:00Z",
        "raw_data": {},
    }

# ── load_rule Tests ──────────────────────────────────────────────────────────

class TestLoadRule:
    def test_load_valid_rule(self, engine):
        rid = uuid.uuid4()
        compiled = engine.load_rule(
            rid,
            'event.type == "TOOL_CALL"',
            name="detect_tool_call",
            severity="high",
        )
        assert compiled.rule_id == rid
        assert compiled.name == "detect_tool_call"
        assert rid in engine.rules

    def test_load_invalid_prl(self, engine):
        with pytest.raises(ParseError):
            engine.load_rule(uuid.uuid4(), "INVALID @@@")

    def test_load_replaces_existing(self, engine):
        rid = uuid.uuid4()
        engine.load_rule(rid, 'event.type == "A"', name="v1")
        engine.load_rule(rid, 'event.type == "B"', name="v2")
        assert engine.rules[rid].name == "v2"

# ── evaluate_event Tests ──────────────────────────────────────────────────────

class TestEvaluateEvent:
    def test_matching_rule(self, engine, tool_call_event):
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="detect_tool_call",
        )
        matched = engine.evaluate_event(tool_call_event)
        assert len(matched) == 1
        assert matched[0].name == "detect_tool_call"

    def test_no_match(self, engine, heartbeat_event):
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="detect_tool_call",
        )
        matched = engine.evaluate_event(heartbeat_event)
        assert len(matched) == 0

    def test_multiple_rules_match(self, engine, tool_call_event):
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="rule1",
        )
        engine.load_rule(
            uuid.uuid4(),
            'event.severity == "medium"',
            name="rule2",
        )
        matched = engine.evaluate_event(tool_call_event)
        names = {r.name for r in matched}
        assert "rule1" in names
        assert "rule2" in names

    def test_disabled_rule_not_evaluated(self, engine, tool_call_event):
        """AC7: Disabled rules not evaluated."""
        rid = uuid.uuid4()
        engine.load_rule(
            rid,
            'event.type == "TOOL_CALL"',
            name="disabled_rule",
            enabled=False,
        )
        matched = engine.evaluate_event(tool_call_event)
        assert len(matched) == 0
        # Disabled rule should have 0 eval_count
        assert engine.rules[rid].eval_count == 0

    def test_tenant_filtering(self, engine, tool_call_event):
        t1 = uuid.uuid4()
        t2 = uuid.uuid4()
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="tenant1_rule",
            tenant_id=t1,
        )
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="tenant2_rule",
            tenant_id=t2,
        )
        matched = engine.evaluate_event(tool_call_event, tenant_id=str(t1))
        names = {r.name for r in matched}
        assert "tenant1_rule" in names
        assert "tenant2_rule" not in names

# ── Context Builder Tests ─────────────────────────────────────────────────────

class TestContextBuilder:
    def test_builds_event_context(self):
        event = {
            "event_type": "TOOL_CALL",
            "severity": "high",
            "agent_id": "agent-1",
            "sensor_id": "sensor-1",
            "raw_data": {"tool_name": "exec_shell"},
        }
        ctx = RuleEngine._build_context(event)
        assert ctx["event"]["type"] == "TOOL_CALL"
        assert ctx["event"]["severity"] == "high"
        assert ctx["event"]["raw_data"]["tool_name"] == "exec_shell"

    def test_handles_string_raw_data(self):
        import json

        event = {
            "event_type": "X",
            "raw_data": json.dumps({"key": "value"}),
        }
        ctx = RuleEngine._build_context(event)
        assert ctx["event"]["raw_data"]["key"] == "value"

    def test_handles_missing_raw_data(self):
        ctx = RuleEngine._build_context({"event_type": "X"})
        assert ctx["event"]["raw_data"] == {}

# ── Sliding Window Integration Tests ─────────────────────────────────────────

class TestSlidingWindowIntegration:
    def test_count_increases_with_events(self, engine):
        engine.load_rule(
            uuid.uuid4(),
            'count("TOOL_CALL", "60s") > 5',
            name="rate_limit",
        )

        # Record 3 events — should not match
        for _ in range(3):
            engine.func_ctx.record_event("TOOL_CALL")

        event = {"event_type": "TOOL_CALL", "raw_data": {}}
        matched = engine.evaluate_event(event)
        assert len(matched) == 0

        # Record 10 more — should match
        for _ in range(10):
            engine.func_ctx.record_event("TOOL_CALL")

        matched = engine.evaluate_event(event)
        assert len(matched) == 1

# ── Performance Test (AC6) ────────────────────────────────────────────────────

class TestPerformance:
    def test_1000_events_50_rules_under_10ms(self, engine):
        """AC6: 1000 events/sec with 50 rules → < 10ms latency per event."""
        # Load 50 rules
        for i in range(50):
            engine.load_rule(
                uuid.uuid4(),
                f'event.type == "TYPE_{i}" AND event.severity == "high"',
                name=f"rule_{i}",
            )

        event = {
            "event_type": "TYPE_25",
            "severity": "high",
            "raw_data": {},
        }

        # Warm up
        engine.evaluate_event(event)

        # Time 1000 evaluations
        start = time.perf_counter()
        for _ in range(1000):
            engine.evaluate_event(event)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / 1000) * 1000
        assert avg_ms < 10.0, f"Average {avg_ms:.2f}ms per event exceeds 10ms"

# ── Stats Test ────────────────────────────────────────────────────────────────

class TestStats:
    def test_stats_reporting(self, engine, tool_call_event):
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="test",
        )
        engine.evaluate_event(tool_call_event)

        stats = engine.stats
        assert stats["rules_loaded"] == 1
        assert stats["rules_enabled"] == 1

    def test_eval_count_increment(self, engine, tool_call_event):
        rid = uuid.uuid4()
        engine.load_rule(rid, 'event.type == "TOOL_CALL"', name="test")
        engine.evaluate_event(tool_call_event)
        assert engine.rules[rid].eval_count == 1

    def test_match_count_increment(self, engine, tool_call_event):
        rid = uuid.uuid4()
        engine.load_rule(rid, 'event.type == "TOOL_CALL"', name="test")
        engine.evaluate_event(tool_call_event)
        assert engine.rules[rid].match_count == 1
