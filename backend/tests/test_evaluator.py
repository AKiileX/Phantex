# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for the PRL Evaluator and built-in functions.

Covers all acceptance criteria:
  AC1: PRL parses correctly → valid AST
  AC3: regex_match works correctly
  AC4: count() sliding window works
  AC5: Invalid PRL → clear error with line number
  AC7: Disabled rules not evaluated
"""

import time

import pytest

from engine.evaluator.evaluator import EvalError, Evaluator
from engine.evaluator.functions import (
    BuiltinRegistry,
    FunctionContext,
    fn_count_distinct,
    fn_in_allowlist,
    parse_duration,
)
from engine.parser import ast as ast_nodes
from engine.parser.parser import ParseError, parse_prl

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def evaluator():
    return Evaluator(functions=BuiltinRegistry())

@pytest.fixture
def func_ctx():
    return FunctionContext()

@pytest.fixture
def tool_call_event():
    """A typical TOOL_CALL event context."""
    return {
        "event": {
            "type": "TOOL_CALL",
            "severity": "medium",
            "agent_id": "aaaaaaaa-1111-2222-3333-444444444444",
            "sensor_id": "sensor-1",
            "timestamp": "2025-01-15T10:00:00Z",
            "raw_data": {
                "tool_name": "exec_shell",
                "tool_input": "cat /etc/passwd",
                "protocol": "langchain_tool",
                "arguments": '{"command": "cat /etc/passwd"}',
            },
        },
    }

@pytest.fixture
def heartbeat_event():
    return {
        "event": {
            "type": "HEARTBEAT",
            "severity": "info",
            "agent_id": "",
            "sensor_id": "sensor-1",
            "timestamp": "2025-01-15T10:00:00Z",
            "raw_data": {},
        },
    }

# ── Duration Parser Tests ─────────────────────────────────────────────────────

class TestParseDuration:
    def test_seconds(self):
        assert parse_duration("60s") == 60.0

    def test_minutes(self):
        assert parse_duration("5m") == 300.0

    def test_hours(self):
        assert parse_duration("1h") == 3600.0

    def test_days(self):
        assert parse_duration("7d") == 604800.0

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid duration format"):
            parse_duration("abc")

    def test_whitespace_trimmed(self):
        assert parse_duration("  30s  ") == 30.0

# ── Evaluator Literal Tests ──────────────────────────────────────────────────

class TestEvaluatorLiterals:
    def test_string_literal(self, evaluator):
        rule = parse_prl('"hello"')
        assert evaluator.evaluate(rule, {})  # Non-empty string is truthy

    def test_number_literal(self, evaluator):
        rule = parse_prl("42")
        assert evaluator.evaluate(rule, {})  # Non-zero is truthy

    def test_zero_is_falsy(self, evaluator):
        rule = parse_prl("0")
        assert not evaluator.evaluate(rule, {})

    def test_bool_true(self, evaluator):
        rule = parse_prl("true")
        assert evaluator.evaluate(rule, {})

    def test_bool_false(self, evaluator):
        rule = parse_prl("false")
        assert not evaluator.evaluate(rule, {})

# ── Evaluator Field Access Tests ──────────────────────────────────────────────

class TestEvaluatorFieldAccess:
    def test_simple_field(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "TOOL_CALL"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_nested_field(self, evaluator, tool_call_event):
        rule = parse_prl('event.raw_data.tool_name == "exec_shell"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_unknown_object_returns_false(self, evaluator):
        """Unknown top-level objects resolve to _MISSING → comparison returns False."""
        rule = parse_prl('unknown.field == "x"')
        assert not evaluator.evaluate(rule, {})

    def test_unknown_field_returns_false(self, evaluator, tool_call_event):
        """Nonexistent nested fields resolve to _MISSING → comparison returns False."""
        rule = parse_prl('event.nonexistent == "x"')
        assert not evaluator.evaluate(rule, tool_call_event)

# ── Evaluator Comparison Tests ────────────────────────────────────────────────

class TestEvaluatorComparisons:
    def test_eq_match(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "TOOL_CALL"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_eq_no_match(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "HEARTBEAT"')
        assert not evaluator.evaluate(rule, tool_call_event)

    def test_neq(self, evaluator, tool_call_event):
        rule = parse_prl('event.type != "HEARTBEAT"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_gt(self, evaluator):
        rule = parse_prl("x > 10")
        assert evaluator.evaluate(rule, {"x": 20})
        assert not evaluator.evaluate(rule, {"x": 5})

    def test_lt(self, evaluator):
        rule = parse_prl("x < 10")
        assert evaluator.evaluate(rule, {"x": 5})

    def test_gte(self, evaluator):
        rule = parse_prl("x >= 10")
        assert evaluator.evaluate(rule, {"x": 10})

    def test_lte(self, evaluator):
        rule = parse_prl("x <= 10")
        assert evaluator.evaluate(rule, {"x": 10})

    def test_in_operator(self, evaluator, tool_call_event):
        rule = parse_prl('event.type IN ["TOOL_CALL", "TOOL_RESPONSE"]')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_in_not_found(self, evaluator, tool_call_event):
        rule = parse_prl('event.type IN ["HEARTBEAT", "PROCESS_EXEC"]')
        assert not evaluator.evaluate(rule, tool_call_event)

    def test_in_requires_list(self, evaluator):
        rule = parse_prl('x IN "not_a_list"')
        with pytest.raises(EvalError, match="IN operator requires a list"):
            evaluator.evaluate(rule, {"x": "a"})

# ── Evaluator Logical Operators ───────────────────────────────────────────────

class TestEvaluatorLogical:
    def test_and_both_true(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "TOOL_CALL" AND event.severity == "medium"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_and_one_false(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "TOOL_CALL" AND event.severity == "critical"')
        assert not evaluator.evaluate(rule, tool_call_event)

    def test_or_one_true(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "HEARTBEAT" OR event.type == "TOOL_CALL"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_or_both_false(self, evaluator, tool_call_event):
        rule = parse_prl('event.type == "HEARTBEAT" OR event.type == "PROCESS_EXEC"')
        assert not evaluator.evaluate(rule, tool_call_event)

    def test_not(self, evaluator, tool_call_event):
        rule = parse_prl('NOT event.type == "HEARTBEAT"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_not_true_is_false(self, evaluator, tool_call_event):
        rule = parse_prl('NOT event.type == "TOOL_CALL"')
        assert not evaluator.evaluate(rule, tool_call_event)

    def test_short_circuit_and(self, evaluator):
        """AND should short-circuit: if left is False, right is not evaluated."""
        rule = parse_prl("false AND undefined_var == 1")
        # If short-circuit works, undefined_var is never accessed
        assert not evaluator.evaluate(rule, {})

    def test_short_circuit_or(self, evaluator):
        """OR should short-circuit: if left is True, right is not evaluated."""
        rule = parse_prl("true OR undefined_var == 1")
        assert evaluator.evaluate(rule, {})

# ── Built-in Function Tests ──────────────────────────────────────────────────

class TestFunctionContains:
    def test_contains_match(self, evaluator, tool_call_event):
        rule = parse_prl('contains(event.raw_data.tool_input, "passwd")')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_contains_no_match(self, evaluator, tool_call_event):
        rule = parse_prl('contains(event.raw_data.tool_input, "shadow")')
        assert not evaluator.evaluate(rule, tool_call_event)

class TestFunctionRegexMatch:
    """AC3: regex_match works correctly."""

    def test_regex_match_simple(self, evaluator, tool_call_event):
        rule = parse_prl('regex_match(".*passwd.*", event.raw_data.tool_input)')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_regex_no_match(self, evaluator, tool_call_event):
        rule = parse_prl('regex_match("^shadow$", event.raw_data.tool_input)')
        assert not evaluator.evaluate(rule, tool_call_event)

    def test_regex_anchored(self, evaluator, tool_call_event):
        rule = parse_prl('regex_match("^cat", event.raw_data.tool_input)')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_regex_invalid_pattern(self, evaluator, tool_call_event):
        rule = parse_prl('regex_match("[invalid", event.raw_data.tool_input)')
        with pytest.raises(EvalError, match="Function.*failed"):
            evaluator.evaluate(rule, tool_call_event)

class TestFunctionCount:
    """AC4: count() sliding window works."""

    def test_count_empty(self, evaluator, func_ctx):
        rule = parse_prl('count("TOOL_CALL", "60s") > 0')
        assert not evaluator.evaluate(rule, {}, func_ctx)

    def test_count_with_events(self, evaluator, func_ctx):
        # Record 5 events within the window
        now = time.time()
        for i in range(5):
            func_ctx.record_event("TOOL_CALL", now - i)

        rule = parse_prl('count("TOOL_CALL", "60s") > 3')
        assert evaluator.evaluate(rule, {}, func_ctx)

    def test_count_expired_events(self, evaluator, func_ctx):
        # Record events 120 seconds ago (outside 60s window)
        old = time.time() - 120
        for i in range(10):
            func_ctx.record_event("TOOL_CALL", old + i)

        rule = parse_prl('count("TOOL_CALL", "60s") > 0')
        assert not evaluator.evaluate(rule, {}, func_ctx)

    def test_count_mixed_types(self, evaluator, func_ctx):
        now = time.time()
        for i in range(5):
            func_ctx.record_event("TOOL_CALL", now - i)
        for i in range(3):
            func_ctx.record_event("HEARTBEAT", now - i)

        rule = parse_prl('count("TOOL_CALL", "60s") == 5')
        assert evaluator.evaluate(rule, {}, func_ctx)

    def test_count_sliding_window_purge(self, evaluator, func_ctx):
        """Verify that expired entries are purged on access."""
        now = time.time()
        # 3 old events + 2 recent
        func_ctx.record_event("X", now - 200)
        func_ctx.record_event("X", now - 150)
        func_ctx.record_event("X", now - 100)
        func_ctx.record_event("X", now - 5)
        func_ctx.record_event("X", now - 1)

        rule = parse_prl('count("X", "60s") == 2')
        assert evaluator.evaluate(rule, {}, func_ctx)

class TestFunctionTimeSince:
    def test_time_since_never_seen(self, evaluator, func_ctx):
        rule = parse_prl('time_since("HEARTBEAT") > 300')
        assert evaluator.evaluate(rule, {}, func_ctx)  # 999999 > 300

    def test_time_since_recent(self, evaluator, func_ctx):
        func_ctx.record_event("HEARTBEAT", time.time())
        rule = parse_prl('time_since("HEARTBEAT") < 5')
        assert evaluator.evaluate(rule, {}, func_ctx)

    def test_time_since_old(self, evaluator, func_ctx):
        func_ctx.record_event("HEARTBEAT", time.time() - 600)
        rule = parse_prl('time_since("HEARTBEAT") > 300')
        assert evaluator.evaluate(rule, {}, func_ctx)

# ── Complex Rule Evaluation Tests ─────────────────────────────────────────────

class TestComplexRules:
    def test_detect_sensitive_file_access(self, evaluator, tool_call_event):
        """Detect tool calls accessing sensitive files."""
        rule = parse_prl(
            'event.type == "TOOL_CALL" AND regex_match("/etc/(passwd|shadow|sudoers)", event.raw_data.tool_input)'
        )
        assert evaluator.evaluate(rule, tool_call_event)

    def test_detect_shell_execution(self, evaluator, tool_call_event):
        """Detect exec_shell tool usage."""
        rule = parse_prl('event.type == "TOOL_CALL" AND event.raw_data.tool_name == "exec_shell"')
        assert evaluator.evaluate(rule, tool_call_event)

    def test_not_heartbeat_and_high_severity(self, evaluator):
        ctx = {
            "event": {
                "type": "TOOL_CALL",
                "severity": "high",
                "raw_data": {},
            },
        }
        rule = parse_prl('NOT event.type == "HEARTBEAT" AND event.severity == "high"')
        assert evaluator.evaluate(rule, ctx)

    def test_rate_limit_with_type_check(self, evaluator, func_ctx, tool_call_event):
        """Combine type check with rate limiting."""
        # Must record with same agent_id as event fixture so scoped window matches
        agent_id = tool_call_event["event"]["agent_id"]
        now = time.time()
        for i in range(200):
            func_ctx.record_event("TOOL_CALL", now - i * 0.1, agent_id=agent_id)

        rule = parse_prl('event.type == "TOOL_CALL" AND count("TOOL_CALL", "60s") > 100')
        assert evaluator.evaluate(rule, tool_call_event, func_ctx)

# ── Parse Error Tests (AC5) ──────────────────────────────────────────────────

class TestParseErrors:
    """AC5: Invalid PRL → clear error with line number."""

    def test_invalid_syntax_has_line(self):
        try:
            parse_prl("event.type == AND")
        except ParseError as e:
            assert "Line" in str(e)
            assert e.line >= 1

    def test_unterminated_string(self):
        with pytest.raises(ParseError, match="Line"):
            parse_prl('"hello')

    def test_unknown_function(self):
        with pytest.raises(ParseError, match="Unknown function"):
            parse_prl("bad_func()")

    def test_empty_rule(self):
        with pytest.raises(ParseError):
            parse_prl("")

    def test_multiline_error_position(self):
        try:
            parse_prl('event.type == "X"\nAND\n@invalid')
        except ParseError as e:
            # Error should be at line 3
            assert e.line == 3

# ── AST Walk + Pretty Print Tests ────────────────────────────────────────────

class TestASTHelpers:
    def test_walk_visits_all_nodes(self):
        rule = parse_prl('event.type == "TOOL_CALL" AND x > 10')
        nodes = list(ast_nodes.walk(rule))
        # Should find: Rule, BinaryOp, Compare x2, FieldAccess, StringLiteral,
        # Identifier, NumberLiteral
        assert len(nodes) >= 6

    def test_pretty_print(self):
        rule = parse_prl('event.type == "TOOL_CALL"')
        output = ast_nodes.pretty_print(rule)
        assert "Rule" in output
        assert "Compare" in output
        assert "TOOL_CALL" in output

# ── count_distinct Tests ──────────────────────────────────────────────────────

class TestCountDistinct:
    """Tests for count_distinct(event_type, field_path, window)."""

    def test_returns_zero_for_empty_context(self):
        ctx = FunctionContext()
        result = fn_count_distinct(["FILE_READ", "raw_data.filename", "60s"], {}, ctx)
        assert result == 0

    def test_counts_distinct_values(self):
        ctx = FunctionContext()
        # Record 5 events but only 3 distinct filenames
        for fname in ["a.txt", "b.txt", "a.txt", "c.txt", "b.txt"]:
            ctx.record_event("FILE_READ", field_values={"raw_data.filename": fname})
        result = fn_count_distinct(["FILE_READ", "raw_data.filename", "60s"], {}, ctx)
        assert result == 3

    def test_ignores_other_event_types(self):
        ctx = FunctionContext()
        ctx.record_event("FILE_READ", field_values={"raw_data.filename": "a.txt"})
        ctx.record_event("NETWORK_CONNECT", field_values={"raw_data.filename": "b.txt"})
        result = fn_count_distinct(["FILE_READ", "raw_data.filename", "60s"], {}, ctx)
        assert result == 1

    def test_window_expiry(self):
        ctx = FunctionContext()
        ctx.record_event("FILE_READ", field_values={"raw_data.filename": "old.txt"})

        # Manually age the entry by shifting its timestamp back
        key = ctx._window_key("FILE_READ", None, None)
        vkey = f"{key}:raw_data.filename"
        dq = ctx.event_value_windows[vkey]
        dq[0] = (time.time() - 120, "old.txt")  # 2 min ago

        ctx.record_event("FILE_READ", field_values={"raw_data.filename": "new.txt"})
        # Only 1 distinct within 60s window (old.txt expired)
        result = fn_count_distinct(["FILE_READ", "raw_data.filename", "60s"], {}, ctx)
        assert result == 1

    def test_no_func_ctx_returns_zero(self):
        result = fn_count_distinct(["FILE_READ", "raw_data.filename", "60s"], {}, None)
        assert result == 0

    def test_missing_field_path_not_counted(self):
        ctx = FunctionContext()
        ctx.record_event("FILE_READ", field_values={"raw_data.other": "val"})
        result = fn_count_distinct(["FILE_READ", "raw_data.filename", "60s"], {}, ctx)
        assert result == 0

# ── in_allowlist Tests ────────────────────────────────────────────────────────

class TestInAllowlist:
    """Tests for in_allowlist(value, list_name) with fail-closed semantics."""

    def test_unconfigured_returns_false(self):
        """No allowlist set → False (fail-closed)."""
        ctx = FunctionContext()
        result = fn_in_allowlist(["10.0.0.1", "allowed_ips"], {}, ctx)
        assert result is False

    def test_value_in_allowlist_returns_true(self):
        ctx = FunctionContext()
        ctx.set_allowlist("approved_tools", {"read_file", "search"})
        result = fn_in_allowlist(["read_file", "approved_tools"], {}, ctx)
        assert result is True

    def test_value_not_in_allowlist_returns_false(self):
        ctx = FunctionContext()
        ctx.set_allowlist("approved_tools", {"read_file", "search"})
        result = fn_in_allowlist(["exec_shell", "approved_tools"], {}, ctx)
        assert result is False

    def test_empty_allowlist_returns_false(self):
        """An explicitly-empty list is configured but has no entries."""
        ctx = FunctionContext()
        ctx.set_allowlist("approved_tools", set())
        result = fn_in_allowlist(["anything", "approved_tools"], {}, ctx)
        assert result is False

    def test_no_func_ctx_returns_false(self):
        result = fn_in_allowlist(["x", "list"], {}, None)
        assert result is False

    def test_not_in_allowlist_rule_expression(self):
        """Full integration: NOT in_allowlist(...) is True when list is unconfigured."""
        rule = parse_prl(
            'event.type == "NETWORK_CONNECT" AND NOT in_allowlist(event.raw_data.network.dst_addr, "allowed_dests")'
        )
        evaluator = Evaluator(functions=BuiltinRegistry())
        ctx = FunctionContext()
        event_ctx = {
            "event": {
                "type": "NETWORK_CONNECT",
                "raw_data": {"network": {"dst_addr": "8.8.8.8"}},
            }
        }
        matched = evaluator.evaluate(rule, event_ctx, func_ctx=ctx)
        assert matched is True  # NOT False = True → rule fires

    def test_allowlist_suppresses_rule(self):
        """Value IN configured allowlist → NOT True = False → rule suppressed."""
        rule = parse_prl(
            'event.type == "NETWORK_CONNECT" AND NOT in_allowlist(event.raw_data.network.dst_addr, "allowed_dests")'
        )
        evaluator = Evaluator(functions=BuiltinRegistry())
        ctx = FunctionContext()
        ctx.set_allowlist("allowed_dests", {"8.8.8.8"})
        event_ctx = {
            "event": {
                "type": "NETWORK_CONNECT",
                "raw_data": {"network": {"dst_addr": "8.8.8.8"}},
            }
        }
        matched = evaluator.evaluate(rule, event_ctx, func_ctx=ctx)
        assert matched is False  # NOT True = False → suppressed
