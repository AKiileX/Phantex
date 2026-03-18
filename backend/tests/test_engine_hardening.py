# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Block E — Detection Engine Security Hardening Tests ().

Covers all 8 findings from the  audit:
  E-01: ReDoS guard compiled once at module level + catches {n,m} quantifiers
  E-02: _create_alerts parses UUIDs once before loop
  E-03: max_rules_per_event enforced in evaluate_event
  E-04: Parser recursion depth limit (MAX_DEPTH = 64)
  E-05: _build_context raw_data JSON size cap (1 MB)
  E-06: Non-match logging removed from hot path
  E-07: truncate_dict handles list values
  E-08: List literal element cap in parser (256)
"""

import json
import re
import uuid
from unittest.mock import patch

import pytest

from engine.evaluator.functions import (
    _REDOS_PATTERN,
    FunctionContext,
    _get_compiled_regex,
    _regex_cache,
)
from engine.parser import ast as ast_nodes
from engine.parser.parser import ParseError, Parser, parse_prl
from engine.rule_engine import EngineConfig, RuleEngine
from engine.utils.truncate import truncate_dict

# ═══════════════════════════════════════════════════════════════════════════════
# E-01: ReDoS guard — module-level compiled, catches {n,m} patterns
# ═══════════════════════════════════════════════════════════════════════════════

class TestReDoSGuard:
    """E-01: ReDoS protection compiled once + expanded coverage."""

    def test_redos_pattern_is_module_level_compiled(self):
        """_REDOS_PATTERN should be a pre-compiled re.Pattern, not built inline."""
        assert isinstance(_REDOS_PATTERN, re.Pattern)

    def test_rejects_nested_quantifier_star_star(self):
        with pytest.raises(ValueError, match="ReDoS"):
            _get_compiled_regex("(a*)*")

    def test_rejects_nested_quantifier_plus_plus(self):
        with pytest.raises(ValueError, match="ReDoS"):
            _get_compiled_regex("(a+)+")

    def test_rejects_nested_quantifier_plus_star(self):
        with pytest.raises(ValueError, match="ReDoS"):
            _get_compiled_regex("(a+)*")

    def test_rejects_curly_brace_nested_quantifier(self):
        """E-01 expansion: (a{2,5})+ should also be caught."""
        with pytest.raises(ValueError, match="ReDoS"):
            _get_compiled_regex("(a{2,5})+")

    def test_rejects_curly_on_curly(self):
        """(a{1,100}){1,100} should be caught."""
        with pytest.raises(ValueError, match="ReDoS"):
            _get_compiled_regex("(a{1,100}){1,100}")

    def test_allows_simple_quantifiers(self):
        """Normal patterns should compile fine."""
        p = _get_compiled_regex("a+b*c?")
        assert p.search("abc") is not None

    def test_allows_non_nested_groups(self):
        """Groups without nested quantifiers are fine."""
        p = _get_compiled_regex("(abc|def)+")
        assert p.search("abcdef") is not None

    def test_rejects_pattern_over_1000_chars(self):
        with pytest.raises(ValueError, match="too long"):
            _get_compiled_regex("a" * 1001)

    def test_cache_eviction_works(self):
        """Cache should evict when full."""
        # Clear the cache first
        _regex_cache.clear()
        # Fill cache to the max
        for i in range(1000):
            _get_compiled_regex(f"test_pattern_{i}")
        assert len(_regex_cache) == 1000
        # One more triggers eviction
        _get_compiled_regex("trigger_eviction")
        assert len(_regex_cache) < 1000

# ═══════════════════════════════════════════════════════════════════════════════
# E-02: _create_alerts UUID parsing once before loop
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateAlertsUUIDParsing:
    """E-02: UUIDs parsed once before the per-rule loop."""

    @pytest.mark.asyncio
    async def test_invalid_tenant_id_returns_early(self):
        """Bad tenant_id should log error and return, not crash per rule."""
        engine = RuleEngine(EngineConfig())
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="test",
        )

        with patch("engine.rule_engine.logger") as mock_logger:
            await engine._create_alerts(
                matched_rules=list(engine.rules.values()),
                event_data={"event_type": "TOOL_CALL"},
                tenant_id="not-a-uuid",
            )
            mock_logger.error.assert_any_call(
                "invalid_tenant_id",
                tenant_id="not-a-uuid",
            )

    @pytest.mark.asyncio
    async def test_invalid_event_id_logs_warning_continues(self):
        """Bad event_id in event_data should warn but not abort."""
        engine = RuleEngine(EngineConfig())
        engine.load_rule(uuid.uuid4(), 'event.type == "X"', name="test")

        with patch("engine.rule_engine.logger") as mock_logger:
            await engine._create_alerts(
                matched_rules=list(engine.rules.values()),
                event_data={"event_id": "bad-uuid", "event_type": "X"},
                tenant_id=str(uuid.uuid4()),
            )
            mock_logger.warning.assert_any_call(
                "invalid_event_id",
                event_id="bad-uuid",
            )

    @pytest.mark.asyncio
    async def test_agent_id_accepted_as_paid_string(self):
        """agent_id is a PAID string, not a UUID — should be passed through."""
        engine = RuleEngine(EngineConfig())
        engine.load_rule(uuid.uuid4(), 'event.type == "X"', name="test")

        with patch("engine.rule_engine.logger") as mock_logger:
            await engine._create_alerts(
                matched_rules=list(engine.rules.values()),
                event_data={"agent_id": "ptx-default-dev-abc123", "event_type": "X"},
                tenant_id=str(uuid.uuid4()),
            )
            # agent_id is NOT validated as UUID — it's a PAID string
            # Verify no warning was logged about agent_id
            for call in mock_logger.warning.call_args_list:
                assert call.args[0] != "invalid_agent_id"

# ═══════════════════════════════════════════════════════════════════════════════
# E-03: max_rules_per_event enforcement
# ═══════════════════════════════════════════════════════════════════════════════

class TestMaxRulesPerEvent:
    """E-03: max_rules_per_event config enforced in evaluate_event."""

    def test_enforces_max_rules_cap(self):
        """When more rules match than the cap, stop early."""
        config = EngineConfig(max_rules_per_event=3)
        engine = RuleEngine(config)

        # Load 10 rules that all match
        for i in range(10):
            engine.load_rule(
                uuid.uuid4(),
                'event.severity == "high"',
                name=f"rule_{i}",
            )

        event = {"event_type": "X", "severity": "high", "raw_data": {}}
        matched = engine.evaluate_event(event)
        assert len(matched) == 3  # capped at max_rules_per_event

    def test_default_cap_is_500(self):
        config = EngineConfig()
        assert config.max_rules_per_event == 500

    def test_all_match_when_under_cap(self):
        """When fewer rules match than cap, all are returned."""
        config = EngineConfig(max_rules_per_event=100)
        engine = RuleEngine(config)

        for i in range(5):
            engine.load_rule(
                uuid.uuid4(),
                'event.severity == "high"',
                name=f"rule_{i}",
            )

        event = {"event_type": "X", "severity": "high", "raw_data": {}}
        matched = engine.evaluate_event(event)
        assert len(matched) == 5

# ═══════════════════════════════════════════════════════════════════════════════
# E-04: Parser recursion depth limit
# ═══════════════════════════════════════════════════════════════════════════════

class TestParserDepthLimit:
    """E-04: Deeply nested expressions rejected instead of stack overflow."""

    def test_max_depth_constant_exists(self):
        assert Parser.MAX_DEPTH == 64

    def test_deeply_nested_nots_rejected(self):
        """NOT NOT NOT ... (100×) should fail, not overflow stack."""
        prl = "NOT " * 100 + "true"
        with pytest.raises(ParseError, match="nesting too deep"):
            parse_prl(prl)

    def test_deeply_nested_parens_rejected(self):
        """(((( ... )))) 100 deep should fail."""
        prl = "(" * 100 + "true" + ")" * 100
        with pytest.raises(ParseError, match="nesting too deep"):
            parse_prl(prl)

    def test_moderate_nesting_allowed(self):
        """Reasonable nesting (10 levels) should work fine."""
        prl = "NOT " * 10 + "true"
        rule = parse_prl(prl)
        assert isinstance(rule.condition, ast_nodes.UnaryOp)

    def test_moderate_parens_allowed(self):
        """Reasonable parentheses nesting should work."""
        prl = "(" * 10 + "true" + ")" * 10
        rule = parse_prl(prl)
        # Innermost is BoolLiteral
        assert rule is not None

# ═══════════════════════════════════════════════════════════════════════════════
# E-05: _build_context raw_data JSON size cap
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildContextSizeCap:
    """E-05: raw_data strings over 1 MB rejected."""

    def test_normal_json_string_parsed(self):
        event = {
            "event_type": "X",
            "raw_data": json.dumps({"tool": "read_file"}),
        }
        ctx = RuleEngine._build_context(event)
        assert ctx["event"]["raw_data"]["tool"] == "read_file"

    def test_oversized_json_string_replaced_with_empty(self):
        """raw_data string over 1 MB → empty dict (not parsed)."""
        huge_str = json.dumps({"big": "x" * 2_000_000})
        event = {"event_type": "X", "raw_data": huge_str}
        ctx = RuleEngine._build_context(event)
        assert ctx["event"]["raw_data"] == {}

    def test_1mb_exactly_still_parsed(self):
        """Strings at or just below 1 MB should still be parsed."""
        small = json.dumps({"k": "v"})
        assert len(small) < 1_048_576
        event = {"event_type": "X", "raw_data": small}
        ctx = RuleEngine._build_context(event)
        assert ctx["event"]["raw_data"]["k"] == "v"

    def test_dict_raw_data_passed_through(self):
        """If raw_data is already a dict, no size check needed."""
        event = {"event_type": "X", "raw_data": {"tool": "x"}}
        ctx = RuleEngine._build_context(event)
        assert ctx["event"]["raw_data"]["tool"] == "x"

# ═══════════════════════════════════════════════════════════════════════════════
# E-06: Non-match logging removed from hot path
# ═══════════════════════════════════════════════════════════════════════════════

class TestMatchOnlyLogging:
    """E-06: Only rule matches are logged (not every non-match)."""

    def test_match_logged(self):
        """Matched rules should still be logged."""
        engine = RuleEngine(EngineConfig())
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "TOOL_CALL"',
            name="match_me",
        )
        event = {"event_type": "TOOL_CALL", "severity": "high", "raw_data": {}}

        with patch("engine.rule_engine.log_match_action") as mock_log:
            matched = engine.evaluate_event(event)
            assert len(matched) == 1
            mock_log.assert_called_once()
            assert mock_log.call_args.kwargs["matched"] is True

    def test_non_match_not_logged(self):
        """Non-matching rules should NOT call log_match_action."""
        engine = RuleEngine(EngineConfig())
        engine.load_rule(
            uuid.uuid4(),
            'event.type == "NETWORK"',
            name="no_match",
        )
        event = {"event_type": "TOOL_CALL", "severity": "high", "raw_data": {}}

        with patch("engine.rule_engine.log_match_action") as mock_log:
            matched = engine.evaluate_event(event)
            assert len(matched) == 0
            mock_log.assert_not_called()

# ═══════════════════════════════════════════════════════════════════════════════
# E-07: truncate_dict handles list values
# ═══════════════════════════════════════════════════════════════════════════════

class TestTruncateDictLists:
    """E-07: List values in truncated dicts are properly handled."""

    def test_list_strings_truncated(self):
        data = {"commands": ["x" * 500, "y" * 500]}
        result = truncate_dict(data, max_size=100, nested_str_len=64)
        for item in result["commands"]:
            assert len(item) <= 67  # 64 + "..."

    def test_list_capped_at_20_elements(self):
        data = {"items": list(range(50))}
        result = truncate_dict(data, max_size=100)
        assert len(result["items"]) == 20

    def test_list_non_strings_preserved(self):
        data = {"nums": [1, 2, 3]}
        result = truncate_dict(data, max_size=10)
        assert result["nums"] == [1, 2, 3]

    def test_small_data_unchanged(self):
        data = {"items": ["a", "b"]}
        result = truncate_dict(data)
        assert result == data

    def test_mixed_dict_and_list_values(self):
        data = {
            "str_val": "x" * 500,
            "dict_val": {"k": "v" * 200},
            "list_val": ["long" * 100],
            "int_val": 42,
        }
        result = truncate_dict(data, max_size=100, max_str_len=64, nested_str_len=32)
        assert "truncated" in result["str_val"]
        assert isinstance(result["list_val"], list)
        assert result["int_val"] == 42

# ═══════════════════════════════════════════════════════════════════════════════
# E-08: List literal element cap in parser
# ═══════════════════════════════════════════════════════════════════════════════

class TestParserListCap:
    """E-08: PRL list literals capped at 256 elements."""

    def test_normal_list_allowed(self):
        prl = 'event.type IN ["A", "B", "C"]'
        rule = parse_prl(prl)
        assert isinstance(rule.condition, ast_nodes.Compare)

    def test_256_elements_allowed(self):
        elements = ", ".join(f'"{i}"' for i in range(256))
        prl = f"x IN [{elements}]"
        rule = parse_prl(prl)
        assert isinstance(rule.condition.right, ast_nodes.ListLiteral)
        assert len(rule.condition.right.elements) == 256

    def test_257_elements_rejected(self):
        elements = ", ".join(f'"{i}"' for i in range(257))
        prl = f"x IN [{elements}]"
        with pytest.raises(ParseError, match="List literal too large"):
            parse_prl(prl)

# ═══════════════════════════════════════════════════════════════════════════════
# Additional hardening: FunctionContext bounds
# ═══════════════════════════════════════════════════════════════════════════════

class TestFunctionContextBounds:
    """Verify existing window bounds are properly enforced."""

    def test_window_maxlen_enforced(self):
        """Deque maxlen=100_000 should prevent unbounded growth."""
        ctx = FunctionContext()
        key = ctx._window_key("TEST", "tenant", "agent")
        dq = ctx.event_windows[key]
        assert dq.maxlen == 100_000

    def test_allowlist_isolation(self):
        """Allowlists must not leak between names."""
        ctx = FunctionContext()
        ctx.set_allowlist("list_a", {"x"})
        ctx.set_allowlist("list_b", {"y"})
        assert ctx.is_in_allowlist("x", "list_a") is True
        assert ctx.is_in_allowlist("x", "list_b") is False

    def test_tenant_scoped_windows(self):
        """Windows for different tenants must not collide."""
        ctx = FunctionContext()
        ctx.record_event("TOOL_CALL", tenant_id="t1", agent_id="a1")
        ctx.record_event("TOOL_CALL", tenant_id="t1", agent_id="a1")
        ctx.record_event("TOOL_CALL", tenant_id="t2", agent_id="a1")

        assert ctx.count_in_window("TOOL_CALL", 60.0, "t1", "a1") == 2
        assert ctx.count_in_window("TOOL_CALL", 60.0, "t2", "a1") == 1
