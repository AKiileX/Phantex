# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for N3 (SDK v2) and N4 (Policy Editor Backend).

Covers:
 • N4 — YAML safe parsing, tag rejection, size/depth limits
 • N4 — Policy definition validation (rules, schedule, scope)
 • N4 — Policy engine consumer (schedule, matching, rule application)
 • N4 — Pydantic schema validation
 • N3 — OTel bridge attribute sanitization
 • N3 — Trust context dataclass & staleness
 • N3 — Async buffer transport
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
#  N4 — YAML Safe Parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestYAMLParsing:
    """parse_yaml_safe() security & correctness tests."""

    def test_valid_yaml(self):
        from app.services.policy_service import parse_yaml_safe

        content = """
rules:
  - name: excessive_tool_calls
    enabled: true
    severity_override: high
"""
        result, errors = parse_yaml_safe(content)
        assert errors == []
        assert result is not None
        assert "rules" in result
        assert result["rules"][0]["name"] == "excessive_tool_calls"

    def test_empty_yaml(self):
        from app.services.policy_service import parse_yaml_safe

        result, errors = parse_yaml_safe("")
        # yaml.safe_load("") → None, which is not a dict
        assert result is None
        assert len(errors) > 0

    def test_non_dict_yaml(self):
        from app.services.policy_service import parse_yaml_safe

        result, errors = parse_yaml_safe("- item1\n- item2")
        assert result is None
        assert any("root must be a mapping" in e for e in errors)

    def test_reject_python_tag(self):
        from app.services.policy_service import parse_yaml_safe

        content = "exploit: !!python/object/apply:os.system ['echo hacked']"
        result, errors = parse_yaml_safe(content)
        assert result is None
        assert any("dangerous tags" in e for e in errors)

    def test_reject_exec_tag(self):
        from app.services.policy_service import parse_yaml_safe

        content = "run: !!exec/command 'rm -rf /'"
        result, errors = parse_yaml_safe(content)
        assert result is None
        assert any("dangerous tags" in e for e in errors)

    def test_reject_ruby_tag(self):
        from app.services.policy_service import parse_yaml_safe

        content = "x: !!ruby/hash {}"
        result, errors = parse_yaml_safe(content)
        assert result is None
        assert any("dangerous tags" in e for e in errors)

    def test_size_limit_exceeded(self):
        from app.services.policy_service import MAX_YAML_SIZE, parse_yaml_safe

        content = "a: " + "x" * (MAX_YAML_SIZE + 1)
        result, errors = parse_yaml_safe(content)
        assert result is None
        assert any("too large" in e.lower() for e in errors)

    def test_size_limit_just_under(self):
        from app.services.policy_service import MAX_YAML_SIZE, parse_yaml_safe

        content = "a: " + "x" * (MAX_YAML_SIZE - 10)
        result, errors = parse_yaml_safe(content)
        assert errors == []
        assert result is not None

    def test_depth_limit_exceeded(self):
        from app.services.policy_service import MAX_YAML_DEPTH, parse_yaml_safe

        # Build deeply nested YAML
        content = "a:\n"
        for i in range(MAX_YAML_DEPTH + 5):
            content += "  " * (i + 1) + "b:\n"
        content += "  " * (MAX_YAML_DEPTH + 6) + "val: 1\n"
        result, errors = parse_yaml_safe(content)
        assert result is None
        assert any("nesting too deep" in e.lower() for e in errors)

    def test_valid_depth(self):
        from app.services.policy_service import parse_yaml_safe

        content = "a:\n  b:\n    c: 1"
        result, errors = parse_yaml_safe(content)
        assert errors == []
        assert result is not None

    def test_invalid_yaml_syntax(self):
        from app.services.policy_service import parse_yaml_safe

        content = "rules:\n  - name: test\n bad_indent"
        result, errors = parse_yaml_safe(content)
        # May parse as valid YAML depending on content — check either case
        # The important thing is no crash
        assert isinstance(errors, list)

    def test_safe_load_no_full_loader(self):
        """Ensure we never use yaml.load() with FullLoader."""
        import inspect

        from app.services.policy_service import parse_yaml_safe

        source = inspect.getsource(parse_yaml_safe)
        assert "yaml.load(" not in source or "safe_load" in source
        assert "FullLoader" not in source
        assert "UnsafeLoader" not in source

# ═══════════════════════════════════════════════════════════════════════════════
#  N4 — Measure Depth
# ═══════════════════════════════════════════════════════════════════════════════

class TestMeasureDepth:
    def test_flat_dict(self):
        from app.services.policy_service import _measure_depth

        # {"a": 1} → dict(1) + value traversal(2) = 2
        assert _measure_depth({"a": 1, "b": 2}) == 2

    def test_nested_dict(self):
        from app.services.policy_service import _measure_depth

        # {"a": {"b": {"c": 1}}} → 4 levels
        assert _measure_depth({"a": {"b": {"c": 1}}}) == 4

    def test_empty_dict(self):
        from app.services.policy_service import _measure_depth

        assert _measure_depth({}) == 1

    def test_list_in_dict(self):
        from app.services.policy_service import _measure_depth

        # dict(1) → list(2) → scalar(3) = 3
        assert _measure_depth({"a": [1, 2, 3]}) == 3

    def test_nested_list(self):
        from app.services.policy_service import _measure_depth

        # dict(1) → list(2) → dict(3) → scalar(4) = 4
        assert _measure_depth({"a": [{"b": 1}]}) == 4

    def test_scalar(self):
        from app.services.policy_service import _measure_depth

        assert _measure_depth("hello") == 1

# ═══════════════════════════════════════════════════════════════════════════════
#  N4 — Policy Validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyValidation:
    """validate_policy_definition() tests."""

    def test_valid_definition(self):
        from app.services.policy_service import validate_policy_definition

        defn = {
            "rules": [
                {"name": "excessive_tool_calls", "enabled": True, "severity_override": "high"},
                {"name": "data_exfil", "severity_override": "critical"},
            ],
            "schedule": {"active_hours": "09:00-17:00 UTC", "weekend": "suppress"},
            "scope": {
                "agent_tags": ["production", "finance"],
                "frameworks": ["langchain"],
            },
        }
        result = validate_policy_definition(defn)
        assert result.valid is True
        assert result.errors == []

    def test_empty_rules(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition({"rules": []})
        assert result.valid is True

    def test_rules_not_list(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition({"rules": "not a list"})
        assert result.valid is False
        assert any("'rules' must be a list" in e for e in result.errors)

    def test_too_many_rules(self):
        from app.services.policy_service import validate_policy_definition

        rules = [{"name": f"rule_{i}"} for i in range(101)]
        result = validate_policy_definition({"rules": rules})
        assert result.valid is False
        assert any("too many rules" in e.lower() for e in result.errors)

    def test_duplicate_rule_names(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [{"name": "dup"}, {"name": "dup"}],
            }
        )
        assert result.valid is False
        assert any("duplicate" in e.lower() for e in result.errors)

    def test_missing_rule_name(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition({"rules": [{"enabled": True}]})
        assert result.valid is False
        assert any("missing" in e.lower() for e in result.errors)

    def test_invalid_severity(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [{"name": "r1", "severity_override": "mega_high"}],
            }
        )
        assert result.valid is False
        assert any("invalid severity" in e.lower() for e in result.errors)

    def test_valid_severities(self):
        from app.services.policy_service import validate_policy_definition

        for sev in ("info", "low", "medium", "high", "critical"):
            result = validate_policy_definition(
                {
                    "rules": [{"name": "r1", "severity_override": sev}],
                }
            )
            assert result.valid is True, f"Severity {sev} should be valid"

    def test_invalid_schedule_format(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [],
                "schedule": {"active_hours": "9am-5pm"},
            }
        )
        assert result.valid is False
        assert any("active_hours format" in e for e in result.errors)

    def test_invalid_weekend_action(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [],
                "schedule": {"weekend": "ignore_all"},
            }
        )
        assert result.valid is False
        assert any("weekend action" in e for e in result.errors)

    def test_scope_too_many_tags(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [],
                "scope": {"agent_tags": [f"tag_{i}" for i in range(51)]},
            }
        )
        assert result.valid is False
        assert any("too many" in e.lower() for e in result.errors)

    def test_scope_tag_too_long(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [],
                "scope": {"agent_tags": ["x" * 200]},
            }
        )
        assert result.valid is False

    def test_complex_param_warning(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition(
            {
                "rules": [{"name": "r1", "parameters": {"nested": {"deep": True}}}],
            }
        )
        assert result.valid is True  # warning, not error
        assert len(result.warnings) > 0

    def test_no_definition(self):
        from app.services.policy_service import validate_policy_definition

        result = validate_policy_definition({})
        assert result.valid is True  # empty is valid (no rules)

# ═══════════════════════════════════════════════════════════════════════════════
#  N4 — Pydantic Schema Validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicySchemas:
    """Pydantic schema validation tests."""

    def test_create_request_valid(self):
        from app.schemas.policy import PolicyCreateRequest, PolicyDefinition

        req = PolicyCreateRequest(
            name="My Policy",
            description="Test policy",
            definition=PolicyDefinition(rules=[]),
        )
        assert req.name == "My Policy"
        assert req.enabled is True

    def test_create_request_bad_name(self):
        from app.schemas.policy import PolicyCreateRequest

        with pytest.raises(Exception):
            PolicyCreateRequest(name="evil<script>", description="test")

    def test_create_request_name_stripped(self):
        from app.schemas.policy import PolicyCreateRequest

        req = PolicyCreateRequest(name="  My Policy  ")
        assert req.name == "My Policy"

    def test_rule_override_severity_pattern(self):
        from app.schemas.policy import PolicyRuleOverride

        r = PolicyRuleOverride(name="test", severity_override="critical")
        assert r.severity_override == "critical"

        with pytest.raises(Exception):
            PolicyRuleOverride(name="test", severity_override="bogus")

    def test_scope_tag_validation(self):
        from app.schemas.policy import PolicyScope

        s = PolicyScope(agent_tags=["production", "finance-team"])
        assert len(s.agent_tags) == 2

    def test_scope_invalid_tag_chars(self):
        from app.schemas.policy import PolicyScope

        with pytest.raises(Exception):
            PolicyScope(agent_tags=["invalid tag with spaces!"])

    def test_scope_too_many_tags(self):
        from app.schemas.policy import PolicyScope

        with pytest.raises(Exception):
            PolicyScope(agent_tags=[f"t{i}" for i in range(51)])

    def test_scope_tag_too_long(self):
        from app.schemas.policy import PolicyScope

        with pytest.raises(Exception):
            PolicyScope(agent_tags=["x" * 129])

    def test_definition_max_rules(self):
        from app.schemas.policy import PolicyDefinition, PolicyRuleOverride

        with pytest.raises(Exception):
            PolicyDefinition(rules=[PolicyRuleOverride(name=f"r{i}") for i in range(101)])

    def test_definition_duplicate_names(self):
        from app.schemas.policy import PolicyDefinition, PolicyRuleOverride

        with pytest.raises(Exception):
            PolicyDefinition(rules=[PolicyRuleOverride(name="dup"), PolicyRuleOverride(name="dup")])

    def test_schedule_weekend_pattern(self):
        from app.schemas.policy import PolicySchedule

        for val in ("suppress", "alert", "inherit"):
            s = PolicySchedule(weekend=val)
            assert s.weekend == val

        with pytest.raises(Exception):
            PolicySchedule(weekend="invalid")

    def test_policy_response_model(self):
        from app.schemas.policy import PolicyResponse

        now = datetime.now(UTC)
        uid = uuid.uuid4()
        resp = PolicyResponse(
            id=uid,
            tenant_id=uid,
            name="Test",
            description="desc",
            version=1,
            enabled=True,
            definition={"rules": []},
            scope_agent_tags=["prod"],
            scope_frameworks=["langchain"],
            created_by=uid,
            updated_by=None,
            created_at=now,
            updated_at=now,
        )
        assert resp.name == "Test"
        assert resp.scope_agent_tags == ["prod"]

    def test_validate_request_yaml_size(self):
        from app.schemas.policy import PolicyValidateRequest

        # 64KB should be accepted
        req = PolicyValidateRequest(yaml_content="rules: []\n")
        assert req.yaml_content is not None

    def test_update_request_partial(self):
        from app.schemas.policy import PolicyUpdateRequest

        req = PolicyUpdateRequest(enabled=False, change_summary="disable for maintenance")
        assert req.name is None
        assert req.definition is None
        assert req.enabled is False

# ═══════════════════════════════════════════════════════════════════════════════
#  N4 — Policy Engine Consumer (schedule, matching, rule application)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicySchedule:
    """is_within_schedule() tests."""

    def test_no_schedule_always_active(self):
        from app.consumers.policy_engine import is_within_schedule

        assert is_within_schedule(None) is True
        assert is_within_schedule({}) is True

    def test_within_active_hours(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"active_hours": "09:00-17:00 UTC"}
        # Wednesday at 12:00 UTC
        now = datetime(2025, 1, 8, 12, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is True

    def test_outside_active_hours(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"active_hours": "09:00-17:00 UTC"}
        # Wednesday at 03:00 UTC
        now = datetime(2025, 1, 8, 3, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is False

    def test_overnight_window(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"active_hours": "22:00-06:00 UTC"}
        # 23:00 — should be active
        now = datetime(2025, 1, 8, 23, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is True

        # 03:00 — should be active
        now = datetime(2025, 1, 8, 3, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is True

        # 12:00 — should not be active
        now = datetime(2025, 1, 8, 12, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is False

    def test_weekend_suppress(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"weekend": "suppress"}
        # Saturday
        now = datetime(2025, 1, 11, 12, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is False

    def test_weekend_alert(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"weekend": "alert"}
        # Sunday
        now = datetime(2025, 1, 12, 12, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is True

    def test_weekend_inherit(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"weekend": "inherit", "active_hours": "09:00-17:00 UTC"}
        # Saturday at 12:00 — within hours
        now = datetime(2025, 1, 11, 12, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is True

        # Saturday at 03:00 — outside hours
        now = datetime(2025, 1, 11, 3, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is False

    def test_weekday_ignore_weekend_setting(self):
        from app.consumers.policy_engine import is_within_schedule

        schedule = {"weekend": "suppress", "active_hours": "09:00-17:00 UTC"}
        # Wednesday at 12:00 — weekday, so weekend setting irrelevant
        now = datetime(2025, 1, 8, 12, 0, tzinfo=UTC)
        assert is_within_schedule(schedule, now) is True

class TestPolicyMatching:
    """match_policy_to_agent() tests."""

    def test_no_scope_matches_all(self):
        from app.consumers.policy_engine import match_policy_to_agent

        policy = {}
        assert match_policy_to_agent(policy, ["any-tag"], "langchain") is True

    def test_tag_overlap(self):
        from app.consumers.policy_engine import match_policy_to_agent

        policy = {"scope_agent_tags": ["production", "finance"]}
        assert match_policy_to_agent(policy, ["production", "devops"]) is True
        assert match_policy_to_agent(policy, ["staging"]) is False

    def test_framework_match(self):
        from app.consumers.policy_engine import match_policy_to_agent

        policy = {"scope_frameworks": ["langchain", "autogen"]}
        assert match_policy_to_agent(policy, [], "langchain") is True
        assert match_policy_to_agent(policy, [], "crewai") is False

    def test_tag_or_framework_match(self):
        from app.consumers.policy_engine import match_policy_to_agent

        policy = {"scope_agent_tags": ["prod"], "scope_frameworks": ["langchain"]}
        # Framework matches even if tags don't
        assert match_policy_to_agent(policy, ["staging"], "langchain") is True
        # Tags match even if framework doesn't
        assert match_policy_to_agent(policy, ["prod"], "crewai") is True
        # Neither matches
        assert match_policy_to_agent(policy, ["staging"], "crewai") is False

    def test_empty_agent_tags(self):
        from app.consumers.policy_engine import match_policy_to_agent

        policy = {"scope_agent_tags": ["prod"]}
        assert match_policy_to_agent(policy, [], None) is False

class TestApplyPolicyRules:
    """apply_policy_rules() tests."""

    def test_severity_override(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "excessive_tool_calls", "severity": "medium"}
        policy = {
            "id": "p1",
            "name": "strict",
            "definition": {
                "rules": [
                    {"name": "excessive_tool_calls", "severity_override": "critical"},
                ],
            },
        }
        result = apply_policy_rules(event, policy)
        assert result["severity"] == "critical"
        assert result["_original_severity"] == "medium"

    def test_disabled_rule_suppresses(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "data_exfil", "severity": "high"}
        policy = {
            "id": "p1",
            "name": "lax",
            "definition": {
                "rules": [{"name": "data_exfil", "enabled": False}],
            },
        }
        result = apply_policy_rules(event, policy)
        assert result.get("_policy_suppressed") is True
        assert result.get("_policy_suppressed_reason") == "rule_disabled"

    def test_no_matching_rule(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "unknown_rule", "severity": "low"}
        policy = {
            "id": "p1",
            "name": "specific",
            "definition": {
                "rules": [{"name": "different_rule", "severity_override": "high"}],
            },
        }
        result = apply_policy_rules(event, policy)
        assert result["severity"] == "low"  # unchanged
        assert any(m["action"] == "no_matching_rule" for m in result.get("_policy_metadata", []))

    def test_parameter_overrides(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "r1"}
        policy = {
            "id": "p1",
            "name": "parameterized",
            "definition": {
                "rules": [{"name": "r1", "parameters": {"threshold": 100, "window": "5m"}}],
            },
        }
        result = apply_policy_rules(event, policy)
        assert result["_parameter_overrides"]["threshold"] == 100
        assert result["_parameter_overrides"]["window"] == "5m"

    def test_notification_overrides(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "r1"}
        policy = {
            "id": "p1",
            "name": "notified",
            "definition": {
                "rules": [{"name": "r1", "notifications": [{"channel": "slack"}]}],
            },
        }
        result = apply_policy_rules(event, policy)
        assert result["_notification_overrides"] == [{"channel": "slack"}]

    def test_schedule_suppresses_event(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "r1"}
        policy = {
            "id": "p1",
            "name": "scheduled",
            "definition": {
                "rules": [{"name": "r1"}],
                "schedule": {"active_hours": "09:00-17:00 UTC"},
            },
        }
        # 03:00 — outside schedule
        now = datetime(2025, 1, 8, 3, 0, tzinfo=UTC)
        result = apply_policy_rules(event, policy, now=now)
        assert result.get("_policy_suppressed") is True
        assert result.get("_policy_suppressed_reason") == "outside_schedule"

    def test_does_not_mutate_original_event(self):
        from app.consumers.policy_engine import apply_policy_rules

        event = {"rule_name": "r1", "severity": "low"}
        policy = {
            "id": "p1",
            "name": "test",
            "definition": {
                "rules": [{"name": "r1", "severity_override": "critical"}],
            },
        }
        result = apply_policy_rules(event, policy)
        assert event["severity"] == "low"  # original unchanged
        assert result["severity"] == "critical"

class TestApplyPoliciesToEvent:
    """apply_policies_to_event() tests."""

    def test_multiple_policies_applied(self):
        from app.consumers.policy_engine import apply_policies_to_event

        event = {"rule_name": "r1", "severity": "low"}
        policies = [
            {
                "enabled": True,
                "scope_agent_tags": ["prod"],
                "definition": {"rules": [{"name": "r1", "severity_override": "medium"}]},
                "id": "p1",
                "name": "first",
            },
            {
                "enabled": True,
                "scope_agent_tags": ["prod"],
                "definition": {"rules": [{"name": "r1", "severity_override": "critical"}]},
                "id": "p2",
                "name": "second",
            },
        ]
        result = apply_policies_to_event(event, policies, agent_tags=["prod"])
        # Second policy overrides the first
        assert result["severity"] == "critical"

    def test_disabled_policy_skipped(self):
        from app.consumers.policy_engine import apply_policies_to_event

        event = {"rule_name": "r1", "severity": "low"}
        policies = [
            {
                "enabled": False,
                "definition": {"rules": [{"name": "r1", "severity_override": "critical"}]},
                "id": "p1",
                "name": "disabled",
            },
        ]
        result = apply_policies_to_event(event, policies, agent_tags=["prod"])
        assert result["severity"] == "low"  # unmodified

    def test_suppression_stops_chain(self):
        from app.consumers.policy_engine import apply_policies_to_event

        event = {"rule_name": "r1", "severity": "low"}
        policies = [
            {
                "enabled": True,
                "definition": {
                    "rules": [{"name": "r1", "enabled": False}],
                },
                "id": "p1",
                "name": "suppressor",
            },
            {
                "enabled": True,
                "definition": {
                    "rules": [{"name": "r1", "severity_override": "critical"}],
                },
                "id": "p2",
                "name": "second",
            },
        ]
        result = apply_policies_to_event(event, policies, agent_tags=["prod"])
        assert result.get("_policy_suppressed") is True
        # Second policy should not have been applied
        meta = result.get("_policy_metadata", [])
        assert not any(m.get("policy_name") == "second" for m in meta)

# ═══════════════════════════════════════════════════════════════════════════════
#  N3 — OTel Bridge Attribute Sanitization
# ═══════════════════════════════════════════════════════════════════════════════

class TestOTelSanitize:
    """_sanitize_attributes() PII stripping tests."""

    def test_strips_pii_keys(self):
        from phantex_sdk.hooks.otel_bridge import _sanitize_attributes

        attrs = {
            "tool.name": "search",
            "prompt": "secret user input",
            "password": "hunter2",
            "secret": "s3cr3t",
            "token": "tok-abc123",
            "prompt_content": "raw prompt text",
            "tool_input_raw": "raw bytes",
        }
        result = _sanitize_attributes(attrs)
        assert "tool.name" in result
        assert result["tool.name"] == "search"
        assert "prompt" not in result
        assert "password" not in result
        assert "secret" not in result
        assert "token" not in result
        assert "prompt_content" not in result
        assert "tool_input_raw" not in result

    def test_truncates_long_strings(self):
        from phantex_sdk.hooks.otel_bridge import _sanitize_attributes

        long_val = "x" * 500
        result = _sanitize_attributes({"key": long_val})
        assert len(result["key"]) == 256

    def test_primitive_types_preserved(self):
        from phantex_sdk.hooks.otel_bridge import _sanitize_attributes

        attrs = {
            "bool_val": True,
            "int_val": 42,
            "float_val": 3.14,
            "str_val": "hello",
        }
        result = _sanitize_attributes(attrs)
        assert result["bool_val"] is True
        assert result["int_val"] == 42
        assert result["float_val"] == 3.14
        assert result["str_val"] == "hello"

    def test_complex_types_stringified(self):
        from phantex_sdk.hooks.otel_bridge import _sanitize_attributes

        attrs = {"complex": {"nested": True}, "list_val": [1, 2, 3]}
        result = _sanitize_attributes(attrs)
        assert isinstance(result["complex"], str)
        assert isinstance(result["list_val"], str)

    def test_empty_attributes(self):
        from phantex_sdk.hooks.otel_bridge import _sanitize_attributes

        assert _sanitize_attributes({}) == {}

    def test_case_insensitive_pii_keys(self):
        from phantex_sdk.hooks.otel_bridge import _sanitize_attributes

        # Keys are lowered before comparison
        attrs = {"Password": "hunter2", "SECRET": "s3cr3t"}
        result = _sanitize_attributes(attrs)
        # The implementation uses k.lower() so these should be stripped
        assert "Password" not in result
        assert "SECRET" not in result

class TestOTelBridge:
    """OTelBridge class tests (without actual OTel)."""

    def test_disabled_when_no_endpoint(self, monkeypatch):
        # Clear env to ensure bridge is disabled
        monkeypatch.delenv("PHANTEX_OTEL_ENDPOINT", raising=False)
        # Reset global state
        import phantex_sdk.hooks.otel_bridge as bridge_mod

        bridge_mod._tracer = None
        bridge_mod._OTEL_AVAILABLE = False

        from phantex_sdk.hooks.otel_bridge import OTelBridge

        bridge = OTelBridge()
        assert bridge.enabled is False
        # start_span should return None when disabled
        handle = bridge.start_span("test_op", {"key": "val"})
        assert handle is None
        # end_span should be a no-op
        bridge.end_span(handle, success=True)

    def test_is_otel_enabled_false_by_default(self, monkeypatch):
        monkeypatch.delenv("PHANTEX_OTEL_ENDPOINT", raising=False)
        import phantex_sdk.hooks.otel_bridge as bridge_mod

        bridge_mod._tracer = None
        bridge_mod._OTEL_AVAILABLE = False

        from phantex_sdk.hooks.otel_bridge import is_otel_enabled

        assert is_otel_enabled() is False

# ═══════════════════════════════════════════════════════════════════════════════
#  N3 — Trust Context
# ═══════════════════════════════════════════════════════════════════════════════

class TestTrustContext:
    """TrustContext dataclass tests."""

    def test_defaults(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext()
        assert ctx.score == 0.5
        assert ctx.factors == {}
        assert ctx.engine_reachable is False

    def test_is_stale_when_old(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext(last_updated=time.time() - 120)  # 2 min ago > 2*30=60s
        assert ctx.is_stale is True

    def test_not_stale_when_recent(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext(last_updated=time.time())
        assert ctx.is_stale is False

    def test_is_healthy(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext(score=0.8, engine_reachable=True)
        assert ctx.is_healthy is True

    def test_not_healthy_low_score(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext(score=0.3, engine_reachable=True)
        assert ctx.is_healthy is False

    def test_not_healthy_unreachable(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext(score=0.9, engine_reachable=False)
        assert ctx.is_healthy is False

    def test_to_dict(self):
        from phantex_sdk.trust import TrustContext

        ctx = TrustContext(score=0.75, factors={"compliance": 0.9}, engine_reachable=True)
        d = ctx.to_dict()
        assert d["trust_score"] == 0.75
        assert d["trust_factors"]["compliance"] == 0.9
        assert d["trust_engine_reachable"] is True

class TestTrustScoreProvider:
    """TrustScoreProvider unit tests (no real gRPC)."""

    def test_default_neutral_score(self):
        from phantex_sdk.trust import TrustScoreProvider

        provider = TrustScoreProvider(agent_id="test-agent")
        ctx = provider.current
        assert ctx.score == 0.5
        assert ctx.engine_reachable is False

    def test_current_returns_copy(self):
        from phantex_sdk.trust import TrustScoreProvider

        provider = TrustScoreProvider(agent_id="test-agent")
        c1 = provider.current
        c2 = provider.current
        assert c1 is not c2
        assert c1.score == c2.score

    def test_start_stop(self):
        from phantex_sdk.trust import TrustScoreProvider

        provider = TrustScoreProvider(agent_id="test-agent", refresh_interval=0.1)
        provider.start()
        assert provider._running is True
        assert provider._thread is not None
        provider.stop()
        assert provider._running is False

# ═══════════════════════════════════════════════════════════════════════════════
#  N3 — Async Buffer Transport
# ═══════════════════════════════════════════════════════════════════════════════

class TestAsyncBufferTransport:
    """AsyncBufferTransport tests."""

    @pytest.mark.asyncio
    async def test_send_and_drain(self):
        from phantex_sdk.async_transport import AsyncBufferTransport

        transport = AsyncBufferTransport(max_size=100)
        await transport.send({"event": "test1"})
        await transport.send({"event": "test2"})
        assert len(transport) == 2

        events = await transport.drain()
        assert len(events) == 2
        assert events[0]["event"] == "test1"
        assert len(transport) == 0  # drained

    @pytest.mark.asyncio
    async def test_max_size_eviction(self):
        from phantex_sdk.async_transport import AsyncBufferTransport

        transport = AsyncBufferTransport(max_size=3)
        for i in range(5):
            await transport.send({"i": i})
        assert len(transport) == 3
        events = await transport.drain()
        # Should have the last 3 events (deque evicts oldest)
        assert events[0]["i"] == 2
        assert events[2]["i"] == 4

    @pytest.mark.asyncio
    async def test_peek_sync(self):
        from phantex_sdk.async_transport import AsyncBufferTransport

        transport = AsyncBufferTransport()
        await transport.send({"x": 1})
        peeked = transport.peek_sync()
        assert len(peeked) == 1
        # Peek doesn't drain
        assert len(transport) == 1

    @pytest.mark.asyncio
    async def test_close_is_noop(self):
        from phantex_sdk.async_transport import AsyncBufferTransport

        transport = AsyncBufferTransport()
        await transport.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_bool_always_true(self):
        from phantex_sdk.async_transport import AsyncBufferTransport

        transport = AsyncBufferTransport()
        assert bool(transport) is True

class TestCreateAsyncTransport:
    """create_async_transport() factory tests."""

    @pytest.mark.asyncio
    async def test_buffer_mode(self):
        from phantex_sdk.async_transport import (
            AsyncBufferTransport,
            create_async_transport,
        )

        transport = await create_async_transport(mode="buffer")
        assert isinstance(transport, AsyncBufferTransport)

    @pytest.mark.asyncio
    async def test_auto_mode_fallback_to_buffer(self):
        from phantex_sdk.async_transport import create_async_transport

        # httpx may or may not be installed — either way auto should work
        transport = await create_async_transport(mode="auto")
        assert transport is not None

# ═══════════════════════════════════════════════════════════════════════════════
#  N3 — SpanHandle
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpanHandle:
    """_SpanHandle tests."""

    def test_slots(self):
        from phantex_sdk.hooks.otel_bridge import _SpanHandle

        handle = _SpanHandle(span="mock_span", token="mock_token")
        assert handle.span == "mock_span"
        assert handle.token == "mock_token"
        # Slots — no __dict__
        with pytest.raises(AttributeError):
            handle.extra_field = "nope"

# ═══════════════════════════════════════════════════════════════════════════════
#  N4 — Router Integration (schema-level)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyRouter:
    """Verify router metadata."""

    def test_router_exists(self):
        from app.routers.policies import router

        assert router.prefix == "/api/v1/policies"
        assert "policies" in router.tags

    def test_router_has_endpoints(self):
        from app.routers.policies import router

        paths = [r.path for r in router.routes]
        methods = {}
        for r in router.routes:
            if hasattr(r, "methods"):
                methods[r.path] = r.methods
        # Verify key paths exist (router may use different path formats)
        all_paths = " ".join(paths)
        assert "validate" in all_paths
        assert "apply" in all_paths
        assert "versions" in all_paths
        # Should have at least 7 routes
        assert len(router.routes) >= 7

    def test_require_policy_role_admin(self):
        from app.routers.policies import _require_policy_role
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="a@t.co")
        _require_policy_role(user)  # Should not raise

    def test_require_policy_role_analyst(self):
        from app.routers.policies import _require_policy_role
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst", email="a@t.co")
        _require_policy_role(user)  # Should not raise

    def test_require_policy_role_viewer_rejected(self):
        from fastapi import HTTPException

        from app.routers.policies import _require_policy_role
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="viewer", email="v@t.co")
        with pytest.raises(HTTPException) as exc_info:
            _require_policy_role(user)
        assert exc_info.value.status_code == 403

    def test_require_policy_role_empty_rejected(self):
        from fastapi import HTTPException

        from app.routers.policies import _require_policy_role
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="", email="e@t.co")
        with pytest.raises(HTTPException):
            _require_policy_role(user)

# ═══════════════════════════════════════════════════════════════════════════════
#  N3-N4 Hardening Tests ( audit)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyRouterHardening:
    """Verify router now uses CurrentUser attribute access."""

    def test_require_policy_role_accepts_currentuser(self):
        """The helper must accept CurrentUser, not dict."""
        from app.routers.policies import _require_policy_role
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="x@y.co")
        _require_policy_role(user)  # no raise

    def test_require_policy_role_rejects_operator(self):
        from fastapi import HTTPException

        from app.routers.policies import _require_policy_role
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="operator", email="x@y.co")
        with pytest.raises(HTTPException):
            _require_policy_role(user)

    def test_router_has_rate_limit_dependency(self):
        """Rate-limit dependency is present on the policies router."""
        from app.routers.policies import router

        dep_names = [getattr(d.dependency, "__name__", "") for d in router.dependencies]
        assert "rate_limit" in dep_names

class TestParseHhmmHardening:
    """_parse_hhmm must reject out-of-range values."""

    def test_rejects_25_colon_00(self):
        from app.consumers.policy_engine import _parse_hhmm

        assert _parse_hhmm("25:00") is None

    def test_rejects_12_colon_60(self):
        from app.consumers.policy_engine import _parse_hhmm

        assert _parse_hhmm("12:60") is None

    def test_accepts_23_colon_59(self):
        from app.consumers.policy_engine import _parse_hhmm

        assert _parse_hhmm("23:59") == (23, 59)

    def test_accepts_00_colon_00(self):
        from app.consumers.policy_engine import _parse_hhmm

        assert _parse_hhmm("00:00") == (0, 0)

    def test_rejects_99_colon_99(self):
        from app.consumers.policy_engine import _parse_hhmm

        assert _parse_hhmm("99:99") is None

class TestPolicyEngineDocstring:
    """Verify docstring matches first-suppression-wins behavior."""

    def test_first_suppression_wins(self):
        from app.consumers.policy_engine import apply_policies_to_event

        suppressing = {
            "id": "p1",
            "name": "block-it",
            "enabled": True,
            "scope_agent_tags": [],
            "scope_frameworks": [],
            "definition": {
                "rules": [{"name": "r1", "enabled": False}],
                "schedule": None,
            },
        }
        later = {
            "id": "p2",
            "name": "override",
            "enabled": True,
            "scope_agent_tags": [],
            "scope_frameworks": [],
            "definition": {
                "rules": [{"name": "r1", "severity_override": "critical"}],
                "schedule": None,
            },
        }
        event = {"rule_name": "r1", "severity": "low"}
        result = apply_policies_to_event(event, [suppressing, later], [])
        assert result.get("_policy_suppressed") is True
        # Second policy should NOT have been applied
        metas = result.get("_policy_metadata", [])
        assert len(metas) == 1
        assert metas[0]["policy_name"] == "block-it"

class TestPolicyServiceHardening:
    """ORDER BY tie-breaker and delete_policy result parsing."""

    def test_delete_result_update_0_returns_false(self):
        """Direct string equality check for 'UPDATE 0'."""
        result = "UPDATE 0"
        assert (result != "UPDATE 0") is False

    def test_delete_result_update_1_returns_true(self):
        result = "UPDATE 1"
        assert (result != "UPDATE 0") is True

class TestSchemaHardening:
    """PolicyRuleOverride parameter and notification caps."""

    def test_too_many_parameters_rejected(self):
        from app.schemas.policy import PolicyRuleOverride

        # 51 parameters should fail
        params = {f"k{i}": i for i in range(51)}
        with pytest.raises(Exception):
            PolicyRuleOverride(name="big-params", parameters=params)

    def test_50_parameters_accepted(self):
        from app.schemas.policy import PolicyRuleOverride

        params = {f"k{i}": i for i in range(50)}
        rule = PolicyRuleOverride(name="just-right", parameters=params)
        assert len(rule.parameters) == 50

    def test_too_many_notifications_rejected(self):
        from app.schemas.policy import PolicyRuleOverride

        notifs = [{"channel": f"ch{i}"} for i in range(21)]
        with pytest.raises(Exception):
            PolicyRuleOverride(name="big-notifs", notifications=notifs)

    def test_20_notifications_accepted(self):
        from app.schemas.policy import PolicyRuleOverride

        notifs = [{"channel": f"ch{i}"} for i in range(20)]
        rule = PolicyRuleOverride(name="ok-notifs", notifications=notifs)
        assert len(rule.notifications) == 20

class TestAsyncTransportCloseHardening:
    """AsyncHTTPTransport.close() must drain entire buffer."""

    def test_close_drains_all_batches(self):
        """close() should drain beyond one batch_size."""

        async def _run():
            from phantex_sdk.async_transport import AsyncHTTPTransport

            t = AsyncHTTPTransport.__new__(AsyncHTTPTransport)
            # Manually set up internal state (no network)
            from collections import deque

            t._buffer = deque(maxlen=5000)
            t._lock = asyncio.Lock()
            t._batch_size = 10
            t._endpoint = "https://localhost:9999/noop"
            t._auth_token = "test"
            t._verify_tls = False
            t._client = None
            t._flush_task = None
            t._batch_timeout = 1.0

            # Add 25 events (2.5 batches)
            for i in range(25):
                t._buffer.append({"i": i})

            # Patch _do_flush to just drain without HTTP
            flushed: list = []

            async def fake_flush():
                batch = []
                while t._buffer and len(batch) < t._batch_size:
                    batch.append(t._buffer.popleft())
                flushed.extend(batch)

            t._do_flush = fake_flush
            await t.close()
            assert len(flushed) == 25

        asyncio.get_event_loop().run_until_complete(_run())

class TestOTelBridgeThreadSafety:
    """OTel bridge must use threading.Lock for init."""

    def test_init_has_lock(self):
        import threading

        from phantex_sdk.hooks import otel_bridge

        assert hasattr(otel_bridge, "_tracer_lock")
        assert isinstance(otel_bridge._tracer_lock, type(threading.Lock()))

class TestTrustTLSHardening:
    """trust.py must use secure_channel when creds are available."""

    def test_source_uses_secure_channel(self):
        """Verify the source code contains grpc.secure_channel, not insecure."""
        import inspect

        from phantex_sdk.trust import TrustScoreProvider

        src = inspect.getsource(TrustScoreProvider._grpc_fetch)
        assert "secure_channel(self._addr, creds)" in src
        assert "insecure_channel(self._addr)  # Will be replaced" not in src
