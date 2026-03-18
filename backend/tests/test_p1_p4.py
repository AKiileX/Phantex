# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests — Block P1-P4: Agent Tagging & Policy.

P1: tags_match engine, tag validation schemas
P2: Rule exemption logic (create, expire, hit-count, check)
P3: Tag-based alert routing evaluation
P4: Cron parsing, maintenance window active check, suppression
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _uid() -> uuid.UUID:
    return uuid.uuid4()

# ══════════════════════════════════════════════════════════════════════════════
#  P1: Tag matching engine
# ══════════════════════════════════════════════════════════════════════════════

class TestTagsMatch:
    """Unit tests for tags_match()."""

    def test_empty_match_tags_matches_all(self):
        from app.services.agent_policy_service import tags_match

        assert tags_match({"env": "prod"}, {}) is True
        assert tags_match({}, {}) is True

    def test_exact_key_value(self):
        from app.services.agent_policy_service import tags_match

        assert tags_match({"env": "prod", "team": "ml"}, {"env": "prod"}) is True

    def test_missing_key_no_match(self):
        from app.services.agent_policy_service import tags_match

        assert tags_match({"env": "prod"}, {"role": "ci-runner"}) is False

    def test_value_mismatch(self):
        from app.services.agent_policy_service import tags_match

        assert tags_match({"env": "staging"}, {"env": "prod"}) is False

    def test_case_insensitive(self):
        from app.services.agent_policy_service import tags_match

        assert tags_match({"ENV": "Prod"}, {"env": "prod"}) is False  # keys are exact
        assert tags_match({"env": "Prod"}, {"env": "prod"}) is True  # values case-insensitive

    def test_multiple_conditions_all_must_match(self):
        from app.services.agent_policy_service import tags_match

        tags = {"env": "prod", "team": "ml", "region": "us"}
        assert tags_match(tags, {"env": "prod", "team": "ml"}) is True
        assert tags_match(tags, {"env": "prod", "team": "infra"}) is False

    def test_empty_agent_tags_with_nonempty_match(self):
        from app.services.agent_policy_service import tags_match

        assert tags_match({}, {"env": "prod"}) is False

# ══════════════════════════════════════════════════════════════════════════════
#  P1: Agent tag schemas
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentTagSchemas:
    """Validation rules for tag update schemas."""

    def test_valid_tags(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        obj = AgentTagsUpdate(tags={"env": "prod", "team": "ml"})
        assert obj.tags["env"] == "prod"

    def test_invalid_key_chars(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        with pytest.raises(Exception):
            AgentTagsUpdate(tags={"inv@lid": "value"})

    def test_key_too_long(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        with pytest.raises(Exception):
            AgentTagsUpdate(tags={"a" * 65: "value"})

    def test_value_too_long(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        with pytest.raises(Exception):
            AgentTagsUpdate(tags={"key": "x" * 257})

    def test_too_many_tags(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        many = {f"key_{i}": "v" for i in range(51)}
        with pytest.raises(Exception):
            AgentTagsUpdate(tags=many)

    def test_empty_tags_ok(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        obj = AgentTagsUpdate(tags={})
        assert obj.tags == {}

    def test_dots_hyphens_underscores_allowed(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        obj = AgentTagsUpdate(tags={"my-tag.v1_key": "val"})
        assert "my-tag.v1_key" in obj.tags

# ══════════════════════════════════════════════════════════════════════════════
#  P2: Exemption schemas
# ══════════════════════════════════════════════════════════════════════════════

class TestExemptionSchemas:
    def test_create_valid(self):
        from app.schemas.agent_policy import ExemptionCreate

        obj = ExemptionCreate(
            rule_name="dns_exfil",
            match_tags={"env": "ci"},
            reason="CI agents are expected to make DNS queries",
        )
        assert obj.rule_name == "dns_exfil"

    def test_create_requires_reason(self):
        from app.schemas.agent_policy import ExemptionCreate

        with pytest.raises(Exception):
            ExemptionCreate(
                rule_name="dns_exfil",
                match_tags={"env": "ci"},
                reason="",  # too short
            )

    def test_create_empty_match_tags_rejected(self):
        from app.schemas.agent_policy import ExemptionCreate

        with pytest.raises(Exception):
            ExemptionCreate(
                rule_name="dns_exfil",
                match_tags={},
                reason="some reason",
            )

    def test_update_partial(self):
        from app.schemas.agent_policy import ExemptionUpdate

        obj = ExemptionUpdate(enabled=False)
        data = obj.model_dump(exclude_unset=True)
        assert data == {"enabled": False}

# ══════════════════════════════════════════════════════════════════════════════
#  P3: Routing rule schemas
# ══════════════════════════════════════════════════════════════════════════════

class TestRoutingSchemas:
    def test_create_valid(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        obj = RoutingRuleCreate(
            name="crit-prod",
            match_tags={"env": "prod"},
            severity_min="high",
            channels=["pagerduty-main"],
        )
        assert obj.priority == 0
        assert obj.severity_min == "high"

    def test_invalid_severity(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(
                name="test",
                channels=["slack"],
                severity_min="banana",
            )

    def test_empty_channels_rejected(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(name="test", channels=[], severity_min="info")

# ══════════════════════════════════════════════════════════════════════════════
#  P3: Routing evaluation engine
# ══════════════════════════════════════════════════════════════════════════════

class TestRoutingEvaluation:
    """Unit tests for evaluate_tag_routing()."""

    def _make_rule(self, **kwargs):
        """Build a mock AlertRoutingRule-like object."""
        from types import SimpleNamespace

        defaults = {
            "enabled": True,
            "match_tags": {},
            "severity_min": "info",
            "channels": ["slack-ch"],
            "priority": 0,
        }
        defaults.update(kwargs)
        return SimpleNamespace(**defaults)

    def test_no_rules(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        assert evaluate_tag_routing({"env": "prod"}, "critical", []) == []

    def test_match_all(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        rule = self._make_rule(match_tags={}, channels=["pagerduty"])
        assert evaluate_tag_routing({"env": "prod"}, "high", [rule]) == ["pagerduty"]

    def test_severity_filter(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        rule = self._make_rule(severity_min="critical", channels=["pagerduty"])
        # "high" < "critical" → no match
        assert evaluate_tag_routing({"env": "prod"}, "high", [rule]) == []
        assert evaluate_tag_routing({"env": "prod"}, "critical", [rule]) == ["pagerduty"]

    def test_tag_filter(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        rule = self._make_rule(match_tags={"env": "prod"}, channels=["slack"])
        assert evaluate_tag_routing({"env": "prod"}, "info", [rule]) == ["slack"]
        assert evaluate_tag_routing({"env": "staging"}, "info", [rule]) == []

    def test_dedup_channels(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        r1 = self._make_rule(match_tags={}, channels=["slack", "pagerduty"])
        r2 = self._make_rule(match_tags={}, channels=["slack", "email"])
        result = evaluate_tag_routing({}, "info", [r1, r2])
        assert result == ["slack", "pagerduty", "email"]

    def test_disabled_rule_skipped(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        rule = self._make_rule(enabled=False, channels=["slack"])
        assert evaluate_tag_routing({}, "critical", [rule]) == []

    def test_multiple_tag_conditions(self):
        from app.services.agent_policy_service import evaluate_tag_routing

        rule = self._make_rule(
            match_tags={"env": "prod", "team": "ml"},
            channels=["pagerduty"],
        )
        assert evaluate_tag_routing({"env": "prod", "team": "ml"}, "info", [rule]) == ["pagerduty"]
        assert evaluate_tag_routing({"env": "prod", "team": "infra"}, "info", [rule]) == []

# ══════════════════════════════════════════════════════════════════════════════
#  P4: Cron parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestCronParsing:
    def test_every_minute(self):
        from app.services.agent_policy_service import compute_next_cron

        after = datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC)
        result = compute_next_cron("* * * * *", after)
        assert result is not None
        assert result == datetime(2025, 1, 15, 10, 31, 0, tzinfo=UTC)

    def test_specific_time(self):
        from app.services.agent_policy_service import compute_next_cron

        after = datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC)
        result = compute_next_cron("0 2 * * *", after)
        assert result is not None
        assert result.hour == 2
        assert result.minute == 0
        assert result.day >= 16  # next 2:00 AM is next day

    def test_step_expression(self):
        from app.services.agent_policy_service import compute_next_cron

        after = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
        result = compute_next_cron("*/15 * * * *", after)
        assert result is not None
        assert result.minute in (0, 15, 30, 45)

    def test_invalid_cron(self):
        from app.services.agent_policy_service import compute_next_cron

        assert compute_next_cron("not a cron") is None
        assert compute_next_cron("* * *") is None
        assert compute_next_cron("") is None

    def test_range_expression(self):
        from app.services.agent_policy_service import compute_next_cron

        after = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
        result = compute_next_cron("0 9-17 * * *", after)
        assert result is not None
        assert 9 <= result.hour <= 17

# ══════════════════════════════════════════════════════════════════════════════
#  P4: Maintenance window active check
# ══════════════════════════════════════════════════════════════════════════════

class TestMaintenanceWindowActive:
    def _make_window(self, **kwargs):
        from types import SimpleNamespace

        defaults = {
            "enabled": True,
            "force_ended_by": None,
            "last_started_at": None,
            "last_ended_at": None,
            "duration_minutes": 60,
        }
        defaults.update(kwargs)
        return SimpleNamespace(**defaults)

    def test_not_started(self):
        from app.services.agent_policy_service import is_window_active

        w = self._make_window()
        assert is_window_active(w) is False

    def test_active_within_duration(self):
        from app.services.agent_policy_service import is_window_active

        now = datetime.now(UTC)
        w = self._make_window(last_started_at=now - timedelta(minutes=30))
        assert is_window_active(w, now) is True

    def test_expired_past_duration(self):
        from app.services.agent_policy_service import is_window_active

        now = datetime.now(UTC)
        w = self._make_window(last_started_at=now - timedelta(minutes=90))
        assert is_window_active(w, now) is False

    def test_force_ended(self):
        from app.services.agent_policy_service import is_window_active

        now = datetime.now(UTC)
        w = self._make_window(
            last_started_at=now - timedelta(minutes=30),
            last_ended_at=now - timedelta(minutes=10),
            force_ended_by=_uid(),
        )
        assert is_window_active(w, now) is False

    def test_disabled(self):
        from app.services.agent_policy_service import is_window_active

        now = datetime.now(UTC)
        w = self._make_window(
            enabled=False,
            last_started_at=now - timedelta(minutes=5),
        )
        assert is_window_active(w, now) is False

# ══════════════════════════════════════════════════════════════════════════════
#  P4: Maintenance window cron schema
# ══════════════════════════════════════════════════════════════════════════════

class TestMaintenanceWindowSchemas:
    def test_valid_create(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        obj = MaintenanceWindowCreate(
            name="nightly-deploy",
            cron_schedule="0 2 * * *",
            duration_minutes=120,
            rules=["dns_exfil", "credential_theft"],
        )
        assert obj.duration_minutes == 120

    def test_invalid_cron(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        with pytest.raises(Exception):
            MaintenanceWindowCreate(
                name="bad",
                cron_schedule="not-a-cron",
                duration_minutes=60,
                rules=["*"],
            )

    def test_duration_bounds(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        with pytest.raises(Exception):
            MaintenanceWindowCreate(
                name="too-long",
                cron_schedule="0 0 * * *",
                duration_minutes=1441,
                rules=["*"],
            )
        with pytest.raises(Exception):
            MaintenanceWindowCreate(
                name="zero",
                cron_schedule="0 0 * * *",
                duration_minutes=0,
                rules=["*"],
            )

    def test_empty_rules_rejected(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        with pytest.raises(Exception):
            MaintenanceWindowCreate(
                name="no-rules",
                cron_schedule="0 0 * * *",
                duration_minutes=60,
                rules=[],
            )

# ══════════════════════════════════════════════════════════════════════════════
#  P1+P3: Routing simulation request
# ══════════════════════════════════════════════════════════════════════════════

class TestRoutingSimulationSchema:
    def test_valid_request(self):
        from app.schemas.agent_policy import RoutingSimulationRequest

        obj = RoutingSimulationRequest(
            severity="critical",
            agent_tags={"env": "prod"},
            rule_name="dns_exfil",
        )
        assert obj.severity == "critical"

    def test_invalid_severity(self):
        from app.schemas.agent_policy import RoutingSimulationRequest

        with pytest.raises(Exception):
            RoutingSimulationRequest(severity="banana")

# ══════════════════════════════════════════════════════════════════════════════
#  P2: Exemption response schema structure
# ══════════════════════════════════════════════════════════════════════════════

class TestExemptionResponseSchema:
    def test_round_trip(self):
        from app.schemas.agent_policy import ExemptionResponse

        now = datetime.now(UTC)
        uid = _uid()
        tid = _uid()
        obj = ExemptionResponse(
            id=uid,
            tenant_id=tid,
            rule_name="dns_exfil",
            match_tags={"env": "ci"},
            reason="CI agents do DNS",
            enabled=True,
            expires_at=None,
            hit_count=42,
            last_hit_at=now,
            created_by=uid,
            created_at=now,
            updated_at=now,
        )
        assert obj.hit_count == 42
        assert obj.enabled is True
        data = obj.model_dump()
        assert "match_tags" in data

    def test_with_expiration(self):
        from app.schemas.agent_policy import ExemptionResponse

        now = datetime.now(UTC)
        uid = _uid()
        obj = ExemptionResponse(
            id=uid,
            tenant_id=uid,
            rule_name="test",
            match_tags={"x": "1"},
            reason="test",
            enabled=True,
            expires_at=now + timedelta(hours=1),
            hit_count=0,
            last_hit_at=None,
            created_by=uid,
            created_at=now,
            updated_at=now,
        )
        assert obj.expires_at is not None

# ══════════════════════════════════════════════════════════════════════════════
#  Edge cases & integration
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_severity_ordering(self):
        from app.schemas.agent_policy import SEVERITY_ORDER

        assert SEVERITY_ORDER["info"] < SEVERITY_ORDER["low"]
        assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["medium"]
        assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["high"]
        assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["critical"]

    def test_tag_key_with_numbers(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        obj = AgentTagsUpdate(tags={"version123": "1.2.3"})
        assert "version123" in obj.tags

    def test_routing_rule_name_validation(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        obj = RoutingRuleCreate(
            name="prod-alerts v2.1",
            channels=["slack"],
        )
        assert obj.name == "prod-alerts v2.1"

    def test_routing_rule_bad_name(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(
                name="bad@name!",
                channels=["slack"],
            )

    def test_agent_update_schema_includes_tags(self):
        from app.schemas.agent import AgentUpdate

        obj = AgentUpdate(tags={"env": "prod"})
        data = obj.model_dump(exclude_unset=True)
        assert "tags" in data

    def test_agent_filter_tag(self):
        from app.schemas.agent import AgentFilter

        obj = AgentFilter(tag="env=prod")
        assert obj.tag == "env=prod"

    def test_cron_field_parser_comma(self):
        from app.services.agent_policy_service import _parse_cron_field

        vals = _parse_cron_field("1,15,30", 0, 59)
        assert vals == {1, 15, 30}

    def test_cron_field_parser_range(self):
        from app.services.agent_policy_service import _parse_cron_field

        vals = _parse_cron_field("5-10", 0, 59)
        assert vals == {5, 6, 7, 8, 9, 10}

    def test_cron_field_parser_star(self):
        from app.services.agent_policy_service import _parse_cron_field

        vals = _parse_cron_field("*", 0, 5)
        assert vals == {0, 1, 2, 3, 4, 5}

    def test_cron_field_parser_step(self):
        from app.services.agent_policy_service import _parse_cron_field

        vals = _parse_cron_field("*/10", 0, 59)
        assert 0 in vals and 10 in vals and 50 in vals

    def test_maintenance_window_name_validation(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        obj = MaintenanceWindowCreate(
            name="nightly.deploy-v2",
            cron_schedule="0 2 * * *",
            duration_minutes=60,
            rules=["*"],
        )
        assert obj.name == "nightly.deploy-v2"

    def test_routing_update_partial(self):
        from app.schemas.agent_policy import RoutingRuleUpdate

        obj = RoutingRuleUpdate(severity_min="high")
        data = obj.model_dump(exclude_unset=True)
        assert data == {"severity_min": "high"}

    def test_window_update_partial(self):
        from app.schemas.agent_policy import MaintenanceWindowUpdate

        obj = MaintenanceWindowUpdate(enabled=False)
        data = obj.model_dump(exclude_unset=True)
        assert data == {"enabled": False}

    def test_window_update_cron_validation(self):
        from app.schemas.agent_policy import MaintenanceWindowUpdate

        with pytest.raises(Exception):
            MaintenanceWindowUpdate(cron_schedule="bad")

# ══════════════════════════════════════════════════════════════════════════════
#  Security hardening tests (audit findings)
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityHardening:
    """Tests added from security audit of P1-P4."""

    # ── Control character rejection ──────────────────────────────────────

    def test_tag_value_control_chars_rejected(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        with pytest.raises(Exception):
            AgentTagsUpdate(tags={"env": "prod\x00injected"})

    def test_tag_value_null_byte_rejected(self):
        from app.schemas.agent_policy import AgentTagsUpdate

        with pytest.raises(Exception):
            AgentTagsUpdate(tags={"env": "\x00"})

    def test_tag_value_tabs_allowed(self):
        """Tabs and newlines are NOT stripped — only harmful control chars."""
        from app.schemas.agent_policy import AgentTagsUpdate

        # Tab (0x09), LF (0x0a), CR (0x0d) are not in the rejection range
        obj = AgentTagsUpdate(tags={"desc": "line1\nline2"})
        assert "\n" in obj.tags["desc"]

    # ── Channel ID validation ────────────────────────────────────────────

    def test_channel_id_valid(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        obj = RoutingRuleCreate(name="test", channels=["slack-main", "pagerduty.prod"])
        assert len(obj.channels) == 2

    def test_channel_id_xss_rejected(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(name="test", channels=["<script>alert(1)</script>"])

    def test_channel_id_too_long_rejected(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(name="test", channels=["a" * 129])

    def test_channel_id_spaces_rejected(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(name="test", channels=["slack main"])

    # ── Rule name sanitization (exemptions) ──────────────────────────────

    def test_exemption_rule_name_pattern_valid(self):
        from app.schemas.agent_policy import ExemptionCreate

        obj = ExemptionCreate(
            rule_name="dns_exfil.v2",
            match_tags={"env": "ci"},
            reason="CI runners do DNS",
        )
        assert obj.rule_name == "dns_exfil.v2"

    def test_exemption_rule_name_pattern_invalid(self):
        from app.schemas.agent_policy import ExemptionCreate

        with pytest.raises(Exception):
            ExemptionCreate(
                rule_name="'; DROP TABLE--",
                match_tags={"env": "ci"},
                reason="injection attempt",
            )

    def test_exemption_rule_name_spaces_rejected(self):
        from app.schemas.agent_policy import ExemptionCreate

        with pytest.raises(Exception):
            ExemptionCreate(
                rule_name="has spaces",
                match_tags={"env": "ci"},
                reason="bad",
            )

    # ── match_tags key validation ────────────────────────────────────────

    def test_match_tags_key_validated(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(
                name="test",
                channels=["slack"],
                match_tags={"inv@lid_key!": "val"},
            )

    def test_match_tags_value_control_chars_rejected(self):
        from app.schemas.agent_policy import RoutingRuleCreate

        with pytest.raises(Exception):
            RoutingRuleCreate(
                name="test",
                channels=["slack"],
                match_tags={"env": "prod\x00"},
            )

    # ── Allowlist enforcement ────────────────────────────────────────────

    def test_routing_rule_allowlisted_fields(self):
        from app.services.agent_policy_service import _ROUTING_RULE_UPDATABLE

        # These should NOT be in the allowlist
        assert "id" not in _ROUTING_RULE_UPDATABLE
        assert "tenant_id" not in _ROUTING_RULE_UPDATABLE
        assert "created_by" not in _ROUTING_RULE_UPDATABLE
        assert "created_at" not in _ROUTING_RULE_UPDATABLE
        # These SHOULD be
        assert "name" in _ROUTING_RULE_UPDATABLE
        assert "channels" in _ROUTING_RULE_UPDATABLE
        assert "enabled" in _ROUTING_RULE_UPDATABLE

    def test_maintenance_window_allowlisted_fields(self):
        from app.services.agent_policy_service import _MAINTENANCE_WINDOW_UPDATABLE

        assert "id" not in _MAINTENANCE_WINDOW_UPDATABLE
        assert "tenant_id" not in _MAINTENANCE_WINDOW_UPDATABLE
        assert "created_by" not in _MAINTENANCE_WINDOW_UPDATABLE
        assert "force_ended_by" not in _MAINTENANCE_WINDOW_UPDATABLE
        assert "name" in _MAINTENANCE_WINDOW_UPDATABLE
        assert "cron_schedule" in _MAINTENANCE_WINDOW_UPDATABLE

    # ── Cron safety ──────────────────────────────────────────────────────

    def test_cron_field_clamps_out_of_bounds(self):
        from app.services.agent_policy_service import _parse_cron_field

        # "99" is out of 0-59 range — should be excluded
        vals = _parse_cron_field("99", 0, 59)
        assert 99 not in vals
        assert len(vals) == 0

    def test_cron_field_negative_step_rejected(self):
        from app.services.agent_policy_service import _parse_cron_field

        with pytest.raises(ValueError):
            _parse_cron_field("*/0", 0, 59)

    def test_cron_iteration_cap_exists(self):
        from app.services.agent_policy_service import _CRON_MAX_ITERATIONS

        assert _CRON_MAX_ITERATIONS <= 600_000  # reasonable upper bound

    def test_impossible_cron_returns_none(self):
        from app.services.agent_policy_service import compute_next_cron

        # Feb 31 never exists — should not spin forever
        result = compute_next_cron("0 0 31 2 *")
        assert result is None

    # ── Maintenance window rules validation ──────────────────────────────

    def test_window_rules_valid_patterns(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        obj = MaintenanceWindowCreate(
            name="deploy",
            cron_schedule="0 2 * * *",
            duration_minutes=60,
            rules=["dns_exfil", "credential_theft", "*"],
        )
        assert "*" in obj.rules

    def test_window_rules_invalid_pattern_rejected(self):
        from app.schemas.agent_policy import MaintenanceWindowCreate

        with pytest.raises(Exception):
            MaintenanceWindowCreate(
                name="deploy",
                cron_schedule="0 2 * * *",
                duration_minutes=60,
                rules=["'; DROP TABLE rules; --"],
            )

    # ── Exemption reason sanitized ───────────────────────────────────────

    def test_exemption_reason_control_chars_stripped(self):
        from app.schemas.agent_policy import ExemptionCreate

        obj = ExemptionCreate(
            rule_name="dns_exfil",
            match_tags={"env": "ci"},
            reason="CI runners\x07do DNS",  # BEL control char
        )
        assert "\x07" not in obj.reason

    # ── Sentinel/update edge cases ───────────────────────────────────────

    def test_sentinel_is_not_none(self):
        from app.services.agent_policy_service import _UNSET

        assert _UNSET is not None
        assert _UNSET is not ...
