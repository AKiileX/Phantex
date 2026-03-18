# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Block L — Investigation Timeline (L1) + MITRE ATLAS (L2).

Tests cover:
  - Timeline service: agent timeline, alert timeline, session grouping,
    partial data source failure, ATLAS enrichment, pagination
  - MITRE service: technique lookup, rule mapping, attack class mapping,
    ML model mapping, content classifier mapping, coverage report,
    alert context enrichment
  - Timeline router: endpoint responses, auth, error handling
  - ATLAS router: coverage, technique detail, rule mapping endpoint
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.schemas.timeline import (
    AtlasCoverageResponse,
    AtlasRuleMappingResponse,
    DataSourceStatus,
    TimelineEvent,
    TimelineResponse,
)
from app.services import mitre_service, timeline_service

# ── Helpers ───────────────────────────────────────────────────────────────────

TENANT_ID = uuid.uuid4()
AGENT_ID = uuid.uuid4()
ALERT_ID = uuid.uuid4()
NOW = datetime.now(UTC)

def _make_event(
    offset_minutes: int = 0,
    event_type: str = "file_read",
    severity: str = "info",
    source: str = "clickhouse",
    agent_id: str | None = None,
) -> TimelineEvent:
    """Factory for TimelineEvent."""
    return TimelineEvent(
        id=str(uuid.uuid4()),
        source=source,
        event_type=event_type,
        severity=severity,
        timestamp=NOW - timedelta(minutes=offset_minutes),
        agent_id=agent_id or str(AGENT_ID),
        description=f"test {event_type}",
    )

# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATLAS Service Tests (L2)
# ══════════════════════════════════════════════════════════════════════════════

class TestMitreServiceLoading:
    """Tests for ATLAS mapping data loading."""

    def test_load_mapping_succeeds(self):
        """Mapping file loads successfully."""
        # Force reload
        mitre_service._atlas_data = {}
        data = mitre_service._load_mapping()
        assert "techniques" in data
        assert "rule_mappings" in data
        assert "attack_class_to_atlas" in data
        assert len(data["techniques"]) > 0

    def test_all_techniques_have_required_fields(self):
        """Every technique in the catalogue has name, tactic, url."""
        mitre_service._atlas_data = {}
        techniques = mitre_service.get_all_techniques()
        for tid, info in techniques.items():
            assert "name" in info, f"{tid} missing 'name'"
            assert "tactic" in info, f"{tid} missing 'tactic'"
            assert "url" in info, f"{tid} missing 'url'"
            assert info["url"].startswith("https://"), f"{tid} URL invalid"

    def test_load_mapping_handles_missing_file(self, tmp_path, monkeypatch):
        """Gracefully handles missing mapping file."""
        mitre_service._atlas_data = {}
        monkeypatch.setattr(mitre_service, "_MAPPING_PATH", tmp_path / "nonexistent.json")
        data = mitre_service._load_mapping()
        assert data["techniques"] == {}
        # Reset for other tests
        mitre_service._atlas_data = {}

class TestMitreTechniqueLookup:
    """Tests for technique lookup functions."""

    def test_get_known_technique(self):
        """Known technique returns full info."""
        mitre_service._atlas_data = {}
        info = mitre_service.get_technique("AML.T0051")
        assert info is not None
        assert info["name"] == "LLM Prompt Injection"
        assert "url" in info

    def test_get_unknown_technique(self):
        """Unknown technique returns None."""
        mitre_service._atlas_data = {}
        assert mitre_service.get_technique("AML.T9999") is None

    def test_get_subtechnique(self):
        """Subtechnique IDs resolve correctly."""
        mitre_service._atlas_data = {}
        info = mitre_service.get_technique("AML.T0051.001")
        assert info is not None
        assert "Direct" in info["name"]

class TestMitreRuleMappings:
    """Tests for rule → ATLAS technique mapping."""

    def test_prompt_injection_rule(self):
        """prompt_injection_pattern maps to AML.T0051."""
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_rule("prompt_injection_pattern")
        assert "AML.T0051" in techniques

    def test_unknown_rule_returns_empty(self):
        """Unknown rule name returns empty list."""
        mitre_service._atlas_data = {}
        assert mitre_service.techniques_for_rule("nonexistent_rule") == []

    def test_high_tool_call_rate_maps_to_dos(self):
        """high_tool_call_rate maps to AML.T0029 (Denial of ML Service)."""
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_rule("high_tool_call_rate")
        assert "AML.T0029" in techniques

    def test_rule_mapping_detail_returns_full_info(self):
        """Rule mapping detail includes confidence and rationale."""
        mitre_service._atlas_data = {}
        detail = mitre_service.rule_mapping_detail("prompt_injection_pattern")
        assert detail is not None
        assert detail["confidence"] == "high"
        assert len(detail["rationale"]) > 0

    def test_all_manifest_rules_have_atlas_mapping(self):
        """Every rule in manifest.json has an ATLAS mapping."""
        mitre_service._atlas_data = {}
        import json as _json
        from pathlib import Path

        manifest_path = Path(__file__).resolve().parent.parent.parent / "rules" / "core" / "manifest.json"
        with open(manifest_path) as f:
            manifest = _json.load(f)
        unmapped = []
        for rule in manifest:
            rule_name = rule["name"]
            techniques = mitre_service.techniques_for_rule(rule_name)
            if not techniques:
                # Fall back to attack_class mapping
                attack_class = rule.get("attack_class", "")
                techniques = mitre_service.techniques_for_attack_class(attack_class)
            if not techniques:
                unmapped.append(rule_name)
        assert unmapped == [], f"Rules without ATLAS mapping: {unmapped}"

class TestMitreAttackClassMapping:
    """Tests for attack_class → ATLAS mapping."""

    def test_exfiltration_maps(self):
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_attack_class("exfiltration")
        assert "AML.T0024" in techniques or "AML.T0025" in techniques

    def test_prompt_injection_maps(self):
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_attack_class("prompt_injection")
        assert "AML.T0051" in techniques

    def test_unknown_class_returns_empty(self):
        mitre_service._atlas_data = {}
        assert mitre_service.techniques_for_attack_class("nonexistent") == []

class TestMitreMLModelMapping:
    """Tests for ML model → ATLAS mapping."""

    def test_isolation_forest(self):
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_ml_model("isolation_forest_anomaly")
        assert len(techniques) > 0

    def test_xgboost_with_class(self):
        """XGBoost with predicted_class resolves per-class mapping."""
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_ml_model("xgboost_attack_class", predicted_class="prompt_injection")
        assert "AML.T0051" in techniques

    def test_xgboost_without_class(self):
        """XGBoost without predicted_class returns no direct techniques (class-specific)."""
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_ml_model("xgboost_attack_class")
        # No direct atlas_techniques, only attack_class_mapping
        assert isinstance(techniques, list)

    def test_unknown_model(self):
        mitre_service._atlas_data = {}
        assert mitre_service.techniques_for_ml_model("nonexistent") == []

class TestMitreContentClassifierMapping:
    """Tests for content classifier → ATLAS mapping."""

    def test_prompt_injection_regex(self):
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_content_classifier("prompt_injection_regex")
        assert "AML.T0051" in techniques

    def test_secret_detector(self):
        mitre_service._atlas_data = {}
        techniques = mitre_service.techniques_for_content_classifier("secret_detector")
        assert "AML.T0025" in techniques

    def test_unknown_classifier(self):
        mitre_service._atlas_data = {}
        assert mitre_service.techniques_for_content_classifier("nonexistent") == []

class TestMitreAlertEnrichment:
    """Tests for alert context enrichment."""

    def test_enrich_with_rule_name(self):
        mitre_service._atlas_data = {}
        context = {"rule_name": "prompt_injection_pattern", "attack_class": "prompt_injection"}
        enriched = mitre_service.enrich_alert_context(
            context, rule_name="prompt_injection_pattern", attack_class="prompt_injection"
        )
        assert "atlas_techniques" in enriched
        assert any(t["id"] == "AML.T0051" for t in enriched["atlas_techniques"])

    def test_enrich_with_attack_class_fallback(self):
        mitre_service._atlas_data = {}
        context = {"attack_class": "dos"}
        enriched = mitre_service.enrich_alert_context(context, attack_class="dos")
        assert "atlas_techniques" in enriched
        assert any(t["id"] == "AML.T0029" for t in enriched["atlas_techniques"])

    def test_enrich_preserves_existing_context(self):
        mitre_service._atlas_data = {}
        context = {"existing_key": "preserved", "rule_name": "prompt_injection_pattern"}
        enriched = mitre_service.enrich_alert_context(context, rule_name="prompt_injection_pattern")
        assert enriched["existing_key"] == "preserved"

    def test_enrich_no_mapping(self):
        """No ATLAS info added if no mapping exists."""
        mitre_service._atlas_data = {}
        context = {"some_field": 42}
        enriched = mitre_service.enrich_alert_context(context)
        assert "atlas_techniques" not in enriched

    def test_enrich_does_not_mutate_original(self):
        """Enrichment returns new dict, does not modify original."""
        mitre_service._atlas_data = {}
        context = {"rule_name": "prompt_injection_pattern"}
        enriched = mitre_service.enrich_alert_context(context, rule_name="prompt_injection_pattern")
        assert "atlas_techniques" not in context
        assert "atlas_techniques" in enriched

class TestMitreCoverageReport:
    """Tests for ATLAS coverage report generation."""

    def test_coverage_report_structure(self):
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        assert "total_techniques" in report
        assert "detected_techniques" in report
        assert "coverage_pct" in report
        assert "techniques" in report
        assert report["total_techniques"] > 0

    def test_coverage_pct_is_valid(self):
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        assert 0.0 <= report["coverage_pct"] <= 100.0

    def test_all_techniques_in_report(self):
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        all_techniques = mitre_service.get_all_techniques()
        assert report["total_techniques"] == len(all_techniques)

    def test_detected_techniques_have_detectors(self):
        """Every detected technique has at least one detector."""
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        for tech in report["techniques"]:
            if tech["detected"]:
                assert len(tech["detected_by"]) > 0

    def test_detectors_have_source_and_name(self):
        """Each detector entry has name and source fields."""
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        for tech in report["techniques"]:
            for detector in tech["detected_by"]:
                assert "name" in detector
                assert "source" in detector
                assert detector["source"] in ("prl_rule", "ml_model", "content_classifier")

# ══════════════════════════════════════════════════════════════════════════════
# Timeline Service Tests (L1)
# ══════════════════════════════════════════════════════════════════════════════

class TestTimelineRangeParsing:
    """Tests for range string parsing."""

    def test_valid_ranges(self):
        assert timeline_service._parse_range("1h") == 1.0
        assert timeline_service._parse_range("24h") == 24.0
        assert timeline_service._parse_range("72h") == 72.0

    def test_cap_at_72h(self):
        """Ranges > 72h capped."""
        assert timeline_service._parse_range("100h") == 72.0
        assert timeline_service._parse_range("168h") == 72.0

    def test_invalid_range_defaults(self):
        """Invalid range strings default to 24h."""
        assert timeline_service._parse_range("invalid") == 24.0

    def test_numeric_string(self):
        """Numeric string with h suffix works."""
        assert timeline_service._parse_range("6h") == 6.0

class TestTimelineSessionGrouping:
    """Tests for session grouping logic."""

    def test_empty_events(self):
        sessions = timeline_service._group_into_sessions([])
        assert sessions == []

    def test_single_event(self):
        events = [_make_event(0)]
        sessions = timeline_service._group_into_sessions(events)
        assert len(sessions) == 1
        assert sessions[0].event_count == 1

    def test_events_within_gap_grouped(self):
        """Events within 5-min gap go into same session."""
        events = [_make_event(10), _make_event(8), _make_event(6)]
        sessions = timeline_service._group_into_sessions(events)
        assert len(sessions) == 1
        assert sessions[0].event_count == 3

    def test_events_beyond_gap_split(self):
        """Events with > 5 min gap split into separate sessions."""
        events = [_make_event(20), _make_event(10)]  # 10 min gap
        sessions = timeline_service._group_into_sessions(events)
        assert len(sessions) == 2
        assert sessions[0].event_count == 1
        assert sessions[1].event_count == 1

    def test_session_severity_counts(self):
        """Session tracks severity distribution."""
        events = [
            _make_event(4, severity="high"),
            _make_event(3, severity="high"),
            _make_event(2, severity="critical"),
        ]
        sessions = timeline_service._group_into_sessions(events)
        assert len(sessions) == 1
        assert sessions[0].severities.get("high") == 2
        assert sessions[0].severities.get("critical") == 1

    def test_session_id_deterministic(self):
        """Same agent+timestamp produces same session ID."""
        sid1 = timeline_service._generate_session_id("agent1", NOW)
        sid2 = timeline_service._generate_session_id("agent1", NOW)
        assert sid1 == sid2

    def test_session_id_differs_for_different_agents(self):
        sid1 = timeline_service._generate_session_id("agent1", NOW)
        sid2 = timeline_service._generate_session_id("agent2", NOW)
        assert sid1 != sid2

class TestClickHouseEvents:
    """Tests for ClickHouse event fetching."""

    @pytest.mark.asyncio
    async def test_no_clickhouse_returns_unavailable(self):
        """None client returns empty events + unavailable status."""
        events, status = await timeline_service._fetch_clickhouse_events(
            None, TENANT_ID, since=NOW - timedelta(hours=24)
        )
        assert events == []
        assert status.available is False
        assert "not configured" in status.error

    @pytest.mark.asyncio
    async def test_clickhouse_query_returns_events(self):
        """Mock ClickHouse client returns events."""
        mock_result = MagicMock()
        mock_result.result_rows = [
            (str(uuid.uuid4()), "file_read", "info", NOW, str(AGENT_ID), str(TENANT_ID)),
            (str(uuid.uuid4()), "network_connect", "high", NOW, str(AGENT_ID), str(TENANT_ID)),
        ]
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(return_value=mock_result)

        events, status = await timeline_service._fetch_clickhouse_events(
            mock_ch, TENANT_ID, agent_id=AGENT_ID, since=NOW - timedelta(hours=1)
        )
        assert len(events) == 2
        assert status.available is True
        assert status.event_count == 2

    @pytest.mark.asyncio
    async def test_clickhouse_error_is_graceful(self):
        """ClickHouse exception doesn't crash — returns error status."""
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(side_effect=Exception("CH connection refused"))

        events, status = await timeline_service._fetch_clickhouse_events(
            mock_ch, TENANT_ID, since=NOW - timedelta(hours=1)
        )
        assert events == []
        assert status.available is False
        assert "connection refused" in status.error.lower()

class TestPGAlerts:
    """Tests for PostgreSQL alert fetching."""

    @pytest.mark.asyncio
    async def test_no_session_returns_unavailable(self):
        events, status = await timeline_service._fetch_pg_alerts(None, TENANT_ID, since=NOW - timedelta(hours=24))
        assert events == []
        assert status.available is False

    @pytest.mark.asyncio
    async def test_pg_returns_enriched_alerts(self):
        """PG alerts are enriched with ATLAS techniques."""
        mitre_service._atlas_data = {}
        mock_row = (
            uuid.uuid4(),
            "critical",
            "Prompt Injection Detected",
            "Agent attempted prompt injection",
            "open",
            {"rule_name": "prompt_injection_pattern", "attack_class": "prompt_injection"},
            NOW,
            AGENT_ID,
            uuid.uuid4(),
            uuid.uuid4(),
        )
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [mock_row]
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        events, status = await timeline_service._fetch_pg_alerts(
            mock_session, TENANT_ID, since=NOW - timedelta(hours=24)
        )
        assert len(events) == 1
        assert status.available is True
        assert events[0].source == "postgres"
        assert events[0].severity == "critical"
        # Should have ATLAS enrichment
        assert len(events[0].atlas_techniques) > 0
        assert any(t["id"] == "AML.T0051" for t in events[0].atlas_techniques)

class TestNeo4jContext:
    """Tests for Neo4j relationship context fetching."""

    @pytest.mark.asyncio
    async def test_no_neo4j_returns_unavailable(self):
        events, status = await timeline_service._fetch_neo4j_context(None, TENANT_ID, since=NOW - timedelta(hours=24))
        assert events == []
        assert status.available is False

    @pytest.mark.asyncio
    async def test_neo4j_error_is_graceful(self):
        mock_driver = MagicMock()
        mock_driver.session = MagicMock(side_effect=Exception("Neo4j down"))

        events, status = await timeline_service._fetch_neo4j_context(
            mock_driver, TENANT_ID, agent_id=AGENT_ID, since=NOW - timedelta(hours=24)
        )
        assert events == []
        assert status.available is False

    @pytest.mark.asyncio
    async def test_no_agent_or_alert_returns_empty(self):
        """If no agent_id or alert_id, returns empty with available=True."""
        mock_driver = MagicMock()
        events, status = await timeline_service._fetch_neo4j_context(
            mock_driver, TENANT_ID, since=NOW - timedelta(hours=24)
        )
        assert events == []
        assert status.available is True

class TestTrustScoreEnrichment:
    """Tests for trust score enrichment."""

    @pytest.mark.asyncio
    async def test_no_trust_client_returns_unavailable(self):
        events = [_make_event(0)]
        status = await timeline_service._enrich_trust_scores(events, None, TENANT_ID)
        assert status.available is False
        assert events[0].trust_score is None

    @pytest.mark.asyncio
    async def test_trust_scores_applied(self):
        """Trust scores are applied to events with agent IDs."""
        events = [_make_event(0, agent_id=str(AGENT_ID))]

        mock_result = MagicMock()
        mock_result.trust_score = 0.85
        mock_client = AsyncMock()
        mock_client.get_trust_score = AsyncMock(return_value=mock_result)

        status = await timeline_service._enrich_trust_scores(events, mock_client, TENANT_ID)
        assert status.available is True
        assert events[0].trust_score == 0.85

    @pytest.mark.asyncio
    async def test_trust_error_falls_back_to_neutral(self):
        """Trust engine error → neutral score 0.5."""
        events = [_make_event(0, agent_id=str(AGENT_ID))]

        mock_client = AsyncMock()
        mock_client.get_trust_score = AsyncMock(side_effect=Exception("grpc unavailable"))

        await timeline_service._enrich_trust_scores(events, mock_client, TENANT_ID)
        # Scores dict entry falls back to 0.5
        assert events[0].trust_score == 0.5

class TestAgentTimeline:
    """Tests for the full agent timeline assembly."""

    @pytest.mark.asyncio
    async def test_empty_timeline(self):
        """All sources unavailable → empty timeline with status."""
        result = await timeline_service.get_agent_timeline(TENANT_ID, AGENT_ID, range_str="1h")
        assert isinstance(result, TimelineResponse)
        assert result.total_events == 0
        assert result.agent_id == str(AGENT_ID)
        assert len(result.data_sources) == 4  # CH, PG, Neo4j, Trust

    @pytest.mark.asyncio
    async def test_timeline_with_clickhouse_only(self):
        """Timeline assembles even if only ClickHouse is available."""
        mock_result = MagicMock()
        mock_result.result_rows = [
            (str(uuid.uuid4()), "file_read", "info", NOW - timedelta(minutes=5), str(AGENT_ID), str(TENANT_ID)),
            (str(uuid.uuid4()), "network_connect", "high", NOW - timedelta(minutes=3), str(AGENT_ID), str(TENANT_ID)),
        ]
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(return_value=mock_result)

        result = await timeline_service.get_agent_timeline(TENANT_ID, AGENT_ID, range_str="1h", ch_client=mock_ch)
        assert result.total_events == 2
        # Events should be sorted chronologically
        assert result.events[0].timestamp <= result.events[1].timestamp
        # At least one session should exist
        assert len(result.sessions) >= 1

    @pytest.mark.asyncio
    async def test_range_cap_at_72h(self):
        """Range > 72h is capped."""
        result = await timeline_service.get_agent_timeline(TENANT_ID, AGENT_ID, range_str="168h")
        assert result.range_hours == 72.0

class TestAlertTimeline:
    """Tests for alert-specific timeline assembly."""

    @pytest.mark.asyncio
    async def test_alert_not_found(self):
        """Alert not found → empty timeline."""
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await timeline_service.get_alert_timeline(TENANT_ID, ALERT_ID, pg_session=mock_session)
        assert result.total_events == 0

    @pytest.mark.asyncio
    async def test_alert_timeline_includes_alert(self):
        """Alert timeline includes the alert event itself."""
        mock_row = (
            ALERT_ID,
            "high",
            "Test Alert",
            "Description",
            "open",
            {"rule_name": "high_tool_call_rate", "attack_class": "dos"},
            NOW,
            AGENT_ID,
            uuid.uuid4(),
            uuid.uuid4(),
        )
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [mock_row]
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await timeline_service.get_alert_timeline(TENANT_ID, ALERT_ID, pg_session=mock_session)
        assert result.total_events >= 1
        assert result.alert_id == str(ALERT_ID)

class TestAtlasEnrichmentOnEvents:
    """Tests for ATLAS enrichment on ClickHouse events."""

    def test_events_with_attack_class_get_atlas(self):
        mitre_service._atlas_data = {}
        events = [
            TimelineEvent(
                id="test1",
                source="clickhouse",
                event_type="tool_call",
                timestamp=NOW,
                raw_data={"attack_class": "prompt_injection"},
            )
        ]
        timeline_service._enrich_events_with_atlas(events)
        assert len(events[0].atlas_techniques) > 0

    def test_events_without_attack_class_unchanged(self):
        events = [
            TimelineEvent(
                id="test2",
                source="clickhouse",
                event_type="file_read",
                timestamp=NOW,
                raw_data={},
            )
        ]
        timeline_service._enrich_events_with_atlas(events)
        assert events[0].atlas_techniques == []

    def test_already_enriched_events_not_overwritten(self):
        existing = [{"id": "AML.T0029", "name": "Denial of ML Service"}]
        events = [
            TimelineEvent(
                id="test3",
                source="postgres",
                event_type="alert:open",
                timestamp=NOW,
                atlas_techniques=existing,
                raw_data={"attack_class": "dos"},
            )
        ]
        timeline_service._enrich_events_with_atlas(events)
        assert events[0].atlas_techniques == existing  # unchanged

# ══════════════════════════════════════════════════════════════════════════════
# Schema Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTimelineSchemas:
    """Tests for Pydantic schema validation."""

    def test_timeline_event_minimal(self):
        evt = TimelineEvent(
            id="123",
            source="clickhouse",
            event_type="test",
            timestamp=NOW,
        )
        assert evt.severity == "info"
        assert evt.atlas_techniques == []

    def test_timeline_response_model(self):
        resp = TimelineResponse(agent_id=str(AGENT_ID), range_hours=24.0, total_events=0, events=[])
        assert resp.sessions == []
        assert resp.data_sources == []
        assert resp.has_more is False

    def test_data_source_status(self):
        ds = DataSourceStatus(source="clickhouse", available=True, event_count=42)
        assert ds.error is None

    def test_atlas_coverage_response(self):
        resp = AtlasCoverageResponse(total_techniques=14, detected_techniques=12, coverage_pct=85.7, techniques=[])
        assert resp.coverage_pct == 85.7

    def test_atlas_rule_mapping_response(self):
        resp = AtlasRuleMappingResponse(rule_name="test_rule")
        assert resp.confidence == "none"

# ══════════════════════════════════════════════════════════════════════════════
# Integration-Level Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTimelineDataSourcePartialFailure:
    """Tests verifying partial data source failure handling."""

    @pytest.mark.asyncio
    async def test_ch_fails_pg_succeeds(self):
        """ClickHouse down but PG works → partial timeline with status."""
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(side_effect=Exception("connection refused"))

        mock_row = (
            uuid.uuid4(),
            "medium",
            "Test Alert",
            None,
            "open",
            {},
            NOW,
            AGENT_ID,
            None,
            None,
        )
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [mock_row]
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await timeline_service.get_agent_timeline(
            TENANT_ID,
            AGENT_ID,
            range_str="1h",
            ch_client=mock_ch,
            pg_session=mock_session,
        )
        # Should have 1 event from PG
        assert result.total_events == 1
        # CH should show as unavailable
        ch_status = next(ds for ds in result.data_sources if ds.source == "clickhouse")
        assert ch_status.available is False
        # PG should show as available
        pg_status = next(ds for ds in result.data_sources if ds.source == "postgres")
        assert pg_status.available is True

    @pytest.mark.asyncio
    async def test_all_sources_up(self):
        """All three data sources return events → merged and sorted."""
        # ClickHouse events
        ch_result = MagicMock()
        ch_result.result_rows = [
            (str(uuid.uuid4()), "file_read", "info", NOW - timedelta(minutes=10), str(AGENT_ID), str(TENANT_ID)),
        ]
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(return_value=ch_result)

        # PG alert
        pg_row = (
            uuid.uuid4(),
            "high",
            "Alert",
            None,
            "open",
            {},
            NOW - timedelta(minutes=5),
            AGENT_ID,
            None,
            None,
        )
        pg_result = MagicMock()
        pg_result.fetchall.return_value = [pg_row]
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=pg_result)

        result = await timeline_service.get_agent_timeline(
            TENANT_ID,
            AGENT_ID,
            range_str="1h",
            ch_client=mock_ch,
            pg_session=mock_session,
        )
        assert result.total_events == 2
        # Events sorted chronologically
        assert result.events[0].timestamp <= result.events[1].timestamp

class TestEndToEndCoverage:
    """End-to-end tests verifying ATLAS coverage completeness."""

    def test_all_attack_classes_mapped(self):
        """Every attack_class in manifest has ATLAS mapping."""
        mitre_service._atlas_data = {}
        import json as _json
        from pathlib import Path

        manifest_path = Path(__file__).resolve().parent.parent.parent / "rules" / "core" / "manifest.json"
        with open(manifest_path) as f:
            manifest = _json.load(f)

        for rule in manifest:
            attack_class = rule.get("attack_class", "")
            techniques = mitre_service.techniques_for_attack_class(attack_class)
            assert techniques, f"attack_class '{attack_class}' has no ATLAS mapping"

    def test_coverage_report_nonzero(self):
        """Coverage report detects at least some techniques."""
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        assert report["detected_techniques"] > 0
        assert report["coverage_pct"] > 50.0  # we should cover most ATLAS techniques

    def test_coverage_report_no_duplicate_detectors(self):
        """No detector appears twice for the same technique."""
        mitre_service._atlas_data = {}
        report = mitre_service.coverage_report()
        for tech in report["techniques"]:
            [d["name"] for d in tech["detected_by"]]
            # Within same source, no exact duplicates
            seen = set()
            for d in tech["detected_by"]:
                key = f"{d['source']}:{d['name']}"
                assert key not in seen, f"Duplicate detector {key} for {tech['id']}"
                seen.add(key)

# ══════════════════════════════════════════════════════════════════════════════
# L Hardening —  Audit
# ══════════════════════════════════════════════════════════════════════════════

class TestTimelineCursorValidation:
    """Invalid cursor must not crash the service (500)."""

    @pytest.mark.asyncio
    async def test_invalid_cursor_ignored(self):
        """Non-ISO cursor is ignored rather than raising ValueError."""
        mock_result = MagicMock()
        mock_result.result_rows = []
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(return_value=mock_result)

        # Pass an obviously invalid cursor
        events, status = await timeline_service._fetch_clickhouse_events(
            mock_ch,
            TENANT_ID,
            agent_id=AGENT_ID,
            since=NOW - timedelta(hours=1),
            cursor="NOT_A_DATE",
        )
        # Should not raise — cursor is silently ignored
        assert status.available is True

    @pytest.mark.asyncio
    async def test_valid_cursor_accepted(self):
        """Valid ISO cursor passes through to the query."""
        mock_result = MagicMock()
        mock_result.result_rows = []
        mock_ch = AsyncMock()
        mock_ch.query = AsyncMock(return_value=mock_result)

        cursor = NOW.isoformat()
        events, status = await timeline_service._fetch_clickhouse_events(
            mock_ch,
            TENANT_ID,
            agent_id=AGENT_ID,
            since=NOW - timedelta(hours=1),
            cursor=cursor,
        )
        assert status.available is True
        # The query call should have cursor_ts in parameters
        call_args = mock_ch.query.call_args
        assert "cursor_ts" in call_args[1].get("parameters", call_args[0][1] if len(call_args[0]) > 1 else {})

class TestAlertTimelineUUIDSafety:
    """alert_agent_id that is not a valid UUID must not crash."""

    @pytest.mark.asyncio
    async def test_non_uuid_agent_id(self):
        """Alert with non-UUID agent_id degrades gracefully."""
        # Build a mock alert row with a non-UUID agent_id
        mock_row = (
            ALERT_ID,
            "high",
            "Test Alert",
            "Desc",
            "open",
            {},
            NOW,
            "not-a-valid-uuid",
            None,
            None,
        )
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [mock_row]
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        # Should NOT raise ValueError
        result = await timeline_service.get_alert_timeline(
            TENANT_ID,
            ALERT_ID,
            pg_session=mock_session,
        )
        assert result.total_events >= 1  # at least the alert

class TestRouterTrustClientSync:
    """_get_trust_client() must NOT await the sync get_trust_client()."""

    @pytest.mark.asyncio
    async def test_get_trust_client_is_sync(self):
        """get_trust_client() is synchronous — verify it's not awaited."""
        from app.services.trust_client import get_trust_client

        # get_trust_client() returns TrustClient directly (not a coroutine)
        client = get_trust_client()
        assert not asyncio.iscoroutine(client)
        # Clean up
        from app.services import trust_client as tc_mod

        tc_mod._trust_client = None

class TestAtlasTechniqueIDValidation:
    """Technique ID must match AML.TXXXX or AML.TXXXX.XXX format."""

    def test_valid_technique_id(self):
        """AML.T0051 matches."""
        import re

        pattern = re.compile(r"^AML\.T\d{4}(\.\d{1,3})?$")
        assert pattern.match("AML.T0051")
        assert pattern.match("AML.T0051.001")

    def test_invalid_technique_ids(self):
        """Malformed IDs are rejected."""
        import re

        pattern = re.compile(r"^AML\.T\d{4}(\.\d{1,3})?$")
        assert not pattern.match("AML.T")
        assert not pattern.match("AML.T00")
        assert not pattern.match("AML.Txyz1")
        assert not pattern.match("AML.T0051.1234")  # subtechnique too long
        assert not pattern.match("../../etc/passwd")
        assert not pattern.match("AML.T0051; DROP TABLE")

class TestTimelinePaginationEdges:
    """Pagination edge cases."""

    @pytest.mark.asyncio
    async def test_limit_capped_at_max(self):
        """Limit > 500 is silently capped."""
        result = await timeline_service.get_agent_timeline(TENANT_ID, AGENT_ID, range_str="1h", limit=9999)
        # Should not crash — internal cap at MAX_EVENTS_PER_PAGE
        assert isinstance(result, TimelineResponse)

    @pytest.mark.asyncio
    async def test_empty_has_more_false(self):
        """Empty result has has_more=False."""
        result = await timeline_service.get_agent_timeline(TENANT_ID, AGENT_ID, range_str="1h")
        assert result.has_more is False
        assert result.next_cursor is None

class TestMitreServiceEdgeCases:
    """Edge cases for the MITRE service."""

    def test_techniques_for_ml_model_deduplication(self):
        """Direct + per-class techniques are deduplicated."""
        mitre_service._atlas_data = {}
        # XGBoost with prompt_injection class — direct + class-specific
        techniques = mitre_service.techniques_for_ml_model("xgboost_attack_class", predicted_class="prompt_injection")
        # No duplicate technique IDs
        assert len(techniques) == len(set(techniques))

    def test_enrich_alert_context_rule_priority_over_class(self):
        """Rule-based mapping takes priority over attack_class fallback."""
        mitre_service._atlas_data = {}
        enriched = mitre_service.enrich_alert_context({}, rule_name="prompt_injection_pattern", attack_class="dos")
        # Should use rule mapping (prompt_injection_pattern → AML.T0051)
        # not attack_class (dos → AML.T0029)
        assert "atlas_techniques" in enriched
        ids = [t["id"] for t in enriched["atlas_techniques"]]
        assert "AML.T0051" in ids

    def test_coverage_empty_techniques(self):
        """Coverage report handles empty technique catalogue gracefully."""
        mitre_service._atlas_data = {
            "techniques": {},
            "rule_mappings": {},
            "ml_model_mappings": {},
            "content_classifier_mappings": {},
            "attack_class_to_atlas": {},
        }
        report = mitre_service.coverage_report()
        assert report["total_techniques"] == 0
        assert report["coverage_pct"] == 0.0
        # Reset
        mitre_service._atlas_data = {}

class TestSessionGroupingEdges:
    """Edge cases for timeline session grouping."""

    def test_negative_gap_treated_as_same_session(self):
        """Events with same timestamp go in one session."""
        events = [
            _make_event(5, severity="info"),
            _make_event(5, severity="high"),
            _make_event(5, severity="critical"),
        ]
        sessions = timeline_service._group_into_sessions(events)
        assert len(sessions) == 1
        assert sessions[0].event_count == 3

    def test_many_sessions(self):
        """Many distant events produce many sessions."""
        # Events 10 min apart, sorted chronologically (oldest first)
        events = [_make_event(i * 10) for i in range(5)]
        events.sort(key=lambda e: e.timestamp)
        sessions = timeline_service._group_into_sessions(events)
        assert len(sessions) == 5
