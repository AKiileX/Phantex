# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Audit & DVR Recording Tests.

Tests all 4 services: SessionRecorder, DVRReplayEngine,
TamperProofChain, ComplianceExporter.
"""

from __future__ import annotations

import uuid

_TENANT = str(uuid.uuid4())
_TENANT_B = str(uuid.uuid4())
_AGENT = "agent-alpha"
_AGENT_B = "agent-beta"
_USER = str(uuid.uuid4())

# ═══════════════════════════════════════════════════════════════════
#  AU1 — Session Recorder
# ═══════════════════════════════════════════════════════════════════

class TestSessionRecorder:
    """Tests for the three-tier session recorder."""

    def _make(self):
        from app.services.recording.session_recorder import SessionRecorder

        return SessionRecorder()

    def test_default_level_is_audit(self):
        rec = self._make()
        config = rec.get_config(_TENANT)
        assert config.level == 1

    def test_set_tenant_config(self):
        rec = self._make()
        config = rec.set_config(_TENANT, level=2)
        assert config.level == 2
        assert config.agent_id is None

    def test_set_agent_config_overrides_tenant(self):
        from app.services.recording.session_recorder import RecordingLevel

        rec = self._make()
        rec.set_config(_TENANT, level=RecordingLevel.AUDIT)
        rec.set_config(_TENANT, agent_id=_AGENT, level=RecordingLevel.FULL_DVR)
        assert rec.get_config(_TENANT, _AGENT).level == RecordingLevel.FULL_DVR
        assert rec.get_config(_TENANT).level == RecordingLevel.AUDIT

    def test_record_level1_basic(self):
        rec = self._make()
        evt = rec.record(_TENANT, _AGENT, "tool_call", tool_name="mcp://db/query")
        assert evt.audit is not None
        assert evt.audit.agent_id == _AGENT
        assert evt.audit.tool_name == "mcp://db/query"
        assert evt.extended is None
        assert evt.dvr is None

    def test_record_level2_includes_extended(self):
        from app.services.recording.session_recorder import RecordingLevel

        rec = self._make()
        rec.set_config(_TENANT, level=RecordingLevel.EXTENDED)
        evt = rec.record(
            _TENANT,
            _AGENT,
            "tool_call",
            tool_parameters={"query": "SELECT 1"},
            llm_prompt="What is 1+1?",
        )
        assert evt.extended is not None
        assert evt.extended.tool_parameters == {"query": "SELECT 1"}
        assert evt.extended.llm_prompt_hash is not None
        assert len(evt.extended.llm_prompt_hash) == 64  # SHA-256 hex
        assert evt.dvr is None  # Level 2 should NOT have DVR

    def test_record_level3_includes_dvr(self):
        from app.services.recording.session_recorder import RecordingLevel

        rec = self._make()
        rec.set_config(_TENANT, level=RecordingLevel.FULL_DVR)
        evt = rec.record(
            _TENANT,
            _AGENT,
            "llm_invoke",
            llm_prompt_content="Tell me a secret",
            llm_response_content="I cannot do that",
            timing_microseconds=42000,
        )
        assert evt.audit is not None
        assert evt.extended is not None
        assert evt.dvr is not None
        assert evt.dvr.llm_prompt_content == "Tell me a secret"
        assert evt.dvr.timing_microseconds == 42000

    def test_get_events_tenant_scoped(self):
        rec = self._make()
        rec.record(_TENANT, _AGENT, "tool_call")
        rec.record(_TENANT_B, _AGENT, "tool_call")
        assert len(rec.get_events(_TENANT)) == 1
        assert len(rec.get_events(_TENANT_B)) == 1

    def test_get_events_agent_filter(self):
        rec = self._make()
        rec.record(_TENANT, _AGENT, "tool_call")
        rec.record(_TENANT, _AGENT_B, "tool_call")
        assert len(rec.get_events(_TENANT, agent_id=_AGENT)) == 1

    def test_get_events_event_type_filter(self):
        rec = self._make()
        rec.record(_TENANT, _AGENT, "tool_call")
        rec.record(_TENANT, _AGENT, "llm_invoke")
        assert len(rec.get_events(_TENANT, event_type="tool_call")) == 1

    def test_session_timeline(self):
        rec = self._make()
        rec.record(_TENANT, _AGENT, "tool_call")
        rec.record(_TENANT, _AGENT, "llm_invoke")
        timeline = rec.get_session_timeline(_TENANT, _AGENT)
        assert len(timeline) == 2
        assert "audit" in timeline[0]

    def test_stats(self):
        rec = self._make()
        rec.record(_TENANT, _AGENT, "tool_call")
        stats = rec.stats(_TENANT)
        assert stats["total_events"] == 1

    def test_to_dict_serialization(self):
        rec = self._make()
        evt = rec.record(_TENANT, _AGENT, "tool_call")
        d = evt.to_dict()
        assert "id" in d
        assert d["level"] == 1
        assert d["tenant_id"] == _TENANT

    def test_get_configs(self):
        rec = self._make()
        rec.set_config(_TENANT, level=2)
        rec.set_config(_TENANT, agent_id=_AGENT, level=3)
        configs = rec.get_configs(_TENANT)
        assert len(configs) == 2

# ═══════════════════════════════════════════════════════════════════
#  AU2 — DVR Replay Engine
# ═══════════════════════════════════════════════════════════════════

class TestDVRReplayEngine:
    """Tests for DVR replay timeline reconstruction."""

    def _make(self):
        from app.services.recording.dvr_replay import DVRReplayEngine

        return DVRReplayEngine()

    def _sample_events(self):
        return [
            {
                "audit": {
                    "timestamp": "2026-03-08T10:00:00Z",
                    "agent_id": _AGENT,
                    "event_type": "user_message",
                    "result": "success",
                },
            },
            {
                "audit": {
                    "timestamp": "2026-03-08T10:00:01Z",
                    "agent_id": _AGENT,
                    "event_type": "llm_invoke",
                    "tool_name": "gpt-4",
                    "result": "success",
                },
            },
            {
                "audit": {
                    "timestamp": "2026-03-08T10:00:02Z",
                    "agent_id": _AGENT,
                    "event_type": "tool_call",
                    "tool_name": "mcp://db/query",
                    "result": "blocked",
                    "rule_matched": "exfil_detection_v2",
                },
            },
        ]

    def test_build_replay_creates_session(self):
        engine = self._make()
        session = engine.build_replay("sess-1", _TENANT, _AGENT, self._sample_events())
        assert session.session_id == "sess-1"
        assert len(session.steps) == 3

    def test_step_types_classified(self):
        engine = self._make()
        session = engine.build_replay("sess-2", _TENANT, _AGENT, self._sample_events())
        assert session.steps[0].step_type.value == "input"
        assert session.steps[1].step_type.value == "decision"
        assert session.steps[2].step_type.value == "blocked"

    def test_blocked_count(self):
        engine = self._make()
        session = engine.build_replay("sess-3", _TENANT, _AGENT, self._sample_events())
        assert session.blocked_count == 1

    def test_get_session_tenant_scoped(self):
        engine = self._make()
        engine.build_replay("sess-4", _TENANT, _AGENT, self._sample_events())
        assert engine.get_session("sess-4", _TENANT) is not None
        assert engine.get_session("sess-4", _TENANT_B) is None

    def test_list_sessions(self):
        engine = self._make()
        engine.build_replay("s1", _TENANT, _AGENT, self._sample_events())
        engine.build_replay("s2", _TENANT, _AGENT_B, self._sample_events())
        sessions = engine.list_sessions(_TENANT)
        assert len(sessions) == 2

    def test_compare_sessions(self):
        engine = self._make()
        engine.build_replay("cmp-a", _TENANT, _AGENT, self._sample_events())
        engine.build_replay("cmp-b", _TENANT, _AGENT, self._sample_events()[:2])
        result = engine.compare_sessions("cmp-a", "cmp-b", _TENANT)
        assert result is not None
        assert result["diff"]["step_count_delta"] == -1

    def test_compare_missing_session_returns_none(self):
        engine = self._make()
        engine.build_replay("cmp-c", _TENANT, _AGENT, self._sample_events())
        assert engine.compare_sessions("cmp-c", "nonexistent", _TENANT) is None

    def test_to_dict_serialization(self):
        engine = self._make()
        session = engine.build_replay("dict-1", _TENANT, _AGENT, self._sample_events())
        d = session.to_dict()
        assert d["step_count"] == 3
        assert len(d["steps"]) == 3

    def test_extended_fields_in_replay(self):
        engine = self._make()
        events = [
            {
                "audit": {
                    "timestamp": "2026-03-08T10:00:00Z",
                    "agent_id": _AGENT,
                    "event_type": "tool_call",
                    "tool_name": "db_query",
                    "result": "success",
                },
                "extended": {
                    "tool_parameters": {"sql": "SELECT 1"},
                    "llm_prompt_hash": "abc123",
                },
            },
        ]
        session = engine.build_replay("ext-1", _TENANT, _AGENT, events)
        assert session.steps[0].details.get("tool_parameters") == {"sql": "SELECT 1"}

    def test_dvr_fields_in_replay(self):
        engine = self._make()
        events = [
            {
                "audit": {
                    "timestamp": "2026-03-08T10:00:00Z",
                    "agent_id": _AGENT,
                    "event_type": "llm_invoke",
                    "result": "success",
                },
                "dvr": {
                    "llm_prompt_content": "Hello",
                    "llm_response_content": "Hi there",
                    "timing_microseconds": 5000,
                },
            },
        ]
        session = engine.build_replay("dvr-1", _TENANT, _AGENT, events)
        assert session.steps[0].details.get("llm_prompt") == "Hello"
        assert session.steps[0].duration_us == 5000

# ═══════════════════════════════════════════════════════════════════
#  AU3 — Tamper-Proof Audit Chain
# ═══════════════════════════════════════════════════════════════════

class TestTamperProofChain:
    """Tests for the HMAC-chained audit log."""

    def _make(self):
        from app.services.recording.tamper_proof_chain import TamperProofChain

        return TamperProofChain()

    def test_append_creates_entry(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        entry = chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        assert entry.entry_hash != ""
        assert entry.previous_hash == "genesis"

    def test_chain_links(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        e1 = chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        e2 = chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        assert e2.previous_hash == e1.entry_hash

    def test_verify_intact_chain(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        chain.append(_TENANT, ChainAction.LEVEL_CHANGED, _USER)
        result = chain.verify_chain(_TENANT)
        assert result["valid"] is True
        assert result["entries_checked"] == 2

    def test_verify_detects_tampering(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        chain.append(_TENANT, ChainAction.LEVEL_CHANGED, _USER)
        # Tamper with the first entry
        chain._entries[_TENANT][0].entry_hash = "tampered"
        result = chain.verify_chain(_TENANT)
        assert result["valid"] is False

    def test_verify_empty_chain(self):
        chain = self._make()
        result = chain.verify_chain(_TENANT)
        assert result["valid"] is True
        assert result["entries_checked"] == 0

    def test_tenant_isolation(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        chain.append(_TENANT_B, ChainAction.EVENT_RECORDED, _USER)
        assert chain.chain_length(_TENANT) == 1
        assert chain.chain_length(_TENANT_B) == 1

    def test_byok_key(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.set_tenant_key(_TENANT, b"my-custom-key-1234567890")
        e1 = chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        assert e1.entry_hash != ""
        result = chain.verify_chain(_TENANT)
        assert result["valid"] is True

    def test_legal_hold_set(self):
        chain = self._make()
        hold = chain.set_legal_hold(_TENANT, _AGENT, "Investigation IR-2026-42", _USER)
        assert hold.active is True
        assert chain.is_held(_TENANT, _AGENT) is True

    def test_legal_hold_release(self):
        chain = self._make()
        chain.set_legal_hold(_TENANT, _AGENT, "Reason", _USER)
        released = chain.release_legal_hold(_TENANT, _AGENT, _USER)
        assert released is not None
        assert released.active is False
        assert chain.is_held(_TENANT, _AGENT) is False

    def test_legal_hold_creates_chain_entries(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.set_legal_hold(_TENANT, _AGENT, "Reason", _USER)
        entries = chain.get_entries(_TENANT, action=ChainAction.LEGAL_HOLD_SET)
        assert len(entries) == 1

    def test_release_nonexistent_hold_returns_none(self):
        chain = self._make()
        assert chain.release_legal_hold(_TENANT, _AGENT, _USER) is None

    def test_get_entries_with_filters(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER, agent_id=_AGENT)
        chain.append(_TENANT, ChainAction.LEVEL_CHANGED, _USER, agent_id=_AGENT_B)
        assert len(chain.get_entries(_TENANT, agent_id=_AGENT)) == 1
        assert len(chain.get_entries(_TENANT, action=ChainAction.LEVEL_CHANGED)) == 1

    def test_stats(self):
        from app.services.recording.tamper_proof_chain import ChainAction

        chain = self._make()
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        chain.set_legal_hold(_TENANT, _AGENT, "Reason", _USER)
        stats = chain.stats(_TENANT)
        assert stats["chain_length"] >= 2
        assert stats["active_holds"] == 1

    def test_get_legal_holds_all(self):
        chain = self._make()
        chain.set_legal_hold(_TENANT, _AGENT, "Hold 1", _USER)
        chain.set_legal_hold(_TENANT, _AGENT_B, "Hold 2", _USER)
        chain.release_legal_hold(_TENANT, _AGENT, _USER)
        active = chain.get_legal_holds(_TENANT, active_only=True)
        all_holds = chain.get_legal_holds(_TENANT, active_only=False)
        assert len(active) == 1
        assert len(all_holds) == 2

# ═══════════════════════════════════════════════════════════════════
#  AU4 — Compliance Export
# ═══════════════════════════════════════════════════════════════════

class TestComplianceExporter:
    """Tests for compliance evidence package generation."""

    def _make(self):
        from app.services.recording.compliance_export import ComplianceExporter
        from app.services.recording.session_recorder import SessionRecorder
        from app.services.recording.tamper_proof_chain import ChainAction, TamperProofChain

        chain = TamperProofChain()
        recorder = SessionRecorder()
        exporter = ComplianceExporter(chain, recorder)

        # Seed some data
        recorder.set_config(_TENANT, level=2)
        recorder.record(_TENANT, _AGENT, "tool_call")
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        chain.append(_TENANT, ChainAction.LEVEL_CHANGED, _USER)

        return exporter, chain, recorder

    def test_generate_iso_export(self):
        from app.services.recording.compliance_export import ComplianceFramework

        exporter, _, _ = self._make()
        pkg = exporter.generate(_TENANT, ComplianceFramework.ISO_27001, _USER)
        assert pkg.framework.value == "iso_27001"
        assert pkg.chain_verification["valid"] is True
        assert pkg.summary["framework"] == "iso_27001"

    def test_generate_hipaa_export_filters_actions(self):
        from app.services.recording.compliance_export import ComplianceFramework

        exporter, chain, _ = self._make()
        from app.services.recording.tamper_proof_chain import ChainAction

        # Add non-HIPAA action
        chain.append(_TENANT, ChainAction.CONFIG_CHANGED, _USER)
        pkg = exporter.generate(_TENANT, ComplianceFramework.HIPAA, _USER)
        # HIPAA only includes: EVENT_RECORDED, LEGAL_HOLD_*, EXPORT_GENERATED
        for entry in pkg.audit_entries:
            assert entry["action"] in ("event_recorded", "legal_hold_set", "legal_hold_released", "export_generated")

    def test_export_records_in_chain(self):
        from app.services.recording.compliance_export import ComplianceFramework
        from app.services.recording.tamper_proof_chain import ChainAction

        exporter, chain, _ = self._make()
        exporter.generate(_TENANT, ComplianceFramework.SOC2, _USER)
        entries = chain.get_entries(_TENANT, action=ChainAction.EXPORT_GENERATED)
        assert len(entries) >= 1

    def test_list_exports(self):
        from app.services.recording.compliance_export import ComplianceFramework

        exporter, _, _ = self._make()
        exporter.generate(_TENANT, ComplianceFramework.ISO_27001, _USER)
        exporter.generate(_TENANT, ComplianceFramework.SOC2, _USER)
        exports = exporter.list_exports(_TENANT)
        assert len(exports) == 2

    def test_export_to_json(self):
        import json

        from app.services.recording.compliance_export import ComplianceFramework

        exporter, _, _ = self._make()
        pkg = exporter.generate(_TENANT, ComplianceFramework.FEDRAMP, _USER)
        j = pkg.to_json()
        parsed = json.loads(j)
        assert "audit_entries" in parsed
        assert parsed["framework"] == "fedramp"

    def test_export_to_dict_metadata_only(self):
        from app.services.recording.compliance_export import ComplianceFramework

        exporter, _, _ = self._make()
        pkg = exporter.generate(_TENANT, ComplianceFramework.ISO_27001, _USER)
        d = pkg.to_dict()
        assert "audit_entry_count" in d
        assert "audit_entries" not in d  # to_dict is metadata only

    def test_export_includes_legal_holds(self):
        from app.services.recording.compliance_export import ComplianceFramework

        exporter, chain, _ = self._make()
        chain.set_legal_hold(_TENANT, _AGENT, "Investigation", _USER)
        pkg = exporter.generate(_TENANT, ComplianceFramework.ISO_27001, _USER)
        assert len(pkg.legal_holds) >= 1

    def test_export_tenant_isolation(self):
        from app.services.recording.compliance_export import ComplianceFramework

        exporter, _, _ = self._make()
        pkg = exporter.generate(_TENANT_B, ComplianceFramework.ISO_27001, _USER)
        # Different tenant should have no data
        assert pkg.summary["entries_in_period"] == 0

# ═══════════════════════════════════════════════════════════════════
#  Security regression tests
# ═══════════════════════════════════════════════════════════════════

class TestSecurityRegression:
    """Regression tests for AU security audit fixes."""

    def test_no_hardcoded_hmac_default_key(self):
        """Ensure TamperProofChain no longer uses a hardcoded default key."""
        from app.services.recording.tamper_proof_chain import TamperProofChain

        chain = TamperProofChain()
        assert chain._DEFAULT_KEY is None

    def test_random_key_per_tenant(self):
        """Each tenant gets an auto-generated random key."""
        from app.services.recording.tamper_proof_chain import ChainAction, TamperProofChain

        chain = TamperProofChain()
        chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        chain.append(_TENANT_B, ChainAction.EVENT_RECORDED, _USER)
        key_a = chain._tenant_keys[_TENANT]
        key_b = chain._tenant_keys[_TENANT_B]
        assert key_a != key_b
        assert len(key_a) == 32
        assert len(key_b) == 32

    def test_session_recorder_memory_bound(self):
        """SessionRecorder evicts oldest events beyond cap."""
        from app.services.recording.session_recorder import SessionRecorder

        rec = SessionRecorder()
        rec._max_events = 5  # Lower cap for test
        for i in range(10):
            rec.record(_TENANT, _AGENT, f"event_{i}")
        assert len(rec._events) == 5

    def test_chain_memory_bound(self):
        """TamperProofChain evicts oldest entries beyond cap."""
        from app.services.recording.tamper_proof_chain import ChainAction, TamperProofChain

        chain = TamperProofChain()
        chain._MAX_ENTRIES_PER_TENANT = 5
        for _i in range(10):
            chain.append(_TENANT, ChainAction.EVENT_RECORDED, _USER)
        assert len(chain._entries[_TENANT]) == 5

    def test_replay_memory_bound(self):
        """DVRReplayEngine evicts oldest sessions beyond cap."""
        from app.services.recording.dvr_replay import DVRReplayEngine

        engine = DVRReplayEngine()
        engine._max_sessions = 3
        events = [{"audit": {"timestamp": "2026-01-01T00:00:00Z", "agent_id": _AGENT, "event_type": "tool_call"}}]
        for i in range(6):
            engine.build_replay(f"sess-{i}", _TENANT, _AGENT, events)
        assert len(engine._sessions) == 3

    def test_set_config_disabled(self):
        """Recorder can disable recording for an agent."""
        from app.services.recording.session_recorder import RecordingLevel, SessionRecorder

        rec = SessionRecorder()
        rec.set_config(_TENANT, agent_id=_AGENT, level=RecordingLevel.AUDIT, enabled=False)
        config = rec.get_config(_TENANT, _AGENT)
        assert config.enabled is False
        evt = rec.record(_TENANT, _AGENT, "tool_call")
        # Disabled recording returns minimal event, not added to store
        assert evt.audit is None
