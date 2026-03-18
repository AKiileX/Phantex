# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — A2A Protocol Support tests.

Covers: registry, task_tracker, correlator, fingerprinter.
"""

from __future__ import annotations

import uuid

import pytest

from app.services.a2a.correlator import A2AMCPCorrelator
from app.services.a2a.fingerprinter import ProtocolFingerprinter
from app.services.a2a.registry import AgentCardRegistry, CardStatus
from app.services.a2a.task_tracker import TaskFlowTracker, TaskStatus

_TENANT = uuid.uuid4()

# ── Registry tests ────────────────────────────────────────────────────────────

class TestAgentCardRegistry:
    def _make_card(self, **overrides):
        base = {"name": "agent-a", "url": "https://agent-a.local", "capabilities": ["summarise"]}
        base.update(overrides)
        return base

    def test_register_and_list(self):
        reg = AgentCardRegistry()
        card, val = reg.register(_TENANT, self._make_card())
        assert card.name == "agent-a"
        assert card.status == CardStatus.UNVERIFIED
        assert len(reg.list_cards(_TENANT)) == 1

    def test_register_missing_field_raises(self):
        reg = AgentCardRegistry()
        with pytest.raises(ValueError, match="Invalid agent card"):
            reg.register(_TENANT, {"name": "x"})

    def test_verify_and_revoke(self):
        reg = AgentCardRegistry()
        card, _ = reg.register(_TENANT, self._make_card())
        assert reg.verify(_TENANT, card.id) is True
        assert reg.get(_TENANT, card.id).status == CardStatus.VERIFIED
        assert reg.revoke(_TENANT, card.id) is True
        assert reg.get(_TENANT, card.id).status == CardStatus.REVOKED

    def test_verify_unknown_returns_false(self):
        reg = AgentCardRegistry()
        assert reg.verify(_TENANT, uuid.uuid4()) is False

    def test_revoke_unknown_returns_false(self):
        reg = AgentCardRegistry()
        assert reg.revoke(_TENANT, uuid.uuid4()) is False

    def test_verify_revoked_card_blocked(self):
        """Once revoked, a card cannot be re-verified."""
        reg = AgentCardRegistry()
        card, _ = reg.register(_TENANT, self._make_card())
        reg.revoke(_TENANT, card.id)
        assert reg.verify(_TENANT, card.id) is False
        assert reg.get(_TENANT, card.id).status == CardStatus.REVOKED

    def test_list_filter_by_status(self):
        reg = AgentCardRegistry()
        c1, _ = reg.register(_TENANT, self._make_card(name="a1"))
        reg.register(_TENANT, self._make_card(name="a2"))
        reg.verify(_TENANT, c1.id)
        assert len(reg.list_cards(_TENANT, status=CardStatus.VERIFIED)) == 1
        assert len(reg.list_cards(_TENANT, status=CardStatus.UNVERIFIED)) == 1

    def test_list_filter_by_capability(self):
        reg = AgentCardRegistry()
        reg.register(_TENANT, self._make_card(name="a1", capabilities=["code_execution"]))
        reg.register(_TENANT, self._make_card(name="a2", capabilities=["summarise"]))
        assert len(reg.list_cards(_TENANT, capability="code_execution")) == 1

    def test_drift_detection_on_reregister(self):
        """Re-registering with different capabilities resets to unverified."""
        reg = AgentCardRegistry()
        c1, _ = reg.register(_TENANT, self._make_card())
        reg.verify(_TENANT, c1.id)
        assert reg.get(_TENANT, c1.id).status == CardStatus.VERIFIED
        c2, val = reg.register(_TENANT, self._make_card(capabilities=["code_execution"]))
        # Drift should reset status
        assert c2.status == CardStatus.UNVERIFIED
        assert any("drift" in w.lower() or "changed" in w.lower() for w in val.warnings)

    def test_tenant_isolation(self):
        """Cards from one tenant are invisible to another."""
        reg = AgentCardRegistry()
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        reg.register(t1, self._make_card(name="a1"))
        reg.register(t2, self._make_card(name="a2"))
        assert len(reg.list_cards(t1)) == 1
        assert len(reg.list_cards(t2)) == 1
        assert reg.list_cards(t1)[0].name == "a1"

    def test_stats(self):
        reg = AgentCardRegistry()
        reg.register(_TENANT, self._make_card(name="a1"))
        reg.register(_TENANT, self._make_card(name="a2"))
        s = reg.stats(_TENANT)
        assert s["total"] == 2
        assert s["unverified"] == 2

    def test_sensitive_capability_flagged(self):
        reg = AgentCardRegistry()
        _, val = reg.register(_TENANT, self._make_card(capabilities=["code_execution"]))
        assert "code_execution" in val.sensitive_capabilities

    def test_url_https_warning(self):
        """Non-HTTPS URL should produce a warning."""
        reg = AgentCardRegistry()
        _, val = reg.register(_TENANT, self._make_card(url="http://insecure.example.com"))
        assert any("HTTPS" in w or "https" in w.lower() for w in val.warnings)

# ── Task Tracker tests ────────────────────────────────────────────────────────

class TestTaskFlowTracker:
    def test_record_delegation(self):
        tr = TaskFlowTracker()
        task = tr.record_delegation(_TENANT, "agent-a", "agent-b", "summarise")
        assert task.source_agent_id == "agent-a"
        assert task.status == TaskStatus.SUBMITTED

    def test_update_status(self):
        tr = TaskFlowTracker()
        task = tr.record_delegation(_TENANT, "a", "b", "cap")
        t2 = tr.update_status(_TENANT, task.task_id, TaskStatus.WORKING)
        assert t2.status == TaskStatus.WORKING
        t3 = tr.update_status(_TENANT, task.task_id, TaskStatus.COMPLETED)
        assert t3.status == TaskStatus.COMPLETED
        assert t3.completed_at is not None

    def test_update_unknown_returns_none(self):
        tr = TaskFlowTracker()
        assert tr.update_status(_TENANT, "nope", TaskStatus.WORKING) is None

    def test_chain_depth_tracking(self):
        tr = TaskFlowTracker()
        t1 = tr.record_delegation(_TENANT, "a", "b", "cap")
        t2 = tr.record_delegation(_TENANT, "b", "c", "cap", parent_task_id=t1.task_id)
        assert t2.chain_depth == 1

    def test_deep_chain_raises(self):
        """Chains deeper than 10 are rejected with ValueError."""
        tr = TaskFlowTracker()
        parent = None
        for i in range(11):
            t = tr.record_delegation(_TENANT, f"a{i}", f"a{i + 1}", "cap", parent_task_id=parent)
            parent = t.task_id
        with pytest.raises(ValueError, match="chain depth"):
            tr.record_delegation(_TENANT, "a11", "a12", "cap", parent_task_id=parent)

    def test_cycle_detection_raises(self):
        """Delegation back to an ancestor raises ValueError."""
        tr = TaskFlowTracker()
        t1 = tr.record_delegation(_TENANT, "a", "b", "cap")
        t2 = tr.record_delegation(_TENANT, "b", "c", "cap", parent_task_id=t1.task_id)
        with pytest.raises(ValueError, match="Circular"):
            tr.record_delegation(_TENANT, "c", "a", "cap", parent_task_id=t2.task_id)

    def test_self_delegation_raises(self):
        """Delegating to self is a cycle."""
        tr = TaskFlowTracker()
        with pytest.raises(ValueError, match="Circular"):
            tr.record_delegation(_TENANT, "a", "a", "cap")

    def test_communication_graph(self):
        tr = TaskFlowTracker()
        tr.record_delegation(_TENANT, "a", "b", "cap1")
        tr.record_delegation(_TENANT, "a", "b", "cap2")
        tr.record_delegation(_TENANT, "b", "c", "cap3")
        g = tr.communication_graph(_TENANT)
        assert len(g["nodes"]) == 3
        assert len(g["edges"]) == 2

    def test_list_tasks_with_filter(self):
        tr = TaskFlowTracker()
        t = tr.record_delegation(_TENANT, "a", "b", "cap")
        tr.update_status(_TENANT, t.task_id, TaskStatus.COMPLETED)
        tr.record_delegation(_TENANT, "c", "d", "cap")
        completed = tr.list_tasks(_TENANT, status=TaskStatus.COMPLETED)
        assert len(completed) == 1

    def test_tenant_isolation(self):
        tr = TaskFlowTracker()
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        tr.record_delegation(t1, "a", "b", "cap")
        tr.record_delegation(t2, "c", "d", "cap")
        assert len(tr.list_tasks(t1)) == 1
        assert len(tr.list_tasks(t2)) == 1

    def test_stats(self):
        tr = TaskFlowTracker()
        tr.record_delegation(_TENANT, "a", "b", "cap")
        s = tr.stats(_TENANT)
        assert s["total_tasks"] == 1

    def test_delegation_chain_walk(self):
        """get_delegation_chain should return full chain."""
        tr = TaskFlowTracker()
        t1 = tr.record_delegation(_TENANT, "a", "b", "cap")
        t2 = tr.record_delegation(_TENANT, "b", "c", "cap", parent_task_id=t1.task_id)
        chain = tr.get_delegation_chain(_TENANT, t2.task_id)
        assert chain is not None
        assert chain.total_depth == 2
        assert chain.initiator == "a"

# ── Correlator tests ──────────────────────────────────────────────────────────

class TestA2AMCPCorrelator:
    def test_ingest_a2a_and_mcp_creates_finding(self):
        cor = A2AMCPCorrelator()
        cor.ingest_a2a_task(
            _TENANT, {"task_id": "t1", "target_agent_id": "agent-a", "source_agent_id": "src", "capability": "write"}
        )
        findings = cor.ingest_mcp_call(_TENANT, {"agent_id": "agent-a", "tool_name": "write_file", "call_id": "c1"})
        assert len(findings) > 0
        assert findings[0].severity == "high"

    def test_no_correlation_without_a2a(self):
        cor = A2AMCPCorrelator()
        findings = cor.ingest_mcp_call(_TENANT, {"agent_id": "agent-x", "tool_name": "write_file", "call_id": "c1"})
        assert len(findings) == 0

    def test_non_sensitive_tool_no_finding(self):
        """Non-sensitive MCP tool should not produce a correlation."""
        cor = A2AMCPCorrelator()
        cor.ingest_a2a_task(
            _TENANT, {"task_id": "t1", "target_agent_id": "a1", "source_agent_id": "src", "capability": "read"}
        )
        findings = cor.ingest_mcp_call(_TENANT, {"agent_id": "a1", "tool_name": "read_file", "call_id": "c1"})
        assert len(findings) == 0

    def test_sensitive_tool_produces_high_finding(self):
        cor = A2AMCPCorrelator()
        cor.ingest_a2a_task(
            _TENANT, {"task_id": "t2", "target_agent_id": "agent-b", "source_agent_id": "src", "capability": "exec"}
        )
        findings = cor.ingest_mcp_call(_TENANT, {"agent_id": "agent-b", "tool_name": "exec", "call_id": "c2"})
        assert len(findings) > 0
        assert all(f.severity == "high" for f in findings)

    def test_tenant_isolation(self):
        cor = A2AMCPCorrelator()
        t1, t2 = uuid.uuid4(), uuid.uuid4()
        cor.ingest_a2a_task(t1, {"task_id": "t1", "target_agent_id": "a", "source_agent_id": "s", "capability": "x"})
        findings = cor.ingest_mcp_call(t2, {"agent_id": "a", "tool_name": "exec", "call_id": "c"})
        assert len(findings) == 0  # Different tenants — no correlation

    def test_recent_correlations_summary(self):
        cor = A2AMCPCorrelator()
        cor.ingest_a2a_task(
            _TENANT, {"task_id": "t1", "target_agent_id": "a1", "source_agent_id": "s", "capability": "x"}
        )
        s = cor.recent_correlations(_TENANT)
        assert s["recent_a2a_tasks"] == 1

# ── Fingerprinter tests ──────────────────────────────────────────────────────

class TestProtocolFingerprinter:
    def test_valid_agent_card_scores_high(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint(
            {
                "name": "agent-x",
                "url": "https://agent-x.local",
                "capabilities": ["summarise"],
                "version": "1.0",
            }
        )
        assert result.conformance_score >= 0.8
        assert result.message_type == "agent_card"
        assert not result.suspicious

    def test_minimal_card_missing_fields(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint({"name": "x"}, message_type="agent_card")
        assert result.conformance_score < 0.7
        assert result.suspicious
        assert any("Missing" in d for d in result.deviations)

    def test_valid_task_request(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint(
            {
                "task_id": "abcd-1234",
                "source_agent": "a",
                "target_agent": "b",
                "capability": "summarise",
            }
        )
        assert result.message_type == "task_request"
        assert result.conformance_score >= 0.8

    def test_valid_task_response(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint(
            {
                "task_id": "abcd",
                "status": "completed",
                "result": {"text": "done"},
            }
        )
        assert result.message_type == "task_response"
        assert result.conformance_score >= 0.8

    def test_unknown_message_type(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint({"random": "data"})
        assert result.message_type == "unknown"
        assert result.suspicious

    def test_invalid_status_in_response(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint({"task_id": "x", "status": "banana"}, message_type="task_response")
        assert any("Invalid status" in d for d in result.deviations)

    def test_extra_fields_produce_warnings(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint(
            {
                "name": "a",
                "url": "https://a.local",
                "capabilities": ["x"],
                "custom_field": "suspicious",
            }
        )
        assert len(result.warnings) > 0

    def test_malformed_url_deviation(self):
        fp = ProtocolFingerprinter()
        result = fp.fingerprint(
            {
                "name": "a",
                "url": "not-a-url",
                "capabilities": ["x"],
            },
            message_type="agent_card",
        )
        assert any("Malformed" in d for d in result.deviations)
