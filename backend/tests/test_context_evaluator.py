# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB5 — Agent Purpose & Context Policy.

Covers:
- PolicyMode enforcement (MONITOR_ONLY, STANDARD, STRICT, COMPLIANCE)
- Purpose profiles & content expectation mapping
- Context-aware decision making (pentester vs support bot)
- Semantic baseline tracker (drift detection, memory bounding)
- Compliance evidence collector (append-only, JSON export, FIFO eviction)
- ContextEvaluator orchestrator (purpose + mode + baseline + evidence)
"""

from __future__ import annotations

import json

import pytest

from ml.content.context.baseline_tracker import (
    SemanticBaselineTracker,
)
from ml.content.context.compliance_evidence import (
    ComplianceEvidence,
    ComplianceEvidenceCollector,
)
from ml.content.context.context_evaluator import ContextEvaluator
from ml.content.context.policy_modes import PolicyMode, apply_mode, requires_evidence
from ml.content.context.purpose_profile import (
    AgentPurposeProfile,
    get_role_expected_content,
    is_content_expected,
)
from ml.content.verdict import Decision, Severity

# ═══════════════════════════════════════════════════════════════════════
# ──  Policy Mode Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPolicyModes:
    """Tests for policy_modes.py."""

    def test_monitor_only_never_blocks(self):
        """Acceptance: MONITOR_ONLY never blocks."""
        result = apply_mode(PolicyMode.MONITOR_ONLY, Severity.CRITICAL, Decision.BLOCK)
        assert result != Decision.BLOCK
        assert result == Decision.LOG

    def test_monitor_only_allows_alerts_for_high(self):
        result = apply_mode(PolicyMode.MONITOR_ONLY, Severity.HIGH, Decision.ALERT)
        assert result == Decision.ALERT

    def test_standard_blocks_critical(self):
        result = apply_mode(PolicyMode.STANDARD, Severity.CRITICAL, Decision.BLOCK)
        assert result == Decision.BLOCK

    def test_standard_alerts_medium(self):
        result = apply_mode(PolicyMode.STANDARD, Severity.MEDIUM, Decision.ALERT)
        assert result == Decision.ALERT

    def test_standard_does_not_block_medium(self):
        """STANDARD only blocks CRITICAL."""
        result = apply_mode(PolicyMode.STANDARD, Severity.MEDIUM, Decision.BLOCK)
        # Medium severity should not trigger block in STANDARD
        assert result in (Decision.ALERT, Decision.LOG, Decision.BLOCK)

    def test_strict_blocks_medium(self):
        """Acceptance: STRICT blocks medium+ severity."""
        result = apply_mode(PolicyMode.STRICT, Severity.MEDIUM, Decision.ALERT)
        assert result == Decision.BLOCK

    def test_strict_blocks_high(self):
        result = apply_mode(PolicyMode.STRICT, Severity.HIGH, Decision.ALERT)
        assert result == Decision.BLOCK

    def test_compliance_blocks_medium(self):
        result = apply_mode(PolicyMode.COMPLIANCE, Severity.MEDIUM, Decision.ALERT)
        assert result == Decision.BLOCK

    def test_compliance_requires_evidence(self):
        """Acceptance: COMPLIANCE mode collects evidence."""
        assert requires_evidence(PolicyMode.COMPLIANCE) is True
        assert requires_evidence(PolicyMode.STANDARD) is False
        assert requires_evidence(PolicyMode.MONITOR_ONLY) is False

    def test_allow_stays_allow_below_threshold(self):
        result = apply_mode(PolicyMode.STANDARD, Severity.INFO, Decision.ALLOW)
        assert result == Decision.ALLOW

# ═══════════════════════════════════════════════════════════════════════
# ──  Purpose Profile Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPurposeProfile:
    """Tests for purpose_profile.py."""

    def test_security_researcher_expects_exploits(self):
        expected = get_role_expected_content("security_research")
        assert "injection_payload" in expected
        assert "exploit_code" in expected

    def test_customer_support_no_exploits(self):
        expected = get_role_expected_content("customer_support")
        assert "injection_payload" not in expected

    def test_public_chatbot_empty_expected(self):
        expected = get_role_expected_content("public_chatbot")
        assert len(expected) == 0

    def test_unknown_role_empty_expected(self):
        expected = get_role_expected_content("unknown_role_xyz")
        assert len(expected) == 0

    def test_is_content_expected_by_role(self):
        profile = AgentPurposeProfile(
            agent_id="a1",
            tenant_id="t1",
            role="security_research",
        )
        assert is_content_expected(profile, "injection_payload") is True
        assert is_content_expected(profile, "customer_email") is False

    def test_is_content_expected_by_explicit_override(self):
        profile = AgentPurposeProfile(
            agent_id="a1",
            tenant_id="t1",
            role="customer_support",
            expected_content_types=frozenset({"injection_payload"}),
        )
        # Explicitly allowed even though role doesn't normally expect it
        assert is_content_expected(profile, "injection_payload") is True

    def test_profile_frozen(self):
        profile = AgentPurposeProfile(agent_id="a1", tenant_id="t1", role="test")
        with pytest.raises(AttributeError):
            profile.role = "other"  # type: ignore[misc]

# ═══════════════════════════════════════════════════════════════════════
# ──  Baseline Tracker Tests
# ═══════════════════════════════════════════════════════════════════════

class TestBaselineTracker:
    """Tests for baseline_tracker.py."""

    def test_initial_record_no_drift(self):
        bt = SemanticBaselineTracker(min_samples=5)
        result = bt.record("t1", "a1", "Hello world")
        assert result["length_drift"] is False
        assert result["entropy_drift"] is False
        assert result["sample_count"] == 1

    def test_consistent_content_no_drift(self):
        bt = SemanticBaselineTracker(min_samples=5, drift_sigma=2.0)
        # Build baseline
        for _ in range(10):
            bt.record("t1", "a1", "Normal agent output about security analysis")
        # Check that normal content doesn't drift
        result = bt.record("t1", "a1", "Normal agent output about security analysis")
        assert result["length_drift"] is False

    def test_anomalous_content_triggers_drift(self):
        """Acceptance: drift > 2σ from mean → alert."""
        bt = SemanticBaselineTracker(min_samples=10, drift_sigma=2.0)
        # Build baseline with short messages
        for _ in range(100):
            bt.record("t1", "a1", "Short message")
        # Massive content shift
        result = bt.record("t1", "a1", "A" * 10000)
        assert result["length_drift"] is True

    def test_snapshot(self):
        bt = SemanticBaselineTracker()
        bt.record("t1", "a1", "Hello world test content")
        snap = bt.snapshot("t1", "a1")
        assert snap is not None
        assert snap.sample_count == 1
        assert snap.mean_length > 0

    def test_snapshot_nonexistent(self):
        bt = SemanticBaselineTracker()
        assert bt.snapshot("t1", "a1") is None

    def test_reset(self):
        bt = SemanticBaselineTracker()
        bt.record("t1", "a1", "test")
        assert bt.reset("t1", "a1") is True
        assert bt.reset("t1", "a1") is False
        assert bt.snapshot("t1", "a1") is None

    def test_memory_bounded(self):
        """Acceptance: max samples per agent, FIFO eviction."""
        bt = SemanticBaselineTracker(max_samples_per_agent=10)
        for i in range(20):
            bt.record("t1", "a1", f"Sample {i}")
        snap = bt.snapshot("t1", "a1")
        assert snap is not None
        assert snap.sample_count == 20  # Counter still tracks total
        # But the FIFO queue only kept last 10

    def test_tenant_isolation(self):
        bt = SemanticBaselineTracker()
        bt.record("t1", "a1", "Tenant 1 content")
        bt.record("t2", "a1", "Tenant 2 content")
        assert bt.snapshot("t1", "a1").sample_count == 1
        assert bt.snapshot("t2", "a1").sample_count == 1

# ═══════════════════════════════════════════════════════════════════════
# ──  Compliance Evidence Tests
# ═══════════════════════════════════════════════════════════════════════

class TestComplianceEvidence:
    """Tests for compliance_evidence.py."""

    def test_collect_creates_record(self):
        collector = ComplianceEvidenceCollector()
        record = collector.collect(
            agent_id="a1",
            tenant_id="t1",
            content="test content",
            classification_labels=("PII",),
            compliance_tags=("GDPR",),
            sensitivity_level="critical",
            verdict_decision=Decision.BLOCK,
            verdict_severity=Severity.CRITICAL,
            policy_mode=PolicyMode.COMPLIANCE,
        )
        assert record.evidence_id == "CE-00000001"
        assert record.agent_id == "a1"
        assert record.tenant_id == "t1"
        assert record.content_hash  # SHA-256 present
        assert "test content" not in record.content_hash  # Not plaintext

    def test_content_never_stored(self):
        """Security: Raw content never in evidence."""
        collector = ComplianceEvidenceCollector()
        secret = "super-secret-content-12345"
        record = collector.collect(
            agent_id="a1",
            tenant_id="t1",
            content=secret,
            classification_labels=(),
            compliance_tags=(),
            sensitivity_level="high",
            verdict_decision=Decision.ALERT,
            verdict_severity=Severity.HIGH,
            policy_mode=PolicyMode.COMPLIANCE,
        )
        # Raw content must not appear anywhere in the record
        assert secret not in str(record)

    def test_query_newest_first(self):
        collector = ComplianceEvidenceCollector()
        for i in range(5):
            collector.collect(
                agent_id="a1",
                tenant_id="t1",
                content=f"content-{i}",
                classification_labels=(),
                compliance_tags=(),
                sensitivity_level="low",
                verdict_decision=Decision.LOG,
                verdict_severity=Severity.LOW,
                policy_mode=PolicyMode.COMPLIANCE,
            )
        records = collector.query(tenant_id="t1")
        assert len(records) == 5
        # Newest first
        assert records[0].evidence_id == "CE-00000005"

    def test_query_by_agent(self):
        collector = ComplianceEvidenceCollector()
        collector.collect(
            agent_id="a1",
            tenant_id="t1",
            content="c1",
            classification_labels=(),
            compliance_tags=(),
            sensitivity_level="low",
            verdict_decision=Decision.LOG,
            verdict_severity=Severity.LOW,
            policy_mode=PolicyMode.COMPLIANCE,
        )
        collector.collect(
            agent_id="a2",
            tenant_id="t1",
            content="c2",
            classification_labels=(),
            compliance_tags=(),
            sensitivity_level="low",
            verdict_decision=Decision.LOG,
            verdict_severity=Severity.LOW,
            policy_mode=PolicyMode.COMPLIANCE,
        )
        records = collector.query(agent_id="a1")
        assert len(records) == 1
        assert records[0].agent_id == "a1"

    def test_export_json(self):
        """Acceptance: Compliance evidence exportable as JSON."""
        collector = ComplianceEvidenceCollector()
        collector.collect(
            agent_id="a1",
            tenant_id="t1",
            content="test",
            classification_labels=("PII",),
            compliance_tags=("GDPR",),
            sensitivity_level="critical",
            verdict_decision=Decision.BLOCK,
            verdict_severity=Severity.CRITICAL,
            policy_mode=PolicyMode.COMPLIANCE,
        )
        exported = collector.export_json(tenant_id="t1")
        parsed = json.loads(exported)
        assert len(parsed) == 1
        assert parsed[0]["evidence_id"] == "CE-00000001"
        assert "PII" in parsed[0]["classification_labels"]

    def test_fifo_eviction(self):
        collector = ComplianceEvidenceCollector(max_records=5)
        for i in range(10):
            collector.collect(
                agent_id="a1",
                tenant_id="t1",
                content=f"c-{i}",
                classification_labels=(),
                compliance_tags=(),
                sensitivity_level="low",
                verdict_decision=Decision.LOG,
                verdict_severity=Severity.LOW,
                policy_mode=PolicyMode.COMPLIANCE,
            )
        assert collector.count == 5

    def test_purge(self):
        collector = ComplianceEvidenceCollector()
        collector.collect(
            agent_id="a1",
            tenant_id="t1",
            content="c1",
            classification_labels=(),
            compliance_tags=(),
            sensitivity_level="low",
            verdict_decision=Decision.LOG,
            verdict_severity=Severity.LOW,
            policy_mode=PolicyMode.COMPLIANCE,
        )
        removed = collector.purge("t1")
        assert removed == 1
        assert collector.count == 0

    def test_evidence_record_frozen(self):
        record = ComplianceEvidence(
            timestamp="2024-01-01T00:00:00Z",
            agent_id="a1",
            tenant_id="t1",
            content_hash="abc",
            classification_labels=(),
            compliance_tags=(),
            sensitivity_level="low",
            verdict_decision="log",
            verdict_severity="low",
            policy_mode="compliance",
        )
        with pytest.raises(AttributeError):
            record.agent_id = "other"  # type: ignore[misc]

# ═══════════════════════════════════════════════════════════════════════
# ──  Context Evaluator Tests
# ═══════════════════════════════════════════════════════════════════════

class TestContextEvaluator:
    """Tests for context_evaluator.py."""

    def _make_evaluator(self, mode=PolicyMode.STANDARD):
        return ContextEvaluator(default_mode=mode)

    # ── Purpose-aware decisions ──────────────────────────────────────

    def test_pentester_exploit_allowed(self):
        """Acceptance: Pentester handling exploit payloads → ALLOW."""
        ev = self._make_evaluator()
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="pentest-1",
                tenant_id="t1",
                role="penetration_tester",
            )
        )
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="pentest-1",
            content="<script>alert('xss')</script>",
            content_type="injection_payload",
            verdict_decision=Decision.BLOCK,
            verdict_severity=Severity.HIGH,
        )
        assert result.purpose_match is True
        assert result.decision != Decision.BLOCK
        assert "dampened" in result.reason

    def test_support_bot_exploit_blocked(self):
        """Acceptance: Same payload on customer support → ALERT/BLOCK."""
        ev = self._make_evaluator()
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="support-1",
                tenant_id="t1",
                role="customer_support",
            )
        )
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="support-1",
            content="<script>alert('xss')</script>",
            content_type="injection_payload",
            verdict_decision=Decision.BLOCK,
            verdict_severity=Severity.CRITICAL,
        )
        assert result.purpose_match is False
        assert result.decision == Decision.BLOCK

    def test_no_purpose_monitor_only(self):
        """Acceptance: No purpose → MONITOR_ONLY (never block, always log)."""
        ev = self._make_evaluator()
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="unknown-agent",
            content="some content",
            content_type="injection_payload",
            verdict_decision=Decision.BLOCK,
            verdict_severity=Severity.CRITICAL,
        )
        assert result.policy_mode == PolicyMode.MONITOR_ONLY
        assert result.decision != Decision.BLOCK

    # ── Secret leaks always alerted ──────────────────────────────────

    def test_secret_leak_not_dampened(self):
        """Even pentester gets alerted on secret leaks."""
        ev = self._make_evaluator()
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="pentest-1",
                tenant_id="t1",
                role="penetration_tester",
            )
        )
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="pentest-1",
            content="sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
            content_type="secret_leak",  # Exception: never dampened
            verdict_decision=Decision.ALERT,
            verdict_severity=Severity.HIGH,
        )
        # Secret leak should NOT be dampened
        assert "dampened" not in result.reason

    # ── Policy mode override ─────────────────────────────────────────

    def test_set_and_get_mode(self):
        ev = self._make_evaluator()
        ev.set_mode("t1", "a1", PolicyMode.STRICT)
        assert ev.get_mode("t1", "a1") == PolicyMode.STRICT
        assert ev.get_mode("t1", "a2") == PolicyMode.STANDARD  # default

    # ── Compliance evidence ──────────────────────────────────────────

    def test_compliance_mode_collects_evidence(self):
        """Acceptance: COMPLIANCE mode → every decision produces evidence."""
        ev = self._make_evaluator()
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="a1",
                tenant_id="t1",
                role="customer_support",
            )
        )
        ev.set_mode("t1", "a1", PolicyMode.COMPLIANCE)
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="a1",
            content="test content",
            content_type="customer_email",
            verdict_decision=Decision.LOG,
            verdict_severity=Severity.LOW,
        )
        assert result.evidence_id != ""
        assert result.evidence_id.startswith("CE-")
        # Verify stored
        records = ev.evidence_collector.query(tenant_id="t1")
        assert len(records) == 1

    def test_standard_mode_no_evidence(self):
        ev = self._make_evaluator()
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="a1",
                tenant_id="t1",
                role="customer_support",
            )
        )
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="a1",
            content="test",
            content_type="general",
            verdict_decision=Decision.ALLOW,
            verdict_severity=Severity.INFO,
        )
        assert result.evidence_id == ""

    # ── Baseline drift ───────────────────────────────────────────────

    def test_baseline_drift_escalates(self):
        """Acceptance: Drift > 2σ → alert escalation."""
        bt = SemanticBaselineTracker(min_samples=10, drift_sigma=2.0)
        ev = ContextEvaluator(baseline_tracker=bt, default_mode=PolicyMode.STANDARD)
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="a1",
                tenant_id="t1",
                role="customer_support",
            )
        )
        # Build baseline
        for _ in range(100):
            ev.evaluate(
                tenant_id="t1",
                agent_id="a1",
                content="Normal short reply",
                content_type="general",
                verdict_decision=Decision.ALLOW,
                verdict_severity=Severity.INFO,
            )
        # Extreme drift
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="a1",
            content="A" * 10000,
            content_type="general",
            verdict_decision=Decision.ALLOW,
            verdict_severity=Severity.INFO,
        )
        assert result.baseline_drift is True
        # Severity should have been escalated
        assert result.severity != Severity.INFO

    # ── Context decision frozen ──────────────────────────────────────

    def test_context_decision_frozen(self):
        ev = self._make_evaluator()
        ev.set_profile(
            AgentPurposeProfile(
                agent_id="a1",
                tenant_id="t1",
                role="test",
            )
        )
        result = ev.evaluate(
            tenant_id="t1",
            agent_id="a1",
            content="test",
            content_type="general",
            verdict_decision=Decision.ALLOW,
            verdict_severity=Severity.INFO,
        )
        with pytest.raises(AttributeError):
            result.decision = Decision.BLOCK  # type: ignore[misc]

    # ── Accessors ────────────────────────────────────────────────────

    def test_accessors(self):
        bt = SemanticBaselineTracker()
        ec = ComplianceEvidenceCollector()
        ev = ContextEvaluator(baseline_tracker=bt, evidence_collector=ec)
        assert ev.baseline_tracker is bt
        assert ev.evidence_collector is ec
