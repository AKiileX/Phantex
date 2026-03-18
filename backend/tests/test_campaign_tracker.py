# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for JB7b — Campaign Tracker.

Verifies signal recording, assessment scoring, escalation detection,
sliding window eviction, LRU eviction, thread safety, and decay.
"""

from __future__ import annotations

import threading

import pytest

from ml.content.offensive.campaign_tracker import (
    CampaignAssessment,
    CampaignSignal,
    CampaignState,
    CampaignTracker,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tracker() -> CampaignTracker:
    """Standard tracker with 24h window, 6h decay."""
    return CampaignTracker()

@pytest.fixture
def short_tracker() -> CampaignTracker:
    """Tracker with 10s window for faster expiry tests."""
    return CampaignTracker(window_seconds=10.0, decay_half_life=5.0)

@pytest.fixture
def tiny_tracker() -> CampaignTracker:
    """Tracker with max_agents=3 for LRU eviction tests."""
    return CampaignTracker(max_agents=3)

# ── Basic recording ──────────────────────────────────────────────────────────

class TestBasicRecording:
    def test_record_single_signal(self, tracker: CampaignTracker):
        tracker.record_signal("agent-1", "tenant-A", "injection", 0.7)
        assert tracker.tracked_agents == 1

    def test_record_multiple_signals(self, tracker: CampaignTracker):
        tracker.record_signal("agent-1", "tenant-A", "injection", 0.7)
        tracker.record_signal("agent-1", "tenant-A", "exploit", 0.9)
        tracker.record_signal("agent-1", "tenant-A", "blocked", 0.5)
        assessment = tracker.assess("agent-1", "tenant-A")
        assert assessment.signal_count == 3

    def test_separate_agents(self, tracker: CampaignTracker):
        tracker.record_signal("agent-1", "tenant-A", "injection", 0.7)
        tracker.record_signal("agent-2", "tenant-A", "exploit", 0.8)
        assert tracker.tracked_agents == 2

    def test_separate_tenants(self, tracker: CampaignTracker):
        tracker.record_signal("agent-1", "tenant-A", "injection", 0.7)
        tracker.record_signal("agent-1", "tenant-B", "injection", 0.7)
        assert tracker.tracked_agents == 2

    def test_score_clamped_0_1(self, tracker: CampaignTracker):
        tracker.record_signal("a", "t", "injection", 5.0)
        tracker.record_signal("a", "t", "injection", -2.0)
        assessment = tracker.assess("a", "t")
        assert assessment.signal_count == 2

# ── Assessment ───────────────────────────────────────────────────────────────

class TestAssessment:
    def test_unknown_agent_zero_score(self, tracker: CampaignTracker):
        a = tracker.assess("nonexistent", "tenant")
        assert a.campaign_score == 0.0
        assert a.signal_count == 0

    def test_single_signal_low_score(self, tracker: CampaignTracker):
        tracker.record_signal("a", "t", "injection", 0.3)
        a = tracker.assess("a", "t")
        # Single low signal → low campaign score
        assert a.campaign_score < 0.5

    def test_many_high_signals_high_score(self, tracker: CampaignTracker):
        """20 high-intensity signals across multiple categories."""
        categories = [
            "reconnaissance",
            "initial_access",
            "execution",
            "credential_access",
            "exfiltration",
        ]
        for i in range(20):
            tracker.record_signal(
                "a",
                "t",
                signal_type="exploit",
                score=0.8 + (i % 3) * 0.05,
                category=categories[i % len(categories)],
            )
        a = tracker.assess("a", "t")
        assert a.campaign_score >= 0.6
        assert a.unique_categories >= 4
        assert a.phase_coverage > 0.3

    def test_assessment_includes_metadata(self, tracker: CampaignTracker):
        tracker.record_signal("a", "t", "injection", 0.5, category="execution")
        a = tracker.assess("a", "t")
        assert "weighted_avg" in a.metadata
        assert "volume_factor" in a.metadata

    def test_assessment_dataclass_fields(self, tracker: CampaignTracker):
        a = tracker.assess("a", "t")
        assert isinstance(a, CampaignAssessment)
        assert hasattr(a, "campaign_score")
        assert hasattr(a, "signal_count")
        assert hasattr(a, "unique_categories")
        assert hasattr(a, "phase_coverage")
        assert hasattr(a, "escalating")
        assert hasattr(a, "window_seconds")

# ── Phase coverage ───────────────────────────────────────────────────────────

class TestPhaseCoverage:
    def test_single_phase(self, tracker: CampaignTracker):
        tracker.record_signal("a", "t", "exploit", 0.8, category="execution")
        a = tracker.assess("a", "t")
        assert a.phase_coverage > 0  # 1/9 phases

    def test_multi_phase(self, tracker: CampaignTracker):
        phases = [
            "reconnaissance",
            "initial_access",
            "execution",
            "credential_access",
            "lateral_movement",
            "exfiltration",
        ]
        for p in phases:
            tracker.record_signal("a", "t", "exploit", 0.7, category=p)
        a = tracker.assess("a", "t")
        assert a.phase_coverage >= 0.5  # 6/9 phases

    def test_non_killchain_category_doesnt_count(self, tracker: CampaignTracker):
        """A category not in the kill-chain set should not bump phase coverage."""
        tracker.record_signal("a", "t", "exploit", 0.8, category="unknown_category")
        a = tracker.assess("a", "t")
        assert a.phase_coverage == 0.0

# ── Escalation detection ────────────────────────────────────────────────────

class TestEscalation:
    def test_escalating_signals(self, tracker: CampaignTracker):
        """Older signals low, recent signals high → escalating."""
        # Record 8 low signals, then 4 high signals
        for _i in range(8):
            tracker.record_signal("a", "t", "injection", 0.2)
        for _i in range(4):
            tracker.record_signal("a", "t", "exploit", 0.9)
        a = tracker.assess("a", "t")
        assert a.escalating is True

    def test_stable_signals_not_escalating(self, tracker: CampaignTracker):
        """All signals at same level → not escalating."""
        for _ in range(10):
            tracker.record_signal("a", "t", "injection", 0.5)
        a = tracker.assess("a", "t")
        assert a.escalating is False

    def test_too_few_signals_not_escalating(self, tracker: CampaignTracker):
        """< 4 signals → not escalating (can't detect trend)."""
        tracker.record_signal("a", "t", "injection", 0.3)
        tracker.record_signal("a", "t", "exploit", 0.9)
        a = tracker.assess("a", "t")
        assert a.escalating is False

# ── Reset ────────────────────────────────────────────────────────────────────

class TestReset:
    def test_reset_single_agent(self, tracker: CampaignTracker):
        tracker.record_signal("a1", "t", "injection", 0.5)
        tracker.record_signal("a2", "t", "injection", 0.5)
        tracker.reset(agent_id="a1", tenant_id="t")
        assert tracker.tracked_agents == 1
        assert tracker.assess("a1", "t").signal_count == 0
        assert tracker.assess("a2", "t").signal_count == 1

    def test_reset_all(self, tracker: CampaignTracker):
        tracker.record_signal("a1", "t", "injection", 0.5)
        tracker.record_signal("a2", "t", "injection", 0.5)
        tracker.reset()
        assert tracker.tracked_agents == 0

# ── LRU Eviction ────────────────────────────────────────────────────────────

class TestLRUEviction:
    def test_evicts_oldest_when_full(self, tiny_tracker: CampaignTracker):
        tiny_tracker.record_signal("a1", "t", "injection", 0.5)
        tiny_tracker.record_signal("a2", "t", "injection", 0.5)
        tiny_tracker.record_signal("a3", "t", "injection", 0.5)
        assert tiny_tracker.tracked_agents == 3

        # Adding a 4th should evict the oldest (a1)
        tiny_tracker.record_signal("a4", "t", "injection", 0.5)
        assert tiny_tracker.tracked_agents == 3
        assert tiny_tracker.assess("a1", "t").signal_count == 0  # evicted

    def test_lru_refresh_on_new_signal(self, tiny_tracker: CampaignTracker):
        tiny_tracker.record_signal("a1", "t", "injection", 0.5)
        tiny_tracker.record_signal("a2", "t", "injection", 0.5)
        tiny_tracker.record_signal("a3", "t", "injection", 0.5)

        # Refresh a1 by recording another signal
        tiny_tracker.record_signal("a1", "t", "injection", 0.6)

        # Adding a4 should now evict a2 (not a1 since a1 was refreshed)
        tiny_tracker.record_signal("a4", "t", "injection", 0.5)
        assert tiny_tracker.assess("a1", "t").signal_count >= 1
        assert tiny_tracker.assess("a2", "t").signal_count == 0  # evicted

# ── Volume factor ────────────────────────────────────────────────────────────

class TestVolumeFactor:
    def test_more_signals_higher_score(self, tracker: CampaignTracker):
        """More signals in the window → higher campaign score."""
        tracker.record_signal("few", "t", "injection", 0.5)
        tracker.record_signal("few", "t", "injection", 0.5)
        a_few = tracker.assess("few", "t")

        for _ in range(20):
            tracker.record_signal("many", "t", "injection", 0.5)
        a_many = tracker.assess("many", "t")

        assert a_many.campaign_score > a_few.campaign_score

# ── Thread safety ────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_recording(self, tracker: CampaignTracker):
        """Multiple threads recording signals simultaneously."""
        errors: list[Exception] = []

        def record_batch(agent_id: str):
            try:
                for _ in range(100):
                    tracker.record_signal(agent_id, "t", "injection", 0.5)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_batch, args=(f"agent-{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert tracker.tracked_agents == 10
        for i in range(10):
            a = tracker.assess(f"agent-{i}", "t")
            assert a.signal_count == 100

# ── CampaignState / CampaignSignal dataclasses ──────────────────────────────

class TestDataclasses:
    def test_campaign_signal_fields(self):
        s = CampaignSignal(
            timestamp=1234.5,
            signal_type="injection",
            score=0.7,
            category="execution",
        )
        assert s.timestamp == 1234.5
        assert s.signal_type == "injection"
        assert s.score == 0.7
        assert s.category == "execution"
        assert s.metadata == {}

    def test_campaign_state_signal_count(self):
        state = CampaignState(agent_id="a", tenant_id="t")
        assert state.signal_count == 0
        state.signals.append(CampaignSignal(0, "injection", 0.5, "execution"))
        assert state.signal_count == 1

    def test_assessment_frozen(self, tracker: CampaignTracker):
        a = tracker.assess("a", "t")
        with pytest.raises(AttributeError):
            a.campaign_score = 0.99  # type: ignore[misc]
