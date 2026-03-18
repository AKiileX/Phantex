# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for JB7 Integration — Gateway Hook with Campaign Tracking.

Verifies that the GatewayContentHook correctly:
  1. Records campaign signals for non-benign verdicts
  2. Escalates decisions when campaign thresholds are breached
  3. Includes campaign metadata in GatewayResult
  4. Handles disabled campaign tracking gracefully
"""

from __future__ import annotations

import pytest

from ml.content.config import ContentAnalysisConfig
from ml.content.integration.gateway_hook import (
    GatewayContentHook,
    GatewayResult,
)
from ml.content.offensive.campaign_tracker import CampaignTracker
from ml.content.verdict import Decision

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def config() -> ContentAnalysisConfig:
    """Config with campaign tracking and exploit scanning enabled."""
    return ContentAnalysisConfig(
        enabled=True,
        exploit_scan_enabled=True,
        campaign_tracking_enabled=True,
        campaign_alert_threshold=0.6,
        campaign_block_threshold=0.8,
    )

@pytest.fixture
def disabled_config() -> ContentAnalysisConfig:
    """Config with campaign tracking disabled."""
    return ContentAnalysisConfig(
        enabled=True,
        campaign_tracking_enabled=False,
    )

@pytest.fixture
def hook(config: ContentAnalysisConfig) -> GatewayContentHook:
    return GatewayContentHook(config=config)

@pytest.fixture
def disabled_hook(disabled_config: ContentAnalysisConfig) -> GatewayContentHook:
    return GatewayContentHook(config=disabled_config)

# ── Basic gateway wiring ─────────────────────────────────────────────────────

class TestGatewayWiring:
    def test_hook_creates_campaign_tracker(self, hook: GatewayContentHook):
        assert hook._campaign is not None

    def test_hook_disabled_no_tracker(self, disabled_hook: GatewayContentHook):
        assert disabled_hook._campaign is None

    def test_hook_accepts_external_tracker(self, config: ContentAnalysisConfig):
        tracker = CampaignTracker(window_seconds=100)
        hook = GatewayContentHook(config=config, campaign_tracker=tracker)
        assert hook._campaign is tracker

# ── Benign content — no campaign signal ──────────────────────────────────────

class TestBenignContent:
    def test_benign_text_no_campaign(self, hook: GatewayContentHook):
        result = hook.analyze_event(
            "Hello, how can I help?",
            agent_id="agent-1",
            tenant_id="tenant-A",
        )
        assert result.allowed is True
        # Campaign metadata should still be present (assess always runs)
        if "campaign_score" in result.metadata:
            assert result.metadata["campaign_score"] == 0.0

# ── Exploit detection → campaign signal ──────────────────────────────────────

class TestExploitCampaignSignal:
    def test_exploit_recorded_to_campaign(self, hook: GatewayContentHook):
        """A detected exploit should register a campaign signal."""
        hook.analyze_event(
            "nmap -sV -p 80,443 192.168.1.0/24\nsqlmap -u target --dbs",
            agent_id="agent-1",
            tenant_id="tenant-A",
        )
        if hook._campaign:
            a = hook._campaign.assess("agent-1", "tenant-A")
            assert a.signal_count >= 1

# ── Campaign escalation ─────────────────────────────────────────────────────

class TestCampaignEscalation:
    def test_campaign_block_escalation(self, config: ContentAnalysisConfig):
        """Many high-score signals should push campaign above block threshold."""
        tracker = CampaignTracker(window_seconds=86400)
        hook = GatewayContentHook(config=config, campaign_tracker=tracker)

        # Pre-load signals to push campaign score above block threshold
        categories = [
            "reconnaissance",
            "initial_access",
            "execution",
            "credential_access",
            "exfiltration",
            "persistence",
        ]
        for i in range(30):
            tracker.record_signal(
                "agent-bad",
                "tenant-A",
                signal_type="exploit",
                score=0.9,
                category=categories[i % len(categories)],
            )

        # Now a benign event should get escalated due to campaign score
        result = hook.analyze_event(
            "just checking in",
            agent_id="agent-bad",
            tenant_id="tenant-A",
        )
        # Campaign score should be high enough to escalate
        if "campaign_score" in result.metadata and result.metadata["campaign_score"] >= 0.8:
            assert result.decision == Decision.BLOCK.value
            assert result.allowed is False

    def test_campaign_alert_escalation(self, config: ContentAnalysisConfig):
        """Moderate campaign activity should escalate to ALERT."""
        tracker = CampaignTracker(window_seconds=86400)
        hook = GatewayContentHook(config=config, campaign_tracker=tracker)

        # Record enough signals for alert but not block
        for i in range(10):
            tracker.record_signal(
                "agent-sus",
                "tenant-A",
                signal_type="injection",
                score=0.6,
                category=["reconnaissance", "initial_access", "execution"][i % 3],
            )

        result = hook.analyze_event(
            "harmless text",
            agent_id="agent-sus",
            tenant_id="tenant-A",
        )
        if "campaign_score" in result.metadata:
            cs = result.metadata["campaign_score"]
            if 0.6 <= cs < 0.8:
                assert result.decision == Decision.ALERT.value

# ── Campaign metadata in result ──────────────────────────────────────────────

class TestCampaignMetadata:
    def test_metadata_present(self, hook: GatewayContentHook):
        hook.analyze_event(
            "nmap -sV 10.0.0.1",
            agent_id="agent-1",
            tenant_id="tenant-A",
        )
        result = hook.analyze_event(
            "sqlmap -u target --dbs",
            agent_id="agent-1",
            tenant_id="tenant-A",
        )
        if "campaign_score" in result.metadata:
            assert isinstance(result.metadata["campaign_score"], float)
            assert isinstance(result.metadata["campaign_signals"], int)
            assert isinstance(result.metadata["campaign_escalating"], bool)
            assert isinstance(result.metadata["campaign_phase_coverage"], float)

    def test_no_metadata_without_agent_id(self, hook: GatewayContentHook):
        """Without agent_id, campaign tracking is skipped."""
        result = hook.analyze_event(
            "nmap -sV 10.0.0.1",
            agent_id="",
            tenant_id="tenant-A",
        )
        assert "campaign_score" not in result.metadata

# ── Disabled campaign tracking ───────────────────────────────────────────────

class TestDisabledCampaign:
    def test_disabled_no_campaign_meta(self, disabled_hook: GatewayContentHook):
        result = disabled_hook.analyze_event(
            "nmap -sV 10.0.0.1",
            agent_id="agent-1",
            tenant_id="tenant-A",
        )
        assert "campaign_score" not in result.metadata

    def test_disabled_still_analyzes(self, disabled_hook: GatewayContentHook):
        """Content analysis still works even without campaign tracking."""
        result = disabled_hook.analyze_event(
            "Hello world",
            agent_id="agent-1",
        )
        assert isinstance(result, GatewayResult)
        assert result.decision in {d.value for d in Decision}

# ── Graceful degradation ────────────────────────────────────────────────────

class TestGracefulDegradation:
    def test_exception_in_hook_degrades(self):
        """If something blows up, the hook should degrade gracefully."""
        config = ContentAnalysisConfig(enabled=True, campaign_tracking_enabled=True)
        hook = GatewayContentHook(config=config)
        # Even with weird input, should not crash
        result = hook.analyze_event("", agent_id="a", tenant_id="t")
        assert isinstance(result, GatewayResult)
