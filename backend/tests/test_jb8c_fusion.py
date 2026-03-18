# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB8c — Cross-Signal Scorer + Confidence Tier Evaluator."""

import pytest

from ml.content.fusion.confidence import (
    DEFAULT_TIER_POLICIES,
    ConfidenceTier,
    ConfidenceTierEvaluator,
    TierPolicy,
)
from ml.content.fusion.cross_signal import (
    CrossSignalScorer,
    SignalInput,
)

# =========================================================================
# CrossSignalScorer
# =========================================================================

@pytest.fixture
def scorer():
    return CrossSignalScorer()

class TestCrossSignalBasics:
    def test_no_signals(self, scorer):
        result = scorer.fuse([])
        assert result.score == 0.0
        assert result.confidence_tier == "info"
        assert result.should_alert is False

    def test_single_low_signal(self, scorer):
        signals = [SignalInput(score=0.2, source="content")]
        result = scorer.fuse(signals)
        assert result.score < 0.5
        assert result.should_alert is False

    def test_two_high_signals(self, scorer):
        signals = [
            SignalInput(score=0.9, source="content"),
            SignalInput(score=0.8, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        assert result.score > 0.5
        assert result.active_signals == 2

    def test_all_signals_high(self, scorer):
        signals = [
            SignalInput(score=0.9, source="content"),
            SignalInput(score=0.85, source="behavioral"),
            SignalInput(score=0.8, source="baseline"),
            SignalInput(score=0.75, source="campaign"),
        ]
        result = scorer.fuse(signals)
        assert result.score > 0.7
        assert result.active_signals == 4
        assert result.should_alert is True
        assert result.should_block is True

    def test_single_signal_penalty(self, scorer):
        """Single active signal gets dampened."""
        single = scorer.fuse(
            [
                SignalInput(score=0.6, source="content"),
            ]
        )
        multi = scorer.fuse(
            [
                SignalInput(score=0.6, source="content"),
                SignalInput(score=0.6, source="behavioral"),
            ]
        )
        # Multi agreement should produce higher score
        assert multi.score > single.score

class TestCrossSignalFuseSimple:
    def test_fuse_simple_zeros(self, scorer):
        result = scorer.fuse_simple(0, 0, 0, 0)
        assert result.score < 0.1
        assert result.should_alert is False

    def test_fuse_simple_high_content(self, scorer):
        result = scorer.fuse_simple(content_score=0.9)
        # Single signal — should be dampened
        assert result.active_signals <= 1

    def test_fuse_simple_all_high(self, scorer):
        result = scorer.fuse_simple(
            content_score=0.9,
            behavioral_score=0.8,
            baseline_z=5.0,
            campaign_score=0.7,
        )
        assert result.active_signals >= 3

    def test_baseline_z_conversion(self, scorer):
        """High z-score should contribute a meaningful baseline signal."""
        low_z = scorer.fuse_simple(baseline_z=0.5)
        high_z = scorer.fuse_simple(baseline_z=10.0)
        assert high_z.score > low_z.score

class TestCrossSignalAgreement:
    def test_agreement_bonus(self, scorer):
        """Multiple active signals get an agreement bonus."""
        two = scorer.fuse(
            [
                SignalInput(score=0.6, source="content"),
                SignalInput(score=0.6, source="behavioral"),
            ]
        )
        three = scorer.fuse(
            [
                SignalInput(score=0.6, source="content"),
                SignalInput(score=0.6, source="behavioral"),
                SignalInput(score=0.6, source="baseline"),
            ]
        )
        # 3 active signals should get a slightly higher boost
        assert three.score >= two.score

class TestCrossSignalClamping:
    def test_score_clamped_to_01(self, scorer):
        signals = [
            SignalInput(score=5.0, source="content"),
            SignalInput(score=-1.0, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        assert 0.0 <= result.score <= 1.0

    def test_overflow_score(self, scorer):
        signals = [
            SignalInput(score=1.0, source="content"),
            SignalInput(score=1.0, source="behavioral"),
            SignalInput(score=1.0, source="baseline"),
            SignalInput(score=1.0, source="campaign"),
        ]
        result = scorer.fuse(signals)
        assert result.score <= 1.0

class TestCrossSignalExplanation:
    def test_explanation_present(self, scorer):
        signals = [SignalInput(score=0.5, source="content")]
        result = scorer.fuse(signals)
        assert "content" in result.explanation

    def test_to_dict(self, scorer):
        signals = [SignalInput(score=0.5, source="content")]
        result = scorer.fuse(signals)
        d = result.to_dict()
        assert "score" in d
        assert "confidence_tier" in d
        assert "signal_breakdown" in d

class TestCrossSignalWeights:
    def test_custom_weights(self):
        scorer = CrossSignalScorer(weights={"content": 1.0, "behavioral": 0.0})
        signals = [
            SignalInput(score=0.9, source="content"),
            SignalInput(score=0.1, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        # Content-heavy weighting: score should be relatively high
        assert result.score > 0.3

class TestCrossSignalThresholds:
    def test_custom_alert_threshold(self):
        scorer = CrossSignalScorer(alert_threshold=0.9)
        signals = [
            SignalInput(score=0.6, source="content"),
            SignalInput(score=0.6, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        # Score likely below 0.9 threshold
        assert result.should_alert is False

    def test_custom_block_threshold(self):
        scorer = CrossSignalScorer(block_threshold=0.99)
        signals = [
            SignalInput(score=0.8, source="content"),
            SignalInput(score=0.8, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        assert result.should_block is False

# =========================================================================
# ConfidenceTierEvaluator
# =========================================================================

@pytest.fixture
def tier_evaluator():
    return ConfidenceTierEvaluator()

class TestTierEvaluatorBasics:
    def test_critical(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.95, active_signals=3)
        assert d.tier == ConfidenceTier.CRITICAL
        assert d.auto_block is True
        assert d.notify is True

    def test_high(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.70, active_signals=2)
        assert d.tier == ConfidenceTier.HIGH
        assert d.action == "block"
        assert d.auto_block is False

    def test_medium(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.50, active_signals=2)
        assert d.tier == ConfidenceTier.MEDIUM
        assert d.action == "alert"

    def test_low(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.30, active_signals=1)
        assert d.tier == ConfidenceTier.LOW
        assert d.action == "log"

    def test_informational(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.05, active_signals=0)
        assert d.tier == ConfidenceTier.INFORMATIONAL
        assert d.action == "allow"
        assert d.notify is False

class TestTierEvaluatorAgreement:
    def test_high_score_low_agreement_downgrades(self, tier_evaluator):
        """High score but only 1 signal → should not be CRITICAL."""
        d = tier_evaluator.evaluate(0.90, active_signals=1)
        # CRITICAL requires 2 signals, HIGH requires 2 signals
        # So with 1 signal, it falls to LOW (min_agreement=1)
        assert d.tier != ConfidenceTier.CRITICAL

    def test_low_score_high_agreement(self, tier_evaluator):
        """Low score even with many signals stays low tier."""
        d = tier_evaluator.evaluate(0.10, active_signals=4)
        assert d.tier == ConfidenceTier.INFORMATIONAL

class TestTierEvaluatorClamping:
    def test_score_clamped(self, tier_evaluator):
        d = tier_evaluator.evaluate(5.0, active_signals=3)
        assert d.fused_score <= 1.0
        assert d.tier == ConfidenceTier.CRITICAL

    def test_negative_score(self, tier_evaluator):
        d = tier_evaluator.evaluate(-1.0, active_signals=0)
        assert d.fused_score >= 0.0
        assert d.tier == ConfidenceTier.INFORMATIONAL

class TestTierEvaluatorCustomPolicies:
    def test_custom_policy(self):
        policy = TierPolicy(
            tier=ConfidenceTier.CRITICAL,
            min_score=0.5,
            min_agreement=1,
            action="block",
            notify=True,
            auto_block=True,
        )
        evaluator = ConfidenceTierEvaluator(policies=[policy])
        d = evaluator.evaluate(0.6, active_signals=1)
        assert d.tier == ConfidenceTier.CRITICAL

    def test_default_policies_count(self):
        assert len(DEFAULT_TIER_POLICIES) == 5

class TestTierDecisionFields:
    def test_decision_has_reason(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.90, active_signals=3)
        assert d.reason
        assert "0.90" in d.reason or "0.900" in d.reason

    def test_decision_fields(self, tier_evaluator):
        d = tier_evaluator.evaluate(0.50, active_signals=2)
        assert isinstance(d.tier, ConfidenceTier)
        assert isinstance(d.action, str)
        assert isinstance(d.notify, bool)
        assert isinstance(d.auto_block, bool)
        assert isinstance(d.fused_score, float)
        assert isinstance(d.active_signals, int)
