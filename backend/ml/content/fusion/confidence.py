# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8c — Confidence Tiering.

Maps raw scores + agreements into a graduated confidence level that
determines enforcement action.  Replaces the binary threshold model
with a nuanced tier system inspired by CrowdStrike/SentinelOne.

Tiers:
  INFORMATIONAL — logged, not alerted.
  LOW           — logged, low-priority alert in dashboard.
  MEDIUM        — standard alert + notification.
  HIGH          — alert + block recommendation.
  CRITICAL      — alert + auto-block + immediate notification.

Each tier has:
- A score range.
- Minimum signal agreement requirement.
- Enforcement action mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

class ConfidenceTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

@dataclass(frozen=True)
class TierPolicy:
    """Policy for a confidence tier."""

    tier: ConfidenceTier
    min_score: float
    min_agreement: int  # Minimum active signals
    action: str  # "allow" | "log" | "alert" | "block"
    notify: bool = False  # Send real-time notification
    auto_block: bool = False  # Block without human review

# Default tier policies (highest → lowest priority)
DEFAULT_TIER_POLICIES: list[TierPolicy] = [
    TierPolicy(
        tier=ConfidenceTier.CRITICAL,
        min_score=0.85,
        min_agreement=2,
        action="block",
        notify=True,
        auto_block=True,
    ),
    TierPolicy(
        tier=ConfidenceTier.HIGH,
        min_score=0.65,
        min_agreement=2,
        action="block",
        notify=True,
        auto_block=False,
    ),
    TierPolicy(
        tier=ConfidenceTier.MEDIUM,
        min_score=0.45,
        min_agreement=2,
        action="alert",
        notify=True,
        auto_block=False,
    ),
    TierPolicy(
        tier=ConfidenceTier.LOW,
        min_score=0.25,
        min_agreement=1,
        action="log",
        notify=False,
        auto_block=False,
    ),
    TierPolicy(
        tier=ConfidenceTier.INFORMATIONAL,
        min_score=0.0,
        min_agreement=0,
        action="allow",
        notify=False,
        auto_block=False,
    ),
]

@dataclass(frozen=True)
class TierDecision:
    """Result of tier evaluation."""

    tier: ConfidenceTier
    action: str
    notify: bool
    auto_block: bool
    fused_score: float
    active_signals: int
    reason: str

class ConfidenceTierEvaluator:
    """Evaluate a fused score + signal count against tier policies.

    Parameters
    ----------
    policies:
        Ordered list of TierPolicy (highest priority first).
        Defaults to the standard 5-tier model.
    """

    def __init__(
        self,
        policies: list[TierPolicy] | None = None,
    ) -> None:
        self._policies = policies or list(DEFAULT_TIER_POLICIES)
        # Sort by min_score descending to check highest tier first
        self._policies.sort(key=lambda p: p.min_score, reverse=True)

    def evaluate(
        self,
        fused_score: float,
        active_signals: int,
    ) -> TierDecision:
        """Determine the appropriate tier and action.

        Parameters
        ----------
        fused_score:
            Cross-signal fused score [0, 1].
        active_signals:
            Number of detection signals that exceeded their individual
            threshold.
        """
        score = max(0.0, min(1.0, fused_score))

        for policy in self._policies:
            if score >= policy.min_score and active_signals >= policy.min_agreement:
                return TierDecision(
                    tier=policy.tier,
                    action=policy.action,
                    notify=policy.notify,
                    auto_block=policy.auto_block,
                    fused_score=round(score, 4),
                    active_signals=active_signals,
                    reason=(
                        f"Score {score:.3f} >= {policy.min_score} "
                        f"with {active_signals} >= {policy.min_agreement} signals"
                    ),
                )

        # Fallback (should never reach here with default policies)
        return TierDecision(
            tier=ConfidenceTier.INFORMATIONAL,
            action="allow",
            notify=False,
            auto_block=False,
            fused_score=round(score, 4),
            active_signals=active_signals,
            reason="No policy matched",
        )
