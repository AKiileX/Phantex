# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8c — Cross-Signal Scoring (Signal Fusion).

Fuses multiple independent detection signals into a single unified
confidence score.  This is the FP-killer: no single noisy detector
can fire alone — only correlated signals produce high confidence.

Input signals:
1. **Content score** — from prompt_injection + embedding_similarity +
   trained_content classifiers (max of all content classifiers).
2. **Behavioral score** — from the J1-J3 ML ensemble (IF+XGB+AE).
3. **Baseline deviation** — z-score from J4 behavioral baselines.
4. **Campaign score** — from JB7b campaign tracker.

Fusion strategy:
- Weighted geometric mean (multiplicative):
  Low score from ANY signal pulls down the fused score → FP reduction.
- Additive bonus when multiple signals agree →
  Two weak signals together are stronger than one strong signal alone.
- Confidence tiering: the fused score maps to INFO/LOW/MEDIUM/HIGH/CRITICAL.

Configuration:
- Weights are tunable (default: content 0.35, behavioral 0.30,
  baseline 0.20, campaign 0.15).
- Minimum agreement: ≥2 signals above their individual thresholds
  required for ALERT or higher.

Hardening:
- All inputs clamped to [0, 1].
- Division-safe (no division by zero).
- Deterministic (no randomness).
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default weights
# ---------------------------------------------------------------------------
_DEFAULT_WEIGHTS = {
    "content": 0.35,
    "behavioral": 0.30,
    "baseline": 0.20,
    "campaign": 0.15,
}

_DEFAULT_INDIVIDUAL_THRESHOLD = 0.3  # Signal is "active" above this
_MIN_AGREEMENT = 2  # Minimum active signals for ALERT+

@dataclass(frozen=True)
class SignalInput:
    """A single detection signal for fusion.

    score:    0.0 (benign) – 1.0 (malicious).
    source:   Signal name (e.g. "content", "behavioral").
    details:  Optional metadata for explainability.
    """

    score: float
    source: str
    details: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class FusedScore:
    """Result of cross-signal fusion."""

    score: float  # Fused score [0, 1]
    confidence_tier: str  # "info" | "low" | "medium" | "high" | "critical"
    active_signals: int  # How many signals exceeded individual threshold
    total_signals: int
    should_alert: bool  # True if fused score + agreement warrants alert
    should_block: bool  # True if should block
    signal_breakdown: dict[str, float]  # Per-signal scores
    explanation: str  # Human-readable summary
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "confidence_tier": self.confidence_tier,
            "active_signals": self.active_signals,
            "total_signals": self.total_signals,
            "should_alert": self.should_alert,
            "should_block": self.should_block,
            "signal_breakdown": {k: round(v, 4) for k, v in self.signal_breakdown.items()},
            "explanation": self.explanation,
        }

class CrossSignalScorer:
    """Fuse multiple detection signals into a unified confidence score.

    Parameters
    ----------
    weights:
        Signal name → weight mapping.  Weights are normalized internally.
    individual_threshold:
        Per-signal score above which a signal is considered "active."
    min_agreement:
        Minimum number of active signals for ALERT or higher.
    alert_threshold:
        Fused score above which to alert (if agreement met).
    block_threshold:
        Fused score above which to block.
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        *,
        individual_threshold: float = _DEFAULT_INDIVIDUAL_THRESHOLD,
        min_agreement: int = _MIN_AGREEMENT,
        alert_threshold: float = 0.45,
        block_threshold: float = 0.75,
    ) -> None:
        raw_weights = weights or dict(_DEFAULT_WEIGHTS)
        total = sum(raw_weights.values()) or 1.0
        self._weights = {k: v / total for k, v in raw_weights.items()}
        self._individual_thresh = individual_threshold
        self._min_agreement = min_agreement
        self._alert_thresh = alert_threshold
        self._block_thresh = block_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuse(self, signals: list[SignalInput]) -> FusedScore:
        """Fuse multiple signals into a single score.

        Any signal sources not in the weight table get weight 0.1.
        """
        if not signals:
            return self._empty_score()

        # Clamp & organize (first occurrence per source wins; dupes logged)
        scores: dict[str, float] = {}
        for sig in signals:
            s = max(0.0, min(1.0, sig.score))
            if sig.source in scores:
                logger.warning("Duplicate signal source '%s' — keeping first", sig.source)
                continue
            scores[sig.source] = s

        # Count active signals
        active = sum(1 for s in scores.values() if s >= self._individual_thresh)

        # Weighted combination (hybrid: geometric for anti-FP + arithmetic for sensitivity)
        fused = self._compute_fused(scores)

        # Agreement bonus: if multiple signals agree, boost slightly
        if active >= 2:
            agreement_bonus = 0.05 * (active - 1)
            fused = min(1.0, fused + agreement_bonus)

        # Agreement penalty: if only 1 signal is active, dampen
        if active <= 1 and fused >= self._alert_thresh:
            fused *= 0.7  # 30% reduction for single-signal alerts

        # Determine tier + actions
        tier = self._score_to_tier(fused)
        should_alert = fused >= self._alert_thresh and active >= self._min_agreement
        should_block = fused >= self._block_thresh and active >= self._min_agreement

        # Explanation
        explanation = self._build_explanation(scores, fused, active)

        return FusedScore(
            score=round(fused, 4),
            confidence_tier=tier,
            active_signals=active,
            total_signals=len(signals),
            should_alert=should_alert,
            should_block=should_block,
            signal_breakdown=scores,
            explanation=explanation,
        )

    def fuse_simple(
        self,
        content_score: float = 0.0,
        behavioral_score: float = 0.0,
        baseline_z: float = 0.0,
        campaign_score: float = 0.0,
    ) -> FusedScore:
        """Convenience: fuse from named float values.

        ``baseline_z`` is a z-score (unbounded); mapped via sigmoid to [0, 1].
        """
        # Convert z-score to [0, 1] via sigmoid-ish mapping
        baseline_score = 0.0
        if baseline_z > 0:
            baseline_score = min(1.0, baseline_z / (baseline_z + 2.0))

        signals = [
            SignalInput(score=content_score, source="content"),
            SignalInput(score=behavioral_score, source="behavioral"),
            SignalInput(score=baseline_score, source="baseline"),
            SignalInput(score=campaign_score, source="campaign"),
        ]
        return self.fuse(signals)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _compute_fused(self, scores: dict[str, float]) -> float:
        """Compute the weighted fused score.

        Uses a hybrid approach:
        - Arithmetic weighted mean for base score.
        - Geometric penalty: if any weighted signal is very low, it pulls
          the score down (anti-FP).
        """
        # Arithmetic weighted mean
        arithmetic = 0.0
        weight_sum = 0.0
        for source, score in scores.items():
            w = self._weights.get(source, 0.1)
            arithmetic += w * score
            weight_sum += w

        if weight_sum > 0:
            arithmetic /= weight_sum

        # Geometric penalty: product of (score + epsilon) ^ weight
        # If one signal is near zero, it pulls the whole score down.
        # Guard: if weight_sum is zero (all weights zero), skip geometric
        # to avoid exp(0)=1.0 inflating the fused score.
        if weight_sum > 1e-8:
            geo_product = 0.0
            for source, score in scores.items():
                w = self._weights.get(source, 0.1) / weight_sum
                geo_product += w * math.log(max(score + 0.01, 1e-8))
            geometric = math.exp(geo_product)
        else:
            geometric = 0.0

        # Blend: 60% arithmetic + 40% geometric
        fused = 0.6 * arithmetic + 0.4 * geometric
        return max(0.0, min(1.0, fused))

    def _score_to_tier(self, score: float) -> str:
        """Map fused score to confidence tier."""
        if score >= 0.85:
            return "critical"
        elif score >= 0.65:
            return "high"
        elif score >= 0.45:
            return "medium"
        elif score >= 0.25:
            return "low"
        return "info"

    def _build_explanation(
        self,
        scores: dict[str, float],
        fused: float,
        active: int,
    ) -> str:
        """Build human-readable explanation."""
        parts = []
        for source, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
            status = "active" if score >= self._individual_thresh else "quiet"
            parts.append(f"{source}={score:.2f}({status})")

        return f"Fused score {fused:.3f} from {active}/{len(scores)} active signals: " + ", ".join(parts)

    def _empty_score(self) -> FusedScore:
        return FusedScore(
            score=0.0,
            confidence_tier="info",
            active_signals=0,
            total_signals=0,
            should_alert=False,
            should_block=False,
            signal_breakdown={},
            explanation="No signals provided",
        )
