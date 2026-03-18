# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Campaign Tracker (JB7b).

Cross-session behavioural accumulation that detects slow-burn attack
campaigns that stay below single-event thresholds but are clearly
malicious when viewed in aggregate.

Design:
  - Per-agent sliding window (configurable, default 24h)
  - Tracks: injection attempts, blocked actions, exploit hits,
    sensitivity escalation, anomaly scores, unique categories hit
  - Exponential decay on older signals (newer activity weighs more)
  - Thread-safe (stdlib Lock + monotonic time)
  - Memory-bounded (max 50K agent entries, LRU eviction)

Campaign score thresholds:
  - 0.0–0.3: normal background noise
  - 0.3–0.6: elevated activity — log + monitor
  - 0.6–0.8: probable campaign — alert
  - 0.8–1.0: confirmed campaign — block
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default window: 24 hours
_DEFAULT_WINDOW_SEC = 86_400
_DEFAULT_MAX_AGENTS = 50_000

@dataclass
class CampaignSignal:
    """A single recorded signal within a campaign window."""

    timestamp: float  # monotonic
    signal_type: str  # "injection", "exploit", "blocked", "anomaly", "sensitive"
    score: float  # 0.0–1.0 intensity of this signal
    category: str  # ATT&CK category or classifier name
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class CampaignState:
    """Accumulated campaign state for one agent."""

    agent_id: str
    tenant_id: str
    signals: list[CampaignSignal] = field(default_factory=list)
    first_seen: float = 0.0  # monotonic
    last_seen: float = 0.0  # monotonic

    @property
    def signal_count(self) -> int:
        return len(self.signals)

@dataclass(frozen=True)
class CampaignAssessment:
    """Result of campaign analysis for an agent."""

    agent_id: str
    tenant_id: str
    campaign_score: float  # 0.0–1.0 aggregate campaign threat level
    signal_count: int  # Total signals in window
    unique_categories: int  # Distinct ATT&CK categories seen
    phase_coverage: float  # 0.0–1.0 how many kill-chain phases hit
    escalating: bool  # True if signal intensity is increasing
    window_seconds: float  # Duration of observation window
    metadata: dict[str, Any] = field(default_factory=dict)

# ATT&CK kill-chain phases for phase-coverage scoring
_KILL_CHAIN_PHASES = frozenset(
    {
        "reconnaissance",
        "initial_access",
        "execution",
        "credential_access",
        "lateral_movement",
        "exfiltration",
        "persistence",
        "prompt_injection",  # AI-specific attack phases
        "data_classification",
    }
)

class CampaignTracker:
    """Cross-session behavioural accumulation for campaign detection.

    Parameters
    ----------
    window_seconds:
        Sliding window duration (default 24h).  Signals older than
        this are evicted on next access.
    max_agents:
        Maximum tracked agents before LRU eviction (default 50,000).
    decay_half_life:
        Half-life for exponential decay in seconds (default 6h).
        Older signals contribute less to the campaign score.
    """

    __slots__ = (
        "_lock",
        "_states",
        "_window",
        "_max_agents",
        "_decay_half_life",
    )

    def __init__(
        self,
        window_seconds: float = _DEFAULT_WINDOW_SEC,
        max_agents: int = _DEFAULT_MAX_AGENTS,
        decay_half_life: float = 21_600.0,  # 6 hours
    ) -> None:
        self._lock = threading.Lock()
        self._states: OrderedDict[str, CampaignState] = OrderedDict()
        self._window = window_seconds
        self._max_agents = max_agents
        self._decay_half_life = max(1.0, decay_half_life)

    # ── Public API ───────────────────────────────────────────────────────

    def record_signal(
        self,
        agent_id: str,
        tenant_id: str,
        signal_type: str,
        score: float,
        category: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a security signal for an agent.

        Call this from the gateway hook whenever a classifier produces
        a non-benign verdict or a policy blocks an action.
        """
        now = time.monotonic()
        signal = CampaignSignal(
            timestamp=now,
            signal_type=signal_type,
            score=max(0.0, min(1.0, score)),
            category=category,
            metadata=metadata or {},
        )

        with self._lock:
            key = f"{tenant_id}:{agent_id}"
            state = self._states.get(key)
            if state is None:
                # Evict LRU if at capacity
                while len(self._states) >= self._max_agents:
                    self._states.popitem(last=False)

                state = CampaignState(
                    agent_id=agent_id,
                    tenant_id=tenant_id,
                    first_seen=now,
                )
                self._states[key] = state

            state.signals.append(signal)
            state.last_seen = now
            self._states.move_to_end(key)

            # Evict expired signals
            self._prune_signals(state, now)

    def assess(self, agent_id: str, tenant_id: str) -> CampaignAssessment:
        """Compute the current campaign score for an agent.

        Returns a ``CampaignAssessment`` with the aggregate score and
        risk indicators.
        """
        now = time.monotonic()

        with self._lock:
            key = f"{tenant_id}:{agent_id}"
            state = self._states.get(key)
            if state is None:
                return CampaignAssessment(
                    agent_id=agent_id,
                    tenant_id=tenant_id,
                    campaign_score=0.0,
                    signal_count=0,
                    unique_categories=0,
                    phase_coverage=0.0,
                    escalating=False,
                    window_seconds=0.0,
                )

            self._prune_signals(state, now)
            return self._compute_assessment(state, now)

    def reset(self, agent_id: str | None = None, tenant_id: str = "") -> None:
        """Clear campaign state.

        If ``agent_id`` is provided, clear only that agent.
        Otherwise clear all agents.
        """
        with self._lock:
            if agent_id is None:
                self._states.clear()
            else:
                key = f"{tenant_id}:{agent_id}"
                self._states.pop(key, None)

    @property
    def tracked_agents(self) -> int:
        """Number of currently tracked agents."""
        with self._lock:
            return len(self._states)

    # ── Internal ─────────────────────────────────────────────────────────

    def _prune_signals(self, state: CampaignState, now: float) -> None:
        """Remove signals older than the window."""
        cutoff = now - self._window
        state.signals = [s for s in state.signals if s.timestamp >= cutoff]

    def _compute_assessment(self, state: CampaignState, now: float) -> CampaignAssessment:
        """Internal: compute campaign assessment from current signals."""
        signals = state.signals
        if not signals:
            return CampaignAssessment(
                agent_id=state.agent_id,
                tenant_id=state.tenant_id,
                campaign_score=0.0,
                signal_count=0,
                unique_categories=0,
                phase_coverage=0.0,
                escalating=False,
                window_seconds=0.0,
            )

        # 1. Decay-weighted signal score sum
        decay_sum = 0.0
        decay_weight_total = 0.0
        for sig in signals:
            age = now - sig.timestamp
            # Exponential decay: weight = 2^(-age / half_life)
            w = 2.0 ** (-age / self._decay_half_life)
            decay_sum += sig.score * w
            decay_weight_total += w

        # Normalise to 0–1 range
        weighted_avg = decay_sum / decay_weight_total if decay_weight_total > 0 else 0.0

        # 2. Category diversity (kill-chain phase coverage)
        categories = {s.category for s in signals if s.category}
        phase_hits = categories & _KILL_CHAIN_PHASES
        phase_coverage = len(phase_hits) / max(1, len(_KILL_CHAIN_PHASES))

        # 3. Escalation detection: are recent signals stronger?
        escalating = self._detect_escalation(signals, now)

        # 4. Volume factor: more signals = higher confidence
        # Logarithmic scale: 1 signal → 0.3, 10 → 0.7, 50+ → 1.0
        volume_factor = min(1.0, math.log2(max(1, len(signals))) / 5.5)

        # 5. Fuse into campaign score
        campaign_score = (
            0.40 * weighted_avg  # Signal intensity
            + 0.25 * phase_coverage  # Kill-chain breadth
            + 0.20 * volume_factor  # Signal density
            + 0.15 * (1.0 if escalating else 0.0)  # Escalation trend
        )
        campaign_score = round(min(1.0, campaign_score), 4)

        window_span = signals[-1].timestamp - signals[0].timestamp

        return CampaignAssessment(
            agent_id=state.agent_id,
            tenant_id=state.tenant_id,
            campaign_score=campaign_score,
            signal_count=len(signals),
            unique_categories=len(categories),
            phase_coverage=round(phase_coverage, 3),
            escalating=escalating,
            window_seconds=round(window_span, 1),
            metadata={
                "weighted_avg": round(weighted_avg, 4),
                "volume_factor": round(volume_factor, 4),
                "phases_hit": sorted(phase_hits),
            },
        )

    def _detect_escalation(self, signals: list[CampaignSignal], now: float) -> bool:
        """Return True if signal intensity is increasing over time.

        Compares the average score of the most recent 25% of signals
        against the older 75%.  If recent > older * 1.3, escalation
        is detected.
        """
        if len(signals) < 4:
            return False

        n = len(signals)
        split = max(1, n * 3 // 4)
        older_avg = sum(s.score for s in signals[:split]) / max(1, split)
        recent_avg = sum(s.score for s in signals[split:]) / max(1, n - split)

        return recent_avg > older_avg * 1.3
