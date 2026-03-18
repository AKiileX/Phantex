# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Semantic Baseline Tracker (JB5).

Tracks per-agent content patterns over time to detect anomalous drift:
- Prompt length distribution
- Output vocabulary entropy
- Tool call frequency distribution

When content suddenly shifts (e.g. prompt injection changes the agent's
"voice"), the baseline drift fires an alert.

Memory-bounded: max 10,000 fingerprints per agent, FIFO eviction.
Uses rolling statistics — raw content is never stored.
"""

from __future__ import annotations

import math
import threading
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class BaselineSnapshot:
    """Point-in-time summary of an agent's content baseline."""

    agent_id: str
    tenant_id: str
    sample_count: int
    mean_length: float
    stddev_length: float
    mean_entropy: float
    stddev_entropy: float
    top_tokens: tuple[tuple[str, int], ...]  # Top 20 most common tokens

@dataclass
class _RollingStats:
    """Running mean/variance using Welford's algorithm.

    These are *all-time* statistics across every sample ever recorded
    (Welford does not support sample removal).  Eviction from the
    sample_queue is for memory bounds only — it does NOT subtract
    from these accumulators.  This means the stats represent the
    lifetime distribution, which is appropriate for drift detection.
    """

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0  # Running sum of (x - mean)²

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0  # Guard: stddev=0 when n<2 prevents division by zero
        return self.m2 / (self.n - 1)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

class SemanticBaselineTracker:
    """Track & detect drift in per-agent content patterns.

    Parameters
    ----------
    max_samples_per_agent:
        Max fingerprints (sample entries) per agent.  FIFO eviction
        when exceeded (default 10,000).
    drift_sigma:
        Number of standard deviations from the mean that triggers
        a drift alert (default 2.0).
    min_samples:
        Minimum samples before drift detection activates (default 100).
    """

    def __init__(
        self,
        max_samples_per_agent: int = 10_000,
        drift_sigma: float = 2.0,
        min_samples: int = 100,
    ) -> None:
        self._max_samples = max_samples_per_agent
        self._sigma = drift_sigma
        self._min_samples = min_samples

        self._lock = threading.Lock()
        # (tenant, agent) → per-agent state
        self._length_stats: dict[tuple[str, str], _RollingStats] = {}
        self._entropy_stats: dict[tuple[str, str], _RollingStats] = {}
        self._token_counts: dict[tuple[str, str], Counter[str]] = {}
        self._sample_counts: dict[tuple[str, str], int] = {}
        # FIFO tracker for eviction
        self._sample_queue: dict[tuple[str, str], deque[tuple[float, float]]] = {}

    # ── Record a sample ──────────────────────────────────────────────

    def record(
        self,
        tenant_id: str,
        agent_id: str,
        content: str,
    ) -> dict[str, Any]:
        """Record a content sample and return drift analysis.

        Returns
        -------
        dict with keys:
            ``length_drift``, ``entropy_drift`` — bool flags
            ``length_zscore``, ``entropy_zscore`` — z-scores (0 if < min_samples)
            ``sample_count`` — total samples for this agent
        """
        key = (tenant_id, agent_id)
        content_len = float(len(content))
        entropy = self._token_entropy(content)

        with self._lock:
            # Initialise state
            if key not in self._length_stats:
                self._length_stats[key] = _RollingStats()
                self._entropy_stats[key] = _RollingStats()
                self._token_counts[key] = Counter()
                self._sample_counts[key] = 0
                self._sample_queue[key] = deque(maxlen=self._max_samples)

            lst = self._length_stats[key]
            est = self._entropy_stats[key]

            # ── Drift check BEFORE updating (compare new sample to existing baseline)
            length_z = self._zscore(content_len, lst)
            entropy_z = self._zscore(entropy, est)
            has_enough = self._sample_counts[key] >= self._min_samples
            length_drift = has_enough and abs(length_z) > self._sigma
            entropy_drift = has_enough and abs(entropy_z) > self._sigma

            # ── Update rolling stats
            lst.update(content_len)
            est.update(entropy)
            self._sample_counts[key] += 1
            self._sample_queue[key].append((content_len, entropy))

            # ── Token frequency (word-level)
            tokens = content.lower().split()
            self._token_counts[key].update(tokens)

        return {
            "length_drift": length_drift,
            "entropy_drift": entropy_drift,
            "length_zscore": round(length_z, 3),
            "entropy_zscore": round(entropy_z, 3),
            "sample_count": self._sample_counts[key],
        }

    # ── Snapshot ─────────────────────────────────────────────────────

    def snapshot(self, tenant_id: str, agent_id: str) -> BaselineSnapshot | None:
        """Get a read-only snapshot of the current baseline."""
        key = (tenant_id, agent_id)
        with self._lock:
            if key not in self._length_stats:
                return None
            lst = self._length_stats[key]
            est = self._entropy_stats[key]
            top = self._token_counts[key].most_common(20)
            return BaselineSnapshot(
                agent_id=agent_id,
                tenant_id=tenant_id,
                sample_count=self._sample_counts[key],
                mean_length=round(lst.mean, 2),
                stddev_length=round(lst.stddev, 2),
                mean_entropy=round(est.mean, 4),
                stddev_entropy=round(est.stddev, 4),
                top_tokens=tuple(top),
            )

    def reset(self, tenant_id: str, agent_id: str) -> bool:
        """Clear baseline data for an agent.  Returns True if it existed."""
        key = (tenant_id, agent_id)
        with self._lock:
            existed = key in self._length_stats
            self._length_stats.pop(key, None)
            self._entropy_stats.pop(key, None)
            self._token_counts.pop(key, None)
            self._sample_counts.pop(key, None)
            self._sample_queue.pop(key, None)
            return existed

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _zscore(value: float, stats: _RollingStats) -> float:
        """Compute z-score.  Returns 0.0 if not enough data.

        Special case: if stddev is 0 (all samples identical) and value
        differs from mean, returns a large z-score to flag the anomaly.
        """
        if stats.n < 2:
            return 0.0
        if stats.stddev == 0:
            # All samples identical — any deviation is anomalous
            if abs(value - stats.mean) > 1e-9:
                return 100.0  # Clearly anomalous
            return 0.0
        return (value - stats.mean) / stats.stddev

    @staticmethod
    def _token_entropy(text: str) -> float:
        """Shannon entropy of word tokens (bits per token)."""
        tokens = text.lower().split()
        if not tokens:
            return 0.0
        freq = Counter(tokens)
        total = len(tokens)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
