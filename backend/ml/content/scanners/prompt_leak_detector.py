# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Prompt Leak Detector (JB3).

Detects when an agent's output contains its system prompt (verbatim or
paraphrased leakage).  Uses n-gram overlap fingerprinting for fast
comparison without storing the raw system prompt.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class PromptFingerprint:
    """Fingerprint of a system prompt — stored instead of raw text."""

    agent_id: str
    tenant_id: str
    ngram_counts: dict[str, int]  # 3-gram → count
    total_ngrams: int
    text_hash: str  # SHA-256 of original (for verbatim check)

@dataclass(frozen=True)
class LeakResult:
    """Result of a prompt-leak check."""

    leaked: bool
    similarity: float  # 0.0 – 1.0 (cosine similarity)
    verbatim: bool = False  # True if exact hash match
    agent_id: str = ""
    tenant_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class PromptLeakDetector:
    """Detect system prompt leakage in agent output.

    Parameters
    ----------
    similarity_threshold:
        Cosine similarity above which we flag a leak (default 0.80).
    ngram_size:
        Character n-gram size for fingerprinting (default 3).
    """

    def __init__(
        self,
        similarity_threshold: float = 0.80,
        ngram_size: int = 3,
        max_entries: int = 50_000,
    ) -> None:
        self._threshold = similarity_threshold
        self._n = ngram_size
        self._max_entries = max_entries
        self._fingerprints: dict[tuple[str, str], PromptFingerprint] = {}

    # ── Registration ─────────────────────────────────────────────────

    def register_prompt(
        self,
        tenant_id: str,
        agent_id: str,
        system_prompt: str,
    ) -> PromptFingerprint:
        """Register a system prompt and store its fingerprint.

        The raw prompt is **not** stored — only the n-gram distribution
        and SHA-256 hash.
        """
        ngrams = self._extract_ngrams(system_prompt)
        fp = PromptFingerprint(
            agent_id=agent_id,
            tenant_id=tenant_id,
            ngram_counts=dict(ngrams),
            total_ngrams=sum(ngrams.values()),
            text_hash=hashlib.sha256(system_prompt.encode("utf-8")).hexdigest(),
        )
        self._fingerprints[(tenant_id, agent_id)] = fp
        # Evict oldest if over limit
        if len(self._fingerprints) > self._max_entries:
            oldest_key = next(iter(self._fingerprints))
            del self._fingerprints[oldest_key]
        return fp

    def unregister(self, tenant_id: str, agent_id: str) -> bool:
        """Remove a fingerprint.  Returns True if it existed."""
        return self._fingerprints.pop((tenant_id, agent_id), None) is not None

    # ── Detection ────────────────────────────────────────────────────

    def check(
        self,
        tenant_id: str,
        agent_id: str,
        output_text: str,
    ) -> LeakResult:
        """Check if *output_text* leaks the registered system prompt.

        Returns a ``LeakResult`` indicating whether a leak was detected.
        """
        fp = self._fingerprints.get((tenant_id, agent_id))
        if fp is None:
            return LeakResult(leaked=False, similarity=0.0)

        # ── Verbatim check (fast path)
        output_hash = hashlib.sha256(output_text.encode("utf-8")).hexdigest()
        if output_hash == fp.text_hash:
            return LeakResult(
                leaked=True,
                similarity=1.0,
                verbatim=True,
                agent_id=agent_id,
                tenant_id=tenant_id,
            )

        # ── Fuzzy check (n-gram cosine similarity)
        output_ngrams = self._extract_ngrams(output_text)
        similarity = self._cosine_similarity(fp.ngram_counts, output_ngrams)

        return LeakResult(
            leaked=similarity >= self._threshold,
            similarity=round(similarity, 4),
            verbatim=False,
            agent_id=agent_id,
            tenant_id=tenant_id,
        )

    # ── Internals ────────────────────────────────────────────────────

    def _extract_ngrams(self, text: str) -> Counter[str]:
        """Extract character n-grams from normalised text."""
        normalised = text.lower().strip()
        if len(normalised) < self._n:
            return Counter({normalised: 1}) if normalised else Counter()
        return Counter(normalised[i : i + self._n] for i in range(len(normalised) - self._n + 1))

    @staticmethod
    def _cosine_similarity(a: dict[str, int], b: Counter[str] | dict[str, int]) -> float:
        """Cosine similarity between two n-gram frequency vectors."""
        if not a or not b:
            return 0.0

        # Dot product
        common_keys = set(a) & set(b)
        dot = sum(a[k] * b[k] for k in common_keys)

        # Magnitudes
        mag_a = sum(v * v for v in a.values()) ** 0.5
        mag_b = sum(v * v for v in b.values()) ** 0.5

        if mag_a == 0 or mag_b == 0:
            return 0.0

        return dot / (mag_a * mag_b)

    @property
    def threshold(self) -> float:
        return self._threshold

    def __len__(self) -> int:
        return len(self._fingerprints)
