# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Sequence Features (J1).

N-gram frequency of event_type sequences (bigram, trigram) over 1h window.
Used to detect unusual action patterns (e.g., FILE_READ→NETWORK_CONNECT
never seen before).
"""

from __future__ import annotations

from collections import Counter

from ml.features.registry import FeatureDefinition, register_feature

# ── Feature Definitions ──────────────────────────────────────────────────────

register_feature(
    FeatureDefinition(
        name="bigram_entropy",
        category="sequence",
        description="Shannon entropy of event-type bigram distribution (1h window)",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="trigram_entropy",
        category="sequence",
        description="Shannon entropy of event-type trigram distribution (1h window)",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="unique_bigrams",
        category="sequence",
        description="Number of unique event-type bigrams (1h window)",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="unique_trigrams",
        category="sequence",
        description="Number of unique event-type trigrams (1h window)",
        window="1h",
    )
)

register_feature(
    FeatureDefinition(
        name="top_bigram_ratio",
        category="sequence",
        description="Fraction of events belonging to the most common bigram (1h window)",
        window="1h",
    )
)

def _shannon_entropy(counter: Counter) -> float:
    """Compute Shannon entropy of a frequency distribution."""
    import math

    total = sum(counter.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def compute_sequence_features(
    events: list[dict],
    now: float,
) -> dict[str, float]:
    """Compute event-type sequence n-gram features.

    Args:
        events: Event dicts sorted by timestamp_epoch ascending.
        now: Current epoch timestamp.

    Returns:
        Dict of feature_name → value.
    """
    cutoff = now - 3_600  # 1h window
    window_events = [e for e in events if e.get("timestamp_epoch", 0) >= cutoff]

    # Extract event type sequence
    types = [e.get("event_type", "UNKNOWN") for e in window_events]

    # Bigrams
    bigrams = Counter()
    for i in range(len(types) - 1):
        bigrams[(types[i], types[i + 1])] += 1

    # Trigrams
    trigrams = Counter()
    for i in range(len(types) - 2):
        trigrams[(types[i], types[i + 1], types[i + 2])] += 1

    total_bigrams = sum(bigrams.values())
    top_bigram_count = bigrams.most_common(1)[0][1] if bigrams else 0
    top_ratio = (top_bigram_count / total_bigrams) if total_bigrams > 0 else 0.0

    return {
        "bigram_entropy": _shannon_entropy(bigrams),
        "trigram_entropy": _shannon_entropy(trigrams),
        "unique_bigrams": float(len(bigrams)),
        "unique_trigrams": float(len(trigrams)),
        "top_bigram_ratio": top_ratio,
    }
