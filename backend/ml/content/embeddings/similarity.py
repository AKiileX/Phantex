# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8a — Embedding Similarity Classifier.

A ``BaseClassifier`` that produces verdicts by measuring cosine similarity
between input text and a corpus of known attack embeddings.

Detection logic:
1. Encode the input text to a dense vector.
2. Search the ``AttackCorpus`` for the top-k most similar known attacks.
3. Aggregate per-category max similarities.
4. Map the highest similarity to a ContentVerdict (score, label, decision).

Advantages over regex:
- Catches novel phrasings of known attack categories.
- Works across languages (sentence-transformers are multilingual).
- Detects obfuscated/paraphrased injections that share semantic meaning.

Graceful degradation:
- If encoder falls back to TF-IDF hashing, detection quality degrades
  but the classifier still runs.  ``verdict.degraded`` is set to True.
"""

from __future__ import annotations

import logging
from typing import Any

from ml.content.base import BaseClassifier
from ml.content.config import ContentAnalysisConfig
from ml.content.embeddings.corpus import AttackCorpus, SimilarityMatch
from ml.content.embeddings.encoder import EmbeddingEncoder
from ml.content.verdict import Confidence, ContentVerdict, Decision, Label, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_DEFAULT_HIGH_SIM = 0.82  # Above this → BLOCK
_DEFAULT_MEDIUM_SIM = 0.65  # Above this → ALERT
_DEFAULT_LOW_SIM = 0.45  # Above this → LOG
_TOP_K = 5  # Number of corpus matches to consider

class EmbeddingSimilarityClassifier(BaseClassifier):
    """Classify content by semantic similarity to known attacks.

    Parameters
    ----------
    encoder:
        Shared EmbeddingEncoder instance.
    corpus:
        Shared AttackCorpus instance.
    config:
        Content analysis configuration.
    high_threshold:
        Similarity above this → BLOCK.
    medium_threshold:
        Similarity above this → ALERT.
    low_threshold:
        Similarity above this → LOG.
    """

    def __init__(
        self,
        encoder: EmbeddingEncoder | None = None,
        corpus: AttackCorpus | None = None,
        config: ContentAnalysisConfig | None = None,
        *,
        high_threshold: float = _DEFAULT_HIGH_SIM,
        medium_threshold: float = _DEFAULT_MEDIUM_SIM,
        low_threshold: float = _DEFAULT_LOW_SIM,
    ) -> None:
        self._config = config or ContentAnalysisConfig()
        self._encoder = encoder or EmbeddingEncoder()
        self._corpus = corpus or AttackCorpus(self._encoder)
        self._high = high_threshold
        self._medium = medium_threshold
        self._low = low_threshold

    # ------------------------------------------------------------------
    # BaseClassifier interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "embedding_similarity"

    def classify(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> ContentVerdict:
        """Classify *text* by similarity to known attack corpus."""
        if not text or not self._config.enabled:
            return self._benign()

        # Length cap (defense-in-depth; encoder also caps)
        capped = text[: self._config.max_content_length]

        # Search corpus
        matches = self._corpus.search(capped, top_k=_TOP_K)
        if not matches:
            return self._benign()

        # Per-category max similarities
        cat_sims = self._corpus.category_similarities(capped)

        # Highest similarity across all categories
        best = matches[0]
        top_sim = best.similarity

        return self._build_verdict(
            top_sim=top_sim,
            best_match=best,
            cat_sims=cat_sims,
            matches=matches,
        )

    def health_check(self) -> bool:
        return self._encoder.health_check() and self._corpus.size > 0

    # ------------------------------------------------------------------
    # Properties for integration
    # ------------------------------------------------------------------

    @property
    def encoder(self) -> EmbeddingEncoder:
        return self._encoder

    @property
    def corpus(self) -> AttackCorpus:
        return self._corpus

    # ------------------------------------------------------------------
    # Verdict builders
    # ------------------------------------------------------------------

    def _build_verdict(
        self,
        *,
        top_sim: float,
        best_match: SimilarityMatch,
        cat_sims: dict[str, float],
        matches: list[SimilarityMatch],
    ) -> ContentVerdict:
        """Map similarity score to verdict."""
        # Decision thresholds
        if top_sim >= self._high:
            decision = Decision.BLOCK
            label = Label.MALICIOUS
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif top_sim >= self._medium:
            decision = Decision.ALERT
            label = Label.SUSPICIOUS
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM
        elif top_sim >= self._low:
            decision = Decision.LOG
            label = Label.SUSPICIOUS
            severity = Severity.MEDIUM
            confidence = Confidence.LOW
        else:
            return self._benign()

        # Evidence
        evidence_parts: list[str] = []
        for m in matches[:3]:
            evidence_parts.append(f"[{m.sample.category}] sim={m.similarity:.3f} label={m.sample.label}")
        evidence = "; ".join(evidence_parts)

        # ATLAS technique mapping for primary category
        atlas = _category_to_atlas(best_match.sample.category)

        return ContentVerdict(
            score=round(min(1.0, top_sim), 4),
            label=label,
            classifier_name=self.name,
            confidence=confidence,
            evidence=evidence,
            severity=severity,
            decision=decision,
            atlas_technique=atlas,
            matched_patterns=tuple(m.sample.label for m in matches[:5]),
            degraded=self._encoder.using_fallback,
            metadata={
                "top_similarity": round(top_sim, 4),
                "top_category": best_match.sample.category,
                "top_label": best_match.sample.label,
                "category_similarities": cat_sims,
                "match_count": len(matches),
                "categories": list(cat_sims.keys()),
            },
        )

    def _benign(self) -> ContentVerdict:
        return ContentVerdict.benign(
            classifier_name=self.name,
            degraded=self._encoder.using_fallback,
        )

# ---------------------------------------------------------------------------
# ATLAS mapping
# ---------------------------------------------------------------------------

_ATLAS_MAP: dict[str, str] = {
    "prompt_injection": "AML.T0051",
    "social_engineering": "AML.T0051.001",
    "data_exfiltration": "AML.T0048",
    "exploit_generation": "AML.T0040",
    "privilege_escalation": "AML.T0044",
    "reconnaissance": "AML.T0043",
    "lateral_movement": "AML.T0045",
}

def _category_to_atlas(category: str) -> str:
    """Map corpus category to MITRE ATLAS technique ID."""
    return _ATLAS_MAP.get(category, "")
