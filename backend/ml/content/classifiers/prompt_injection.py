# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Prompt Injection Classifier.

Two-stage detection:
1. **Fast path** — Regex pattern matching + keyword heuristic (< 1 ms).
   If the fast-path score exceeds ``config.fast_threshold``, a verdict is
   returned immediately (no deep path).
2. **Deep path** — TF-IDF + LinearSVC (< 10 ms).  Only runs when the fast
   path is inconclusive.

Final score = ``fast_weight * fast_score + deep_weight * deep_score``
(weights from ``ContentAnalysisConfig``).

ReDoS protection:
- All regex patterns are pre-compiled and reviewed for catastrophic
  backtracking (see ``injection_patterns.py``).
- Content is length-capped to ``config.max_content_length`` before scanning.

Graceful degradation:
- If the deep-path model is unavailable, the classifier operates in
  *fast-only* mode and sets ``verdict.degraded = True``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ml.content.base import BaseClassifier
from ml.content.config import ContentAnalysisConfig
from ml.content.patterns.encoding_utils import normalize
from ml.content.patterns.injection_patterns import (
    PatternHit,
    compute_heuristic_score,
    scan_fast,
)
from ml.content.verdict import Confidence, ContentVerdict, Decision, Label, Severity

logger = logging.getLogger(__name__)

class PromptInjectionClassifier(BaseClassifier):
    """Prompt-injection detector with fast and deep paths.

    Parameters
    ----------
    config:
        Content analysis configuration.  Uses ``injection.*`` and
        global thresholds from this object.

    Note
    ----
    Content is truncated to ``config.max_content_length`` before scanning.
    Upstream callers (e.g. ``ContentAnalyzer``) may *also* truncate; this
    is intentional defense-in-depth — each layer enforces its own cap.
    """

    def __init__(self, config: ContentAnalysisConfig | None = None) -> None:
        self._config = config or ContentAnalysisConfig()
        self._deep_model: Any | None = None
        self._deep_vectorizer: Any | None = None
        self._deep_available: bool = False
        self._load_deep_model()

    # ── BaseClassifier interface ─────────────────────────────────────────

    @property
    def name(self) -> str:
        return "prompt_injection"

    def classify(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> ContentVerdict:
        """Classify *text* for prompt injection intent."""
        if not text or not self._config.enabled:
            return self._benign_verdict()

        # Length-cap
        capped = text[: self._config.max_content_length]

        # Normalise encoding to defeat evasion
        normalised = normalize(capped)

        # ── Fast path ────────────────────────────────────────────────
        hits = scan_fast(normalised)
        heuristic_score = compute_heuristic_score(normalised)
        fast_score = self._aggregate_fast_score(hits, heuristic_score)

        # If fast path alone is high-confidence, return immediately
        if fast_score >= self._config.fast_threshold:
            return self._build_verdict(
                score=fast_score,
                fast_score=fast_score,
                deep_score=None,
                hits=hits,
                degraded=False,
            )

        # ── Deep path ────────────────────────────────────────────────
        deep_score: float | None = None
        degraded = False

        if self._deep_available:
            try:
                deep_score = self._run_deep(normalised)
            except Exception:
                logger.warning(
                    "prompt_injection deep-path failed; falling back to fast-only",
                    exc_info=True,
                )
                degraded = True
        else:
            degraded = True

        # ── Score fusion ─────────────────────────────────────────────
        if deep_score is not None:
            fused = self._config.injection_fast_weight * fast_score + self._config.injection_deep_weight * deep_score
        else:
            fused = fast_score

        return self._build_verdict(
            score=fused,
            fast_score=fast_score,
            deep_score=deep_score,
            hits=hits,
            degraded=degraded,
        )

    def health_check(self) -> bool:
        return True  # fast path always works

    # ── Deep-path helpers ────────────────────────────────────────────────

    def _load_deep_model(self) -> None:
        """Try to load the TF-IDF + SVM model from disk."""
        model_path = self._config.injection_model_path
        if not model_path or not os.path.exists(model_path):
            logger.info("No deep-path model at %s — running in fast-only mode", model_path)
            return

        try:
            import joblib  # type: ignore[import-untyped]

            bundle = joblib.load(model_path)
            self._deep_vectorizer = bundle["vectorizer"]
            self._deep_model = bundle["model"]
            self._deep_available = True
            logger.info("Deep-path model loaded from %s", model_path)
        except Exception:
            logger.warning("Failed to load deep-path model from %s", model_path, exc_info=True)

    def _run_deep(self, text: str) -> float:
        """Return a 0.0–1.0 injection probability from the SVM model."""
        assert self._deep_vectorizer is not None
        assert self._deep_model is not None

        vec = self._deep_vectorizer.transform([text])
        # decision_function → signed distance; convert to [0, 1]
        raw = self._deep_model.decision_function(vec)[0]
        # Logistic squash
        import numpy as np

        return float(1.0 / (1.0 + np.exp(-raw)))

    # ── Scoring logic ────────────────────────────────────────────────────

    @staticmethod
    def _aggregate_fast_score(
        hits: list[PatternHit],
        heuristic_score: float,
    ) -> float:
        """Combine pattern match weights + heuristic into 0.0–1.0 score."""
        if not hits and heuristic_score <= 0.0:
            return 0.0

        # Weighted sum of top-5 hits (diminishing returns)
        weight_sum = 0.0
        for i, hit in enumerate(hits[:5]):
            decay = 1.0 / (1.0 + i * 0.3)  # 1.0, 0.77, 0.63, …
            weight_sum += hit.weight * decay

        # Normalise hit score: 1 hit at weight 1.0 → ~0.45; 5 heavy hits → ~0.9
        hit_score = min(1.0, weight_sum / 3.5)

        # Combine with heuristic (heuristic is a softer signal)
        combined = 0.7 * hit_score + 0.3 * heuristic_score
        return round(min(1.0, combined), 4)

    # ── Verdict builders ─────────────────────────────────────────────────

    def _build_verdict(
        self,
        *,
        score: float,
        fast_score: float,
        deep_score: float | None,
        hits: list[PatternHit],
        degraded: bool,
    ) -> ContentVerdict:
        """Map fused score to Label / Decision / Severity."""
        # Decision thresholds
        if score >= self._config.block_threshold:
            decision = Decision.BLOCK
            label = Label.MALICIOUS
            severity = Severity.CRITICAL
        elif score >= self._config.alert_threshold:
            decision = Decision.ALERT
            label = Label.SUSPICIOUS
            severity = Severity.HIGH
        elif score > 0.2:
            decision = Decision.LOG
            label = Label.SUSPICIOUS
            severity = Severity.MEDIUM
        else:
            decision = Decision.ALLOW
            label = Label.BENIGN
            severity = Severity.INFO

        # Confidence
        if score >= 0.85:
            confidence = Confidence.HIGH
        elif score >= 0.5:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        # Evidence
        evidence_parts: list[str] = []
        for h in hits[:5]:
            evidence_parts.append(f"[{h.category}] {h.name}: '{h.matched_text}'")
        evidence = "; ".join(evidence_parts) if evidence_parts else ""

        return ContentVerdict(
            score=score,
            label=label,
            classifier_name=self.name,
            confidence=confidence,
            evidence=evidence,
            severity=severity,
            decision=decision,
            atlas_technique="AML.T0051",  # MITRE ATLAS: LLM Prompt Injection
            matched_patterns=tuple(h.name for h in hits),
            degraded=degraded,
            metadata={
                "fast_score": fast_score,
                "deep_score": deep_score,
                "hit_count": len(hits),
            },
        )

    def _benign_verdict(self) -> ContentVerdict:
        return ContentVerdict.benign(
            classifier_name=self.name,
            degraded=not self._config.enabled,
        )
