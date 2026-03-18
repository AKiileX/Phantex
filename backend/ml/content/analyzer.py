# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Analyzer Orchestrator.

``ContentAnalyzer`` is the **single entry-point** that the rest of the
Phantex system calls.  It routes a text blob through every registered
classifier and returns either:

- the single highest-priority ``ContentVerdict`` (default), or
- a list of all verdicts.

Pipeline flow::

    text → length cap → normalise → classifier₁ … classifierₙ → merge → verdict

Thread-safety: the analyzer is safe to call from multiple coroutines
concurrently (all state is immutable after ``__init__``).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from ml.content.base import BaseClassifier
from ml.content.classifiers.registry import ClassifierRegistry
from ml.content.config import ContentAnalysisConfig
from ml.content.verdict import SEVERITY_ORDER, ContentVerdict, Decision

logger = logging.getLogger(__name__)

class ContentAnalyzer:
    """Orchestrate content classifiers and emit a merged verdict.

    Parameters
    ----------
    config:
        Content analysis configuration.
    classifiers:
        Optional list of pre-built classifiers to register.  If omitted
        the default set (prompt injection) is auto-registered.
    """

    def __init__(
        self,
        config: ContentAnalysisConfig | None = None,
        classifiers: list[BaseClassifier] | None = None,
    ) -> None:
        self._config = config or ContentAnalysisConfig()
        self._registry = ClassifierRegistry()

        if classifiers:
            for clf in classifiers:
                self._registry.register(clf)
        else:
            self._register_defaults()

    # ── Public API ───────────────────────────────────────────────────────

    def analyze(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> ContentVerdict:
        """Analyse *text* and return the highest-severity verdict.

        This is the primary entry-point for the whole content analysis
        pipeline.  If the pipeline is disabled or no classifiers are
        registered, returns a benign ALLOW verdict.
        """
        if not self._config.enabled or not text:
            return ContentVerdict.benign(classifier_name="content_analyzer")

        verdicts = self.analyze_all(text, metadata)
        if not verdicts:
            return ContentVerdict.benign(classifier_name="content_analyzer")

        # Return highest-severity verdict (CRITICAL > HIGH > … > INFO),
        # breaking ties by score descending.
        return max(
            verdicts,
            key=lambda v: (
                _SEVERITY_ORDER.get(v.severity, 0),
                v.score,
            ),
        )

    def analyze_all(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> list[ContentVerdict]:
        """Run *all* classifiers and return a list of verdicts."""
        if not self._config.enabled or not text:
            return []

        capped = text[: self._config.max_content_length]
        verdicts: list[ContentVerdict] = []

        for clf in self._registry:
            t0 = time.monotonic()
            try:
                verdict = clf.classify(capped, metadata)
                elapsed_ms = (time.monotonic() - t0) * 1000
                if elapsed_ms > 15.0:
                    logger.warning("classifier %s slow: %.1f ms", clf.name, elapsed_ms)
                verdicts.append(verdict)
            except Exception:
                logger.error(
                    "classifier %s failed; skipping",
                    clf.name,
                    exc_info=True,
                )
                # Emit a degraded verdict so the caller knows
                verdicts.append(
                    ContentVerdict.benign(
                        classifier_name=clf.name,
                        degraded=True,
                    ),
                )

        return verdicts

    # ── Convenience ──────────────────────────────────────────────────────

    def should_block(self, text: str, metadata: dict[str, Any] | None = None) -> bool:
        """Return ``True`` if the highest verdict says BLOCK."""
        return self.analyze(text, metadata).decision == Decision.BLOCK

    def should_alert(self, text: str, metadata: dict[str, Any] | None = None) -> bool:
        """Return ``True`` if the highest verdict says ALERT or BLOCK."""
        return self.analyze(text, metadata).decision in (
            Decision.ALERT,
            Decision.BLOCK,
        )

    # ── Registry delegation ──────────────────────────────────────────────

    @property
    def registry(self) -> ClassifierRegistry:
        return self._registry

    @property
    def config(self) -> ContentAnalysisConfig:
        return self._config

    # ── Private ──────────────────────────────────────────────────────────

    def _register_defaults(self) -> None:
        """Register the built-in classifiers."""
        from ml.content.classifiers.prompt_injection import (
            PromptInjectionClassifier,
        )

        self._registry.register(PromptInjectionClassifier(self._config))

        # JB7a: Exploit code scanner (detects offensive tooling in output)
        if self._config.exploit_scan_enabled:
            from ml.content.offensive.exploit_scanner import ExploitCodeScanner

            self._registry.register(ExploitCodeScanner(self._config))

        # JB8a: Embedding similarity classifier (semantic detection)
        if self._config.embedding_similarity_enabled:
            try:
                from ml.content.embeddings.corpus import AttackCorpus
                from ml.content.embeddings.encoder import EmbeddingEncoder
                from ml.content.embeddings.similarity import (
                    EmbeddingSimilarityClassifier,
                )

                encoder = EmbeddingEncoder(
                    model_name=self._config.embedding_model_name,
                    device=self._config.embedding_device,
                )
                corpus = AttackCorpus(encoder)
                self._registry.register(
                    EmbeddingSimilarityClassifier(
                        encoder=encoder,
                        corpus=corpus,
                        config=self._config,
                        high_threshold=self._config.embedding_high_threshold,
                        medium_threshold=self._config.embedding_medium_threshold,
                        low_threshold=self._config.embedding_low_threshold,
                    )
                )
                self._shared_encoder = encoder
                self._shared_corpus = corpus
            except Exception:
                logger.warning(
                    "JB8a embedding classifier unavailable; skipping",
                    exc_info=True,
                )

        # JB8b: Trained content classifier (learned model)
        if self._config.trained_classifier_enabled:
            try:
                from ml.content.trained.classifier import TrainedContentClassifier

                encoder = getattr(self, "_shared_encoder", None)
                if encoder is None:
                    from ml.content.embeddings.encoder import EmbeddingEncoder

                    encoder = EmbeddingEncoder(
                        model_name=self._config.embedding_model_name,
                        device=self._config.embedding_device,
                    )

                self._registry.register(
                    TrainedContentClassifier(
                        encoder=encoder,
                        config=self._config,
                        model_path=self._config.trained_model_path,
                    )
                )
            except Exception:
                logger.warning(
                    "JB8b trained classifier unavailable; skipping",
                    exc_info=True,
                )

# ── Helpers ──────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = SEVERITY_ORDER  # Re-export for backward compat
