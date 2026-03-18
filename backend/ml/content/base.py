# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Base Classifier ABC.

Every content classifier (prompt injection, data classification, etc.)
implements this interface.  The ContentAnalyzer orchestrates classifiers
through this common contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ml.content.verdict import ContentVerdict

class BaseClassifier(ABC):
    """Interface every content classifier must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name used in registry lookup and PRL ``ml_score()``."""
        ...

    @abstractmethod
    def classify(self, text: str, metadata: dict | None = None) -> ContentVerdict:
        """Classify *text* and return a verdict.

        Parameters
        ----------
        text:
            The content to analyse (prompt, tool response, agent output, …).
            Already truncated to ``max_content_length`` by the caller.
        metadata:
            Optional context: ``agent_id``, ``tenant_id``, ``event_type``, etc.

        Returns
        -------
        ContentVerdict with score, label, evidence.
        """
        ...

    def health_check(self) -> bool:
        """Return True if the classifier is operational.

        Default implementation always returns True.  Subclasses that depend
        on an ML model file can override to verify the model is loaded.
        """
        return True
