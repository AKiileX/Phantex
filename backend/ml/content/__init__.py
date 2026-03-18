# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Phantex — Content Analysis Pipeline

Semantic detection layer for AI agent content: prompts, tool calls,
MCP responses, and agent output.  Closes coverage on 6 of the 14
attack classes that behavioural ML alone cannot detect.

Re-exports the public API surface:

    ContentAnalyzer       — single entry-point for the whole pipeline
    ContentVerdict        — result object returned by all classifiers
    ContentAnalysisConfig — central configuration
    BaseClassifier        — ABC for writing new classifiers
"""

from ml.content.analyzer import ContentAnalyzer
from ml.content.base import BaseClassifier
from ml.content.config import ContentAnalysisConfig
from ml.content.verdict import (
    Confidence,
    ContentVerdict,
    Decision,
    Label,
    Severity,
)

__all__ = [
    "ContentAnalyzer",
    "ContentAnalysisConfig",
    "ContentVerdict",
    "BaseClassifier",
    "Confidence",
    "Decision",
    "Label",
    "Severity",
]
