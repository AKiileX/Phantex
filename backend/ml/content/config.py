# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Configuration.

Central configuration for thresholds, model paths, feature toggles,
and all tunable constants for the content analysis pipeline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

@dataclass(frozen=True)
class ContentAnalysisConfig:
    """Top-level config for the content analysis pipeline."""

    # ── Global ──────────────────────────────────────────────────────
    enabled: bool = True
    max_content_length: int = 32_768  # 32 KB — truncate longer content
    fast_threshold: float = 0.85  # Fast-path score above this → skip deep
    alert_threshold: float = 0.5  # Score above this → ALERT
    block_threshold: float = 0.8  # Score above this → BLOCK

    # ── Prompt injection classifier ─────────────────────────────────
    injection_enabled: bool = True
    injection_regex_only: bool = False  # True → skip ML, regex/heuristic only
    injection_fast_weight: float = 0.6  # Weight for fast-path score in fusion
    injection_deep_weight: float = 0.4  # Weight for deep-path score in fusion
    injection_model_path: str = ""  # Path to serialized ML model (empty → heuristic)

    # ── Output scanner ──────────────────────────────────────────────
    output_scan_enabled: bool = True
    prompt_leak_similarity_threshold: float = 0.80
    entropy_threshold: float = 4.5  # Shannon entropy above this → suspicious

    # ── Data classifier ─────────────────────────────────────────────
    data_classification_enabled: bool = True
    luhn_validation: bool = True  # Validate credit card numbers with Luhn

    # ── MCP / tool policy ───────────────────────────────────────────
    tool_policy_enabled: bool = True
    mcp_policy_enabled: bool = True
    default_mcp_trust_level: str = "unknown"
    # ── Exploit code scanner (JB7a) ──────────────────────────────
    exploit_scan_enabled: bool = True

    # ── Campaign tracker (JB7b) ─────────────────────────────────
    campaign_tracking_enabled: bool = True
    campaign_window_seconds: float = 86_400.0  # 24h sliding window
    campaign_alert_threshold: float = 0.6  # Score above this → ALERT
    campaign_block_threshold: float = 0.8  # Score above this → BLOCK
    campaign_decay_half_life: float = 21_600.0  # 6h half-life for signal decay
    campaign_max_agents: int = 50_000  # Max tracked agents before LRU eviction

    # ── Trust boundary scanner (JB7c) ───────────────────────────
    trust_boundary_scan_enabled: bool = True

    # ── Embedding similarity classifier (JB8a) ──────────────────
    embedding_similarity_enabled: bool = True
    embedding_model_name: str = "all-MiniLM-L6-v2"
    embedding_device: str = "cpu"
    embedding_high_threshold: float = 0.82  # Sim above → BLOCK
    embedding_medium_threshold: float = 0.65  # Sim above → ALERT
    embedding_low_threshold: float = 0.45  # Sim above → LOG

    # ── Trained content classifier (JB8b) ────────────────────────
    trained_classifier_enabled: bool = True
    trained_model_path: str = ""  # Path to saved model

    # ── Cross-signal fusion (JB8c) ──────────────────────────────
    cross_signal_enabled: bool = True
    fusion_content_weight: float = 0.35
    fusion_behavioral_weight: float = 0.30
    fusion_baseline_weight: float = 0.20
    fusion_campaign_weight: float = 0.15
    fusion_alert_threshold: float = 0.45
    fusion_block_threshold: float = 0.75
    fusion_min_agreement: int = 2  # Min active signals for ALERT+

    # ── Feedback loop (JB8c) ─────────────────────────────────────
    feedback_dual_approval: bool = True  # Dismissals need admin sign-off

    # ── Rate limiting ───────────────────────────────────────────────
    max_analyses_per_second: int = 10_000  # Per-tenant cap
    rate_limit_window_seconds: int = 1

    # ── Hardening ───────────────────────────────────────────────────
    timing_jitter_ms: float = 1.0  # ±jitter fed to input_sanitizer.sanitize()
    redos_max_match_ms: int = 10  # Max ms per regex match (reserved — requires third-party timeout lib)

    @classmethod
    def from_env(cls) -> ContentAnalysisConfig:
        """Build config from environment variables with safe defaults."""
        return cls(
            enabled=os.getenv("CONTENT_ANALYSIS_ENABLED", "true").lower() == "true",
            max_content_length=int(
                os.getenv("CONTENT_MAX_LENGTH", str(cls.max_content_length)),
            ),
            injection_regex_only=os.getenv(
                "CONTENT_INJECTION_REGEX_ONLY",
                "false",
            ).lower()
            == "true",
            injection_model_path=os.getenv("CONTENT_INJECTION_MODEL_PATH", ""),
        )
