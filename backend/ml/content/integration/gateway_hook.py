# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Gateway Hook (JB6).

Provides ``analyze_event()`` — the single entry-point that the event
pipeline (gateway / consumer) calls for every inbound or outbound event.

Orchestration flow:
  1. Sanitize input (hardening)
  2. Run content analysis
  3. Apply context evaluation (purpose, baseline, policy mode)
  4. Build feature vector for ensemble
  5. Emit alert if warranted
  6. Return decision (allow / block)

All errors are caught → graceful degradation → ALLOW with ``degraded=True``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ml.content.analyzer import ContentAnalyzer
from ml.content.config import ContentAnalysisConfig
from ml.content.context.context_evaluator import ContextEvaluator
from ml.content.hardening.input_sanitizer import sanitize as _sanitize_input
from ml.content.hardening.rate_limiter import ContentRateLimiter
from ml.content.integration.alert_bridge import ContentAlert, content_verdict_to_alert
from ml.content.integration.feature_bridge import (
    ContentFeatureVector,
    build_feature_vector,
)
from ml.content.offensive.campaign_tracker import CampaignTracker
from ml.content.verdict import Decision, Label, Severity

# Severity ranking for max() comparisons
_SEV_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

def _sev_rank(s: Severity) -> int:
    """Return numeric rank for severity comparison."""
    return _SEV_ORDER.get(s, 0)

@dataclass(frozen=True)
class GatewayResult:
    """Result returned to the gateway / consumer."""

    allowed: bool
    decision: str  # Decision.value
    severity: str  # Severity.value
    score: float
    features: ContentFeatureVector
    alert: ContentAlert | None = None
    processing_ms: float = 0.0
    degraded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

class ContentBlockedError(Exception):
    """Raised when content is blocked (for pipelines that use exceptions)."""

    def __init__(self, result: GatewayResult):
        self.result = result
        super().__init__(f"Content blocked: score={result.score:.3f} severity={result.severity}")

class GatewayContentHook:
    """Single entry-point for content analysis in the event pipeline.

    Usage::

        hook = GatewayContentHook()
        result = hook.analyze_event(content, agent_id=..., tenant_id=...)
        if not result.allowed:
            # reject / quarantine
    """

    def __init__(
        self,
        config: ContentAnalysisConfig | None = None,
        analyzer: ContentAnalyzer | None = None,
        context_evaluator: ContextEvaluator | None = None,
        rate_limiter: ContentRateLimiter | None = None,
        campaign_tracker: CampaignTracker | None = None,
    ):
        self._config = config or ContentAnalysisConfig.from_env()
        self._analyzer = analyzer or ContentAnalyzer(config=self._config)
        self._context = context_evaluator or ContextEvaluator()
        self._limiter = rate_limiter or ContentRateLimiter()
        self._campaign = campaign_tracker or (
            CampaignTracker(
                window_seconds=self._config.campaign_window_seconds,
                decay_half_life=self._config.campaign_decay_half_life,
                max_agents=self._config.campaign_max_agents,
            )
            if self._config.campaign_tracking_enabled
            else None
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_event(
        self,
        content: str,
        *,
        agent_id: str = "",
        tenant_id: str = "",
        event_id: str = "",
        direction: str = "inbound",
        raise_on_block: bool = False,
    ) -> GatewayResult:
        """Analyze content and return a gateway result.

        Parameters
        ----------
        content:
            Raw text content to analyze.
        agent_id:
            Originating agent identifier.
        tenant_id:
            Tenant isolation key.
        event_id:
            Unique event identifier for tracing.
        direction:
            ``"inbound"`` (prompt) or ``"outbound"`` (response).
        raise_on_block:
            If True, raises ``ContentBlockedError`` instead of returning.
        """
        t0 = time.perf_counter()

        try:
            result = self._run_analysis(
                content,
                agent_id=agent_id,
                tenant_id=tenant_id,
                event_id=event_id,
                direction=direction,
            )
        except Exception:
            # Graceful degradation — allow with degraded flag
            result = GatewayResult(
                allowed=True,
                decision=Decision.ALLOW.value,
                severity=Severity.INFO.value,
                score=0.0,
                features=ContentFeatureVector(),
                degraded=True,
                processing_ms=round((time.perf_counter() - t0) * 1000, 2),
            )

        # Timing
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        result = GatewayResult(
            allowed=result.allowed,
            decision=result.decision,
            severity=result.severity,
            score=result.score,
            features=result.features,
            alert=result.alert,
            processing_ms=elapsed,
            degraded=result.degraded,
            metadata=result.metadata,
        )

        if raise_on_block and not result.allowed:
            raise ContentBlockedError(result)

        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_analysis(
        self,
        content: str,
        *,
        agent_id: str,
        tenant_id: str,
        event_id: str,
        direction: str,
    ) -> GatewayResult:
        # 0. Sanitize + rate limit
        content = _sanitize_input(
            content,
            add_jitter=True,
            jitter_ms=self._config.timing_jitter_ms,
        )
        if not self._limiter.allow(tenant_id or "__global__"):
            return GatewayResult(
                allowed=True,
                decision=Decision.LOG.value,
                severity=Severity.INFO.value,
                score=0.0,
                features=ContentFeatureVector(),
                degraded=True,
                metadata={"rate_limited": True, "direction": direction},
            )

        # 1. Content analysis
        verdict = self._analyzer.analyze(content)

        # 2. Context evaluation (purpose, baseline, policy mode)
        ctx_decision = self._context.evaluate(
            tenant_id=tenant_id,
            agent_id=agent_id,
            content=content,
            content_type=verdict.label if verdict.label else "unknown",
            verdict_decision=verdict.decision,
            verdict_severity=verdict.severity,
        )

        # 3. Extract baseline drift z-score from context metadata
        drift_z = 0.0
        if ctx_decision and ctx_decision.metadata:
            drift_z = max(
                ctx_decision.metadata.get("length_zscore", 0.0),
                ctx_decision.metadata.get("entropy_zscore", 0.0),
            )

        # 4. Build feature vector
        features = build_feature_vector(
            prompt_injection_verdict=verdict if verdict.label == Label.MALICIOUS else None,
            baseline_drift_z=drift_z,
        )

        # 5. Use context-adjusted decision if available
        final_decision = ctx_decision.decision if ctx_decision else verdict.decision
        final_severity = ctx_decision.severity if ctx_decision else verdict.severity

        # 5b. Campaign tracking — record signal & assess
        campaign_meta: dict[str, Any] = {}
        if self._campaign and agent_id:
            # Record a signal for non-benign verdicts
            if verdict.decision not in (Decision.ALLOW,):
                # Determine signal_type from classifier + decision
                signal_type = "injection"  # default
                clf_name = (verdict.classifier_name or "").lower()
                if "exploit" in clf_name:
                    signal_type = "exploit"
                elif "data_class" in clf_name or verdict.label == "sensitive":
                    signal_type = "sensitive"
                elif verdict.decision == Decision.BLOCK:
                    signal_type = "blocked"

                # Extract ATT&CK categories from exploit scanner metadata
                # for accurate kill-chain phase-coverage scoring.
                categories: list[str] = []
                if verdict.metadata and "categories" in verdict.metadata:
                    categories = verdict.metadata["categories"]
                elif "injection" in clf_name:
                    categories = ["prompt_injection"]
                elif "data_class" in clf_name:
                    categories = ["data_classification"]

                # Record one signal per category for granular tracking
                if categories:
                    for cat in categories:
                        self._campaign.record_signal(
                            agent_id=agent_id,
                            tenant_id=tenant_id,
                            signal_type=signal_type,
                            score=verdict.score,
                            category=cat,
                        )
                else:
                    self._campaign.record_signal(
                        agent_id=agent_id,
                        tenant_id=tenant_id,
                        signal_type=signal_type,
                        score=verdict.score,
                        category=verdict.label or "",
                    )

            # Always assess (to catch agents already near threshold)
            assessment = self._campaign.assess(agent_id, tenant_id)
            campaign_meta["campaign_score"] = assessment.campaign_score
            campaign_meta["campaign_signals"] = assessment.signal_count
            campaign_meta["campaign_escalating"] = assessment.escalating
            campaign_meta["campaign_phase_coverage"] = assessment.phase_coverage

            # Escalate decision based on campaign score
            if assessment.campaign_score >= self._config.campaign_block_threshold:
                final_decision = Decision.BLOCK
                final_severity = Severity.CRITICAL
            elif (
                assessment.campaign_score >= self._config.campaign_alert_threshold and final_decision == Decision.ALLOW
            ):
                final_decision = Decision.ALERT
                final_severity = max(final_severity, Severity.MEDIUM, key=_sev_rank)

        # 6. Alert bridge
        alert = None
        if final_decision in (Decision.ALERT, Decision.BLOCK, Decision.REDACT):
            alert = content_verdict_to_alert(
                verdict,
                agent_id=agent_id,
                tenant_id=tenant_id,
                event_id=event_id,
            )

        allowed = final_decision not in (Decision.BLOCK, Decision.REDACT)

        return GatewayResult(
            allowed=allowed,
            decision=final_decision.value,
            severity=final_severity.value,
            score=verdict.score,
            features=features,
            alert=alert,
            degraded=verdict.degraded,
            metadata={
                "direction": direction,
                "classifier": verdict.classifier_name,
                **campaign_meta,
            },
        )
