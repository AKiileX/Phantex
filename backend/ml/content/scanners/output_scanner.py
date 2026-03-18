# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Output Content Scanner (JB3).

Orchestrates all output scanning checks:
1. Secret / credential patterns
2. System prompt leakage
3. Encoded exfiltration
4. Internal infrastructure leaks

Returns an ``OutputScanResult`` merging findings from all sub-scanners.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ml.content.scanners.encoding_detector import EncodingDetector, EncodingHit
from ml.content.scanners.internal_leak_detector import (
    InternalLeakHit,
    scan_for_internal_leaks,
)
from ml.content.scanners.prompt_leak_detector import LeakResult, PromptLeakDetector
from ml.content.scanners.secret_patterns import SecretHit, scan_for_secrets
from ml.content.verdict import Decision, Severity

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class OutputScanResult:
    """Aggregated result from all output sub-scanners."""

    has_findings: bool = False

    # Sub-results
    secret_hits: tuple[SecretHit, ...] = ()
    prompt_leak: LeakResult | None = None
    encoding_hits: tuple[EncodingHit, ...] = ()
    internal_leak_hits: tuple[InternalLeakHit, ...] = ()

    # Aggregated decision
    decision: Decision = Decision.ALLOW
    severity: Severity = Severity.INFO
    top_finding: str = ""  # Human-readable summary of worst finding

    metadata: dict[str, Any] = field(default_factory=dict)

class OutputContentScanner:
    """Single-call output scanner that orchestrates all sub-scanners.

    Parameters
    ----------
    prompt_leak_detector:
        Shared PromptLeakDetector (system prompts must be registered
        separately via ``register_prompt``).
    encoding_detector:
        Optional EncodingDetector with custom thresholds.
    max_output_length:
        Max characters to scan (remainder is truncated with a warning).
    """

    def __init__(
        self,
        prompt_leak_detector: PromptLeakDetector | None = None,
        encoding_detector: EncodingDetector | None = None,
        max_output_length: int = 32_768,
    ) -> None:
        self._leak_detector = prompt_leak_detector if prompt_leak_detector is not None else PromptLeakDetector()
        self._encoding_detector = encoding_detector if encoding_detector is not None else EncodingDetector()
        self._max_len = max_output_length

    def scan(
        self,
        text: str,
        tenant_id: str = "",
        agent_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> OutputScanResult:
        """Run all output scanners and return a merged result."""
        if not text:
            return OutputScanResult()

        truncated = len(text) > self._max_len
        capped = text[: self._max_len]

        # ── 1. Secret patterns
        secret_hits = scan_for_secrets(capped)

        # ── 2. Prompt leak check
        prompt_leak: LeakResult | None = None
        if tenant_id and agent_id:
            prompt_leak = self._leak_detector.check(tenant_id, agent_id, capped)
            if not prompt_leak.leaked:
                prompt_leak = None  # Only store if leaked

        # ── 3. Encoding / exfiltration
        encoding_hits = self._encoding_detector.scan(capped)

        # ── 4. Internal leaks
        internal_hits = scan_for_internal_leaks(capped)

        # ── Aggregate decision
        has_findings = bool(secret_hits or prompt_leak or encoding_hits or internal_hits)
        decision, severity, top_finding = self._aggregate(
            secret_hits,
            prompt_leak,
            encoding_hits,
            internal_hits,
        )

        return OutputScanResult(
            has_findings=has_findings,
            secret_hits=tuple(secret_hits),
            prompt_leak=prompt_leak,
            encoding_hits=tuple(encoding_hits),
            internal_leak_hits=tuple(internal_hits),
            decision=decision,
            severity=severity,
            top_finding=top_finding,
            metadata={"truncated": truncated, **(metadata or {})},
        )

    # ── Delegation ───────────────────────────────────────────────────

    def register_prompt(
        self,
        tenant_id: str,
        agent_id: str,
        system_prompt: str,
    ) -> None:
        """Register a system prompt fingerprint for leak detection."""
        self._leak_detector.register_prompt(tenant_id, agent_id, system_prompt)

    @property
    def leak_detector(self) -> PromptLeakDetector:
        return self._leak_detector

    @property
    def encoding_detector(self) -> EncodingDetector:
        return self._encoding_detector

    # ── Private ──────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(
        secrets: list[SecretHit],
        leak: LeakResult | None,
        encodings: list[EncodingHit],
        internals: list[InternalLeakHit],
    ) -> tuple[Decision, Severity, str]:
        """Determine the worst-case decision from all sub-results."""
        # Private keys → BLOCK + CRITICAL
        critical_secrets = [s for s in secrets if s.severity == "critical"]
        if critical_secrets:
            return (
                Decision.BLOCK,
                Severity.CRITICAL,
                f"Private key / critical secret detected: {critical_secrets[0].pattern_name}",
            )

        # System prompt leakage → ALERT + HIGH
        if leak and leak.leaked:
            action = "verbatim" if leak.verbatim else f"similarity {leak.similarity:.2f}"
            return (
                Decision.ALERT,
                Severity.HIGH,
                f"System prompt leaked ({action})",
            )

        # High-severity secrets → ALERT + HIGH
        if secrets:
            return (
                Decision.ALERT,
                Severity.HIGH,
                f"Secret detected: {secrets[0].pattern_name} ({secrets[0].provider})",
            )

        # Encoding anomalies → ALERT + MEDIUM
        if encodings:
            return (
                Decision.ALERT,
                Severity.MEDIUM,
                f"Encoded data detected: {encodings[0].pattern_name}",
            )

        # Internal leaks → LOG + MEDIUM
        if internals:
            return (
                Decision.LOG,
                Severity.MEDIUM,
                f"Internal info leaked: {internals[0].description}",
            )

        return Decision.ALLOW, Severity.INFO, ""
