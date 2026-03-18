# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Content Firewall (U0).

Defense-in-depth layer between user input and the LLM:

  INPUT  →  [Injection Check]  →  [Sanitize]  →  LLM  →  [Output Scan]  →  USER
              fast+deep path       strip control       secrets / PII / leaks

Reuses Phase 2 classifiers:
  - PromptInjectionClassifier   (ml.content.classifiers.prompt_injection)
  - OutputContentScanner        (ml.content.scanners.output_scanner)

Performance target: < 50 ms combined input + output scan.

Security:
  - Input max length enforced (8 KiB default — LLM context is separate)
  - Unicode normalization to defeat homoglyph / invisible-char attacks
  - Blocked patterns: system-prompt override, role impersonation, chain-of-thought extraction
  - Output: secrets, PII, internal IPs/hostnames, encoded exfiltration
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger("phantex.copilot.firewall")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_INPUT_LENGTH = 8192  # 8 KiB — user message hard cap
MAX_OUTPUT_LENGTH = 32768  # 32 KiB — LLM response hard cap

# Fast-path regex patterns for common prompt injection attempts
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+(instructions|prompts?|context)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|the)?\s*(new|different)", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\|?(system|im_start|im_end)\|?>", re.I),
    re.compile(r"(reveal|show|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions|rules)", re.I),
    re.compile(r"(act|behave|respond)\s+(as|like)\s+(if\s+)?(you|a)", re.I),
    re.compile(r"forget\s+(everything|all|your)", re.I),
    re.compile(r"jailbreak|DAN\s+mode|developer\s+mode", re.I),
    re.compile(r"do\s+anything\s+now", re.I),
    re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I),
]

# Output patterns — secrets, PII, internal infra
_SECRET_PATTERNS = [
    re.compile(r"(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.I),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),  # JWT
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI key
]

_PII_PATTERNS = [
    re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"),  # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
]

_INTERNAL_PATTERNS = [
    re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
    re.compile(r"phantex-(postgres|clickhouse|neo4j|redis|kafka|backend|gateway|trust-engine)\b", re.I),
]

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FirewallVerdict:
    """Result of a firewall check."""

    allowed: bool = True
    blocked_reason: str | None = None
    sanitized_input: str | None = None  # Cleaned input (if input check)
    redacted_output: str | None = None  # Cleaned output (if output check)
    findings: list[str] = field(default_factory=list)
    scan_ms: float = 0.0

# ── Copilot Firewall ─────────────────────────────────────────────────────────

class CopilotFirewall:
    """
    Content firewall for the Copilot pipeline.

    Usage::

        fw = CopilotFirewall()

        # Before sending to LLM
        verdict = fw.scan_input(user_message)
        if not verdict.allowed:
            return error(verdict.blocked_reason)

        # After receiving LLM response
        verdict = fw.scan_output(llm_response)
        safe_response = verdict.redacted_output or llm_response
    """

    def __init__(
        self,
        *,
        max_input_length: int = MAX_INPUT_LENGTH,
        max_output_length: int = MAX_OUTPUT_LENGTH,
        strict_mode: bool = True,
    ) -> None:
        self._max_input = max_input_length
        self._max_output = max_output_length
        self._strict = strict_mode

        # Try to load Phase 2 deep classifiers (graceful if missing)
        self._deep_classifier = None
        self._output_scanner = None
        try:
            from ml.content.classifiers.prompt_injection import PromptInjectionClassifier

            self._deep_classifier = PromptInjectionClassifier()
            logger.info("copilot_firewall_deep_classifier_loaded")
        except Exception:
            logger.warning("copilot_firewall_deep_classifier_unavailable, using fast-only mode")

        try:
            from ml.content.scanners.output_scanner import OutputContentScanner

            self._output_scanner = OutputContentScanner()
            logger.info("copilot_firewall_output_scanner_loaded")
        except Exception:
            logger.warning("copilot_firewall_output_scanner_unavailable, using regex-only mode")

    # ── Input scanning ────────────────────────────────────────────────────────

    def scan_input(self, text: str) -> FirewallVerdict:
        """
        Scan user input for prompt injection and malicious content.

        Returns a FirewallVerdict with:
          - allowed: Whether the input is safe to send to LLM
          - sanitized_input: Cleaned version of the input
          - findings: List of detected issues
        """
        t0 = time.monotonic()
        findings: list[str] = []

        # 1. Length check
        if len(text) > self._max_input:
            text = text[: self._max_input]
            findings.append(f"Input truncated to {self._max_input} chars")

        # 2. Unicode normalization (defeat homoglyph attacks)
        try:
            import unicodedata

            text = unicodedata.normalize("NFKC", text)
        except Exception:
            pass

        # 3. Strip invisible/control characters (keep newlines, tabs)
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)
        if sanitized != text:
            findings.append("Stripped control characters")
            text = sanitized

        # 4. Fast-path regex injection detection
        injection_score = 0.0
        for pat in _INJECTION_PATTERNS:
            match = pat.search(text)
            if match:
                findings.append(f"Injection pattern: {match.group()[:60]}")
                injection_score += 0.3

        # 5. Deep-path classifier (if available)
        if self._deep_classifier is not None and injection_score < 0.5:
            try:
                verdict = self._deep_classifier.classify(text)
                if hasattr(verdict, "score") and verdict.score > 0.7:
                    injection_score = max(injection_score, verdict.score)
                    findings.append(f"Deep classifier: score={verdict.score:.2f}")
            except Exception as exc:
                logger.debug("copilot_firewall_deep_classify_error: %s", exc)

        scan_ms = round((time.monotonic() - t0) * 1000, 1)

        # 6. Decide
        if injection_score >= 0.6 and self._strict:
            return FirewallVerdict(
                allowed=False,
                blocked_reason="Potential prompt injection detected. Please rephrase your question.",
                sanitized_input=text,
                findings=findings,
                scan_ms=scan_ms,
            )

        return FirewallVerdict(
            allowed=True,
            sanitized_input=text,
            findings=findings,
            scan_ms=scan_ms,
        )

    # ── Output scanning ───────────────────────────────────────────────────────

    def scan_output(self, text: str) -> FirewallVerdict:
        """
        Scan LLM output for secrets, PII, and internal infrastructure leaks.

        Returns a FirewallVerdict with:
          - redacted_output: Content with sensitive data masked
          - findings: List of detected issues
        """
        t0 = time.monotonic()
        findings: list[str] = []
        redacted = text

        # Length cap
        if len(redacted) > self._max_output:
            redacted = redacted[: self._max_output]
            findings.append(f"Output truncated to {self._max_output} chars")

        # 1. Secret patterns
        for pat in _SECRET_PATTERNS:
            matches = pat.findall(redacted)
            if matches:
                findings.append(f"Secret pattern found: {len(matches)} match(es)")
                redacted = pat.sub("[REDACTED]", redacted)

        # 2. PII patterns
        for pat in _PII_PATTERNS:
            matches = pat.findall(redacted)
            if matches:
                findings.append(f"PII pattern found: {len(matches)} match(es)")
                redacted = pat.sub("[REDACTED-PII]", redacted)

        # 3. Internal infrastructure leaks
        for pat in _INTERNAL_PATTERNS:
            matches = pat.findall(redacted)
            if matches:
                findings.append(f"Internal reference found: {len(matches)} match(es)")
                redacted = pat.sub("[INTERNAL]", redacted)

        # 4. Deep output scanner (if available)
        if self._output_scanner is not None:
            try:
                result = self._output_scanner.scan(redacted)
                if hasattr(result, "has_findings") and result.has_findings:
                    findings.append(f"Output scanner: {result.top_finding}")
            except Exception as exc:
                logger.debug("copilot_firewall_output_scan_error: %s", exc)

        scan_ms = round((time.monotonic() - t0) * 1000, 1)

        return FirewallVerdict(
            allowed=True,
            redacted_output=redacted,
            findings=findings,
            scan_ms=scan_ms,
        )
