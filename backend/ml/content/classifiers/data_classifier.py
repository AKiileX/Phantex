# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Semantic Data Classifier (JB4).

Orchestrates PII, PHI, and financial pattern scanning to produce a
unified ``DataClassification`` result with:
- Matched data items (redacted)
- Sensitivity level (NONE → CRITICAL)
- Compliance tags (GDPR, HIPAA, PCI-DSS, etc.)

Custom proprietary patterns are supported per-tenant.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from ml.content.classifiers.sensitivity import (
    SensitivityLevel,
    classify_sensitivity,
)
from ml.content.data.financial_patterns import FinancialMatch, scan_for_financial
from ml.content.data.phi_patterns import PHIMatch, scan_for_phi
from ml.content.data.pii_patterns import PIIMatch, scan_for_pii
from ml.content.scanners.secret_patterns import SecretHit, scan_for_secrets

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class DataMatch:
    """An individual data detection — value is always redacted."""

    data_type: str
    redacted_value: str
    offset: int
    length: int
    confidence: float
    context: str = ""

@dataclass(frozen=True)
class DataClassification:
    """Unified classification result for a piece of content."""

    labels: tuple[str, ...]  # ("PII", "FINANCIAL", "PHI")
    matches: tuple[DataMatch, ...]
    sensitivity: SensitivityLevel
    compliance_tags: tuple[str, ...]  # ("GDPR", "PCI-DSS", "HIPAA")
    processing_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class CustomPattern:
    """A tenant-configurable proprietary pattern."""

    name: str
    data_type: str
    pattern: re.Pattern[str]
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM
    compliance_tags: tuple[str, ...] = ()
    redact: bool = True

class SemanticDataClassifier:
    """Orchestrates PII, PHI, financial, and custom pattern scanning.

    Parameters
    ----------
    max_content_length:
        Maximum characters to scan (rest is truncated).
    """

    def __init__(self, max_content_length: int = 65_536) -> None:
        self._max_len = max_content_length
        # tenant_id → list of custom patterns
        self._custom_patterns: dict[str, list[CustomPattern]] = {}
        self._lock = threading.Lock()

    # ── Custom patterns ──────────────────────────────────────────────

    def register_custom_pattern(
        self,
        tenant_id: str,
        name: str,
        regex: str,
        data_type: str = "PROPRIETARY",
        sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
        compliance_tags: tuple[str, ...] = (),
    ) -> CustomPattern:
        """Register a tenant-specific detection pattern.

        The regex is validated for basic safety (ReDoS resistance)
        before being compiled.
        """
        # Basic ReDoS guard: reject nested quantifiers
        if re.search(r"(\+|\*|\{)\s*[)]*\s*(\+|\*|\?|\{)", regex):
            raise ValueError(f"Potentially unsafe regex (nested quantifiers): {regex!r}")

        compiled = re.compile(regex, re.I)
        cp = CustomPattern(
            name=name,
            data_type=data_type,
            pattern=compiled,
            sensitivity=sensitivity,
            compliance_tags=compliance_tags,
        )
        with self._lock:
            self._custom_patterns.setdefault(tenant_id, []).append(cp)
        return cp

    def clear_custom_patterns(self, tenant_id: str) -> int:
        """Remove all custom patterns for a tenant.  Returns count removed."""
        with self._lock:
            removed = self._custom_patterns.pop(tenant_id, [])
        return len(removed)

    # ── Classification ───────────────────────────────────────────────

    def classify(
        self,
        text: str,
        tenant_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> DataClassification:
        """Classify *text* for PII, PHI, financial data, and custom patterns.

        Returns a ``DataClassification`` with all matches redacted.
        """
        t0 = time.perf_counter()

        if not text:
            return DataClassification(
                labels=(),
                matches=(),
                sensitivity=SensitivityLevel.NONE,
                compliance_tags=(),
                processing_time_ms=0.0,
            )

        capped = text[: self._max_len]
        all_matches: list[DataMatch] = []

        # ── PII scan
        for hit in scan_for_pii(capped):
            all_matches.append(_from_match(hit))

        # ── PHI scan
        for hit in scan_for_phi(capped):
            all_matches.append(_from_match(hit))

        # ── Financial scan
        for hit in scan_for_financial(capped):
            all_matches.append(_from_match(hit))

        # ── Credential scan (API keys, tokens, private keys)
        for hit in scan_for_secrets(capped):
            all_matches.append(_from_secret_hit(hit))

        # ── Custom patterns (read under lock for thread-safety)
        if tenant_id:
            with self._lock:
                tenant_patterns = list(self._custom_patterns.get(tenant_id, []))
            for cp in tenant_patterns:
                for m in cp.pattern.finditer(capped):
                    raw = m.group(0)
                    redacted = f"[{cp.name}:***]" if cp.redact else raw
                    all_matches.append(
                        DataMatch(
                            data_type=cp.data_type,
                            redacted_value=redacted,
                            offset=m.start(),
                            length=len(raw),
                            confidence=0.70,
                            context=f"custom pattern: {cp.name}",
                        )
                    )

        # ── Sort by offset
        all_matches.sort(key=lambda m: m.offset)

        # ── Sensitivity + compliance
        data_types = [m.data_type for m in all_matches]
        sens = classify_sensitivity(data_types)

        # Merge compliance tags from custom patterns
        extra_tags: set[str] = set()
        if tenant_id:
            for cp in tenant_patterns:
                if any(m.data_type == cp.data_type and m.context.endswith(cp.name) for m in all_matches):
                    extra_tags.update(cp.compliance_tags)

        all_tags = sorted(set(sens.compliance_tags) | extra_tags)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return DataClassification(
            labels=sens.data_labels,
            matches=tuple(all_matches),
            sensitivity=sens.level,
            compliance_tags=tuple(all_tags),
            processing_time_ms=round(elapsed_ms, 3),
            metadata={"truncated": len(text) > self._max_len, **(metadata or {})},
        )

# ── Converters ───────────────────────────────────────────────────────────────

def _from_match(hit: PIIMatch | PHIMatch | FinancialMatch) -> DataMatch:
    """Unified converter — PIIMatch, PHIMatch, FinancialMatch share the same fields."""
    return DataMatch(
        data_type=hit.data_type,
        redacted_value=hit.redacted_value,
        offset=hit.offset,
        length=hit.length,
        confidence=hit.confidence,
        context=hit.context,
    )

# Mapping from secret severity → classifier data_type.
_SECRET_SEVERITY_TYPE = {"critical": "SECRET_KEY", "high": "API_KEY"}

def _from_secret_hit(hit: SecretHit) -> DataMatch:
    """Convert a secret-scanner hit to a unified DataMatch."""
    data_type = _SECRET_SEVERITY_TYPE.get(hit.severity, "CREDENTIAL")
    return DataMatch(
        data_type=data_type,
        redacted_value=hit.redacted_preview,
        offset=hit.position,
        length=hit.length,
        confidence=0.90,
        context=f"secret: {hit.pattern_name} ({hit.provider})",
    )
