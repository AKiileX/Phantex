# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Sensitivity Scorer (JB4).

Maps detected data types to sensitivity levels and compliance tags.

Sensitivity levels:  CRITICAL > HIGH > MEDIUM > LOW > NONE
Compliance tags:     GDPR, CCPA, HIPAA, PCI-DSS, SOX, EU_AI_ACT
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

class SensitivityLevel(enum.Enum):
    """Data sensitivity from NONE to CRITICAL."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Ordering: CRITICAL > HIGH > MEDIUM > LOW > NONE
_LEVEL_ORDER = {
    SensitivityLevel.NONE: 0,
    SensitivityLevel.LOW: 1,
    SensitivityLevel.MEDIUM: 2,
    SensitivityLevel.HIGH: 3,
    SensitivityLevel.CRITICAL: 4,
}

# ── Data-type → sensitivity + compliance mapping ────────────────────────────

_DATA_TYPE_MAP: dict[str, tuple[SensitivityLevel, tuple[str, ...]]] = {
    # PII
    "SSN": (SensitivityLevel.CRITICAL, ("GDPR", "CCPA")),
    "EMAIL": (SensitivityLevel.MEDIUM, ("GDPR", "CCPA")),
    "PHONE": (SensitivityLevel.MEDIUM, ("GDPR", "CCPA")),
    "ADDRESS": (SensitivityLevel.HIGH, ("GDPR", "CCPA")),
    "DOB": (SensitivityLevel.HIGH, ("GDPR", "CCPA")),
    "PASSPORT": (SensitivityLevel.CRITICAL, ("GDPR", "CCPA")),
    "DRIVERS_LICENSE": (SensitivityLevel.HIGH, ("GDPR", "CCPA")),
    # PHI
    "MRN": (SensitivityLevel.CRITICAL, ("HIPAA",)),
    "ICD10": (SensitivityLevel.HIGH, ("HIPAA",)),
    "DRUG": (SensitivityLevel.HIGH, ("HIPAA",)),
    "LAB_RESULT": (SensitivityLevel.HIGH, ("HIPAA",)),
    "PATIENT_ID": (SensitivityLevel.CRITICAL, ("HIPAA",)),
    # Financial
    "CREDIT_CARD": (SensitivityLevel.CRITICAL, ("PCI-DSS",)),
    "BANK_ACCOUNT": (SensitivityLevel.CRITICAL, ("PCI-DSS",)),
    "ROUTING_NUMBER": (SensitivityLevel.HIGH, ("PCI-DSS",)),
    "IBAN": (SensitivityLevel.HIGH, ("PCI-DSS",)),
    "SWIFT": (SensitivityLevel.MEDIUM, ("PCI-DSS",)),
    "CRYPTO_BTC": (SensitivityLevel.HIGH, ()),
    "CRYPTO_ETH": (SensitivityLevel.HIGH, ()),
    # Credentials (AO2)
    "API_KEY": (SensitivityLevel.CRITICAL, ("SOX",)),
    "SECRET_KEY": (SensitivityLevel.CRITICAL, ("SOX",)),
    "PRIVATE_KEY": (SensitivityLevel.CRITICAL, ("SOX",)),
    "PASSWORD": (SensitivityLevel.CRITICAL, ("SOX",)),
    "TOKEN": (SensitivityLevel.HIGH, ("SOX",)),
    "CREDENTIAL": (SensitivityLevel.CRITICAL, ("SOX",)),
}

@dataclass(frozen=True)
class SensitivityResult:
    """Aggregated sensitivity assessment for a piece of content."""

    level: SensitivityLevel
    compliance_tags: tuple[str, ...]
    data_labels: tuple[str, ...]  # Unique category labels found, e.g. ("PII", "FINANCIAL")

# ── Category helpers ─────────────────────────────────────────────────────────

_PII_TYPES = frozenset({"SSN", "EMAIL", "PHONE", "ADDRESS", "DOB", "PASSPORT", "DRIVERS_LICENSE"})
_PHI_TYPES = frozenset({"MRN", "ICD10", "DRUG", "LAB_RESULT", "PATIENT_ID"})
_FIN_TYPES = frozenset({"CREDIT_CARD", "BANK_ACCOUNT", "ROUTING_NUMBER", "IBAN", "SWIFT", "CRYPTO_BTC", "CRYPTO_ETH"})
_CRED_TYPES = frozenset({"API_KEY", "SECRET_KEY", "PRIVATE_KEY", "PASSWORD", "TOKEN", "CREDENTIAL"})

def classify_sensitivity(data_types: list[str]) -> SensitivityResult:
    """Compute aggregate sensitivity from a list of detected data_type strings.

    Parameters
    ----------
    data_types:
        e.g. ``["SSN", "EMAIL", "CREDIT_CARD"]``

    Returns
    -------
    SensitivityResult with the worst-case sensitivity, merged compliance
    tags, and category labels.
    """
    if not data_types:
        return SensitivityResult(
            level=SensitivityLevel.NONE,
            compliance_tags=(),
            data_labels=(),
        )

    max_level = SensitivityLevel.NONE
    tags: set[str] = set()
    labels: set[str] = set()

    for dt in data_types:
        entry = _DATA_TYPE_MAP.get(dt)
        if entry is None:
            continue
        level, ctags = entry
        if _LEVEL_ORDER[level] > _LEVEL_ORDER[max_level]:
            max_level = level
        tags.update(ctags)

        # Determine category label
        if dt in _PII_TYPES:
            labels.add("PII")
        if dt in _PHI_TYPES:
            labels.add("PHI")
        if dt in _FIN_TYPES:
            labels.add("FINANCIAL")
        if dt in _CRED_TYPES:
            labels.add("CREDENTIAL")

    return SensitivityResult(
        level=max_level,
        compliance_tags=tuple(sorted(tags)),
        data_labels=tuple(sorted(labels)),
    )
