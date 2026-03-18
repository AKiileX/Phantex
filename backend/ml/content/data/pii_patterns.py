# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — PII Patterns (JB4).

Regex-based detection of Personally Identifiable Information:
- Social Security Numbers (XXX-XX-XXXX with format validation)
- Email addresses
- Phone numbers (US + international formats)
- Physical addresses (US street + zip)
- Dates of birth (multiple formats)
- Passport numbers (US)
- Driver's license numbers (generic)

All regex patterns are pre-compiled and ReDoS-tested.
Matched values are returned **redacted** — the raw PII is never stored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── SSN ──────────────────────────────────────────────────────────────────────

# XXX-XX-XXXX — rejects known-invalid area numbers (000, 666, 900-999)
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)([0-8]\d{2})-(?!00)(\d{2})-(?!0000)(\d{4})\b")

# ── Email ────────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# ── Phone ────────────────────────────────────────────────────────────────────

# US formats: (555) 123-4567, 555-123-4567, +1-555-123-4567, +15551234567
_PHONE_US_RE = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

# International: +XX XXXXXXXXX (7-15 digits after country code)
_PHONE_INTL_RE = re.compile(r"\+[1-9]\d{0,2}[-.\s]?\d{4,14}\b")

# ── Physical Address (US) ────────────────────────────────────────────────────

_ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9.\s]{2,40}\b(?:St|Street|Ave|Avenue|Blvd|Boulevard|"
    r"Dr|Drive|Rd|Road|Ln|Lane|Way|Ct|Court|Pl|Place|Pkwy|Parkway|Cir|Circle)\b",
    re.I,
)

# US ZIP codes (5 or 5+4)
_ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")

# ── Date of Birth ────────────────────────────────────────────────────────────

# MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD (ISO), DD/MM/YYYY
_DOB_RE = re.compile(
    r"\b(?:"
    r"(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}"
    r"|(?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])"
    r")\b"
)

# Context keywords that indicate the date IS a DOB (not just any date)
_DOB_CONTEXT = re.compile(
    r"(?:date\s+of\s+birth|DOB|born\s+on|birthday|birth\s*date|d\.o\.b)",
    re.I,
)

# ── Passport (US) ───────────────────────────────────────────────────────────

_PASSPORT_US_RE = re.compile(
    r"\b[A-Z]\d{8}\b"  # Letter + 8 digits
)

_PASSPORT_CONTEXT = re.compile(
    r"(?:passport|travel\s+document|passport\s+number|passport\s*#)",
    re.I,
)

# ── Driver's License (generic US) ───────────────────────────────────────────

_DL_RE = re.compile(r"\b[A-Z]\d{7,12}\b")

_DL_CONTEXT = re.compile(
    r"(?:driver'?s?\s+licen[sc]e|DL\s*#|DL\s+number|license\s+number)",
    re.I,
)

# ── Dataclass ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PIIMatch:
    """A PII detection with the value pre-redacted."""

    data_type: str  # "SSN", "EMAIL", "PHONE", "ADDRESS", "DOB", "PASSPORT", "DRIVERS_LICENSE"
    redacted_value: str  # e.g. "***-**-1234"
    offset: int
    length: int
    confidence: float  # 0.0–1.0
    context: str = ""  # e.g. "format validated" or "near keyword 'patient'"

# ── Public API ───────────────────────────────────────────────────────────────

def scan_for_pii(text: str) -> list[PIIMatch]:
    """Scan *text* for PII and return redacted matches.

    Returns a list sorted by offset.
    """
    hits: list[PIIMatch] = []

    # SSN
    for m in _SSN_RE.finditer(text):
        last4 = m.group(3)
        hits.append(
            PIIMatch(
                data_type="SSN",
                redacted_value=f"***-**-{last4}",
                offset=m.start(),
                length=len(m.group(0)),
                confidence=0.95,
                context="SSN format validated (area/group/serial)",
            )
        )

    # Email
    for m in _EMAIL_RE.finditer(text):
        email = m.group(0)
        parts = email.split("@")
        domain = parts[1] if len(parts) == 2 else "***"
        hits.append(
            PIIMatch(
                data_type="EMAIL",
                redacted_value=f"***@{domain}",
                offset=m.start(),
                length=len(email),
                confidence=0.99,
                context="standard email format",
            )
        )

    # Phone
    for m in _PHONE_US_RE.finditer(text):
        raw = m.group(0)
        # Filter out short matches that are just zip codes or random digits
        digits = re.sub(r"\D", "", raw)
        if len(digits) >= 10:
            last4 = digits[-4:]
            hits.append(
                PIIMatch(
                    data_type="PHONE",
                    redacted_value=f"***-***-{last4}",
                    offset=m.start(),
                    length=len(raw),
                    confidence=0.90,
                    context="US phone format",
                )
            )

    for m in _PHONE_INTL_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if len(digits) >= 10:
            last4 = digits[-4:]
            # Avoid double-counting if already matched by US pattern
            if not any(h.offset == m.start() and h.data_type == "PHONE" for h in hits):
                hits.append(
                    PIIMatch(
                        data_type="PHONE",
                        redacted_value=f"+**-***-{last4}",
                        offset=m.start(),
                        length=len(raw),
                        confidence=0.85,
                        context="international phone format",
                    )
                )

    # Address (US street address)
    for m in _ADDRESS_RE.finditer(text):
        raw = m.group(0)
        # Redact: keep only street suffix
        parts = raw.rsplit(" ", 1)
        suffix = parts[-1] if len(parts) > 1 else "***"
        hits.append(
            PIIMatch(
                data_type="ADDRESS",
                redacted_value=f"*** {suffix}",
                offset=m.start(),
                length=len(raw),
                confidence=0.80,
                context="US street address pattern",
            )
        )

    # Date of Birth (only if near DOB context)
    has_dob_context = bool(_DOB_CONTEXT.search(text))
    if has_dob_context:
        for m in _DOB_RE.finditer(text):
            # Check proximity to a DOB keyword (within 60 chars)
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            window = text[start:end]
            if _DOB_CONTEXT.search(window):
                hits.append(
                    PIIMatch(
                        data_type="DOB",
                        redacted_value="**/**/****",
                        offset=m.start(),
                        length=len(m.group(0)),
                        confidence=0.85,
                        context="date near DOB keyword",
                    )
                )

    # Passport (US — only near passport context)
    has_passport_context = bool(_PASSPORT_CONTEXT.search(text))
    if has_passport_context:
        for m in _PASSPORT_US_RE.finditer(text):
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            window = text[start:end]
            if _PASSPORT_CONTEXT.search(window):
                raw = m.group(0)
                hits.append(
                    PIIMatch(
                        data_type="PASSPORT",
                        redacted_value=f"{raw[0]}***{raw[-2:]}",
                        offset=m.start(),
                        length=len(raw),
                        confidence=0.80,
                        context="passport number near keyword",
                    )
                )

    # Driver's License (only near DL context)
    has_dl_context = bool(_DL_CONTEXT.search(text))
    if has_dl_context:
        for m in _DL_RE.finditer(text):
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            window = text[start:end]
            if _DL_CONTEXT.search(window):
                raw = m.group(0)
                hits.append(
                    PIIMatch(
                        data_type="DRIVERS_LICENSE",
                        redacted_value=f"{raw[0]}***{raw[-2:]}",
                        offset=m.start(),
                        length=len(raw),
                        confidence=0.75,
                        context="DL number near keyword",
                    )
                )

    hits.sort(key=lambda h: h.offset)
    return hits
