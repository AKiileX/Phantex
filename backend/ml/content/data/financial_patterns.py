# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Financial Patterns (JB4).

Regex-based detection of financial data:
- Credit card numbers (with Luhn validation)
- Bank account + routing numbers (US)
- IBAN (International Bank Account Number)
- SWIFT/BIC codes
- Cryptocurrency addresses (BTC, ETH)

All regex patterns are pre-compiled.  Matched values are returned
**redacted** — the raw financial data is never stored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class FinancialMatch:
    """A financial data detection with the value pre-redacted."""

    data_type: str  # "CREDIT_CARD", "BANK_ACCOUNT", "ROUTING_NUMBER", "IBAN", "SWIFT", "CRYPTO"
    redacted_value: str
    offset: int
    length: int
    confidence: float
    context: str = ""

# ── Credit Card ──────────────────────────────────────────────────────────────

# 13-19 digit numbers, optionally separated by spaces or dashes.
# Uses negative lookarounds so \b doesn't fail on trailing space/hyphen.
_CC_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

# Major card prefixes for additional confidence
_CARD_PREFIXES = {
    "4": "Visa",
    "5": "Mastercard",
    "34": "Amex",
    "37": "Amex",
    "6011": "Discover",
    "65": "Discover",
    "36": "Diners Club",
    "38": "Diners Club",
    "35": "JCB",
}

def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm.

    Returns True for valid card numbers, False for random digit sequences.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn: double every second digit from right
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

# ── Bank Account / Routing ───────────────────────────────────────────────────

# US routing number: 9 digits, often near "routing" keyword
_ROUTING_RE = re.compile(
    r"(?:routing\s*(?:number|#|no)?|ABA)[\s:=#]*(\d{9})\b",
    re.I,
)

# Bank account: 8-17 digits near "account" keyword
_BANK_ACCT_RE = re.compile(
    r"(?:(?:bank\s+)?account\s*(?:number|#|no)?|acct\s*#?)[\s:=#]*(\d{8,17})\b",
    re.I,
)

# ── IBAN ─────────────────────────────────────────────────────────────────────

# IBAN: 2 letter country + 2 check digits + up to 30 alphanum
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b")

_IBAN_CONTEXT = re.compile(
    r"(?:IBAN|international\s+bank|bank\s+account|wire\s+transfer|SEPA)",
    re.I,
)

# ── SWIFT / BIC ──────────────────────────────────────────────────────────────

# SWIFT/BIC: 8 or 11 characters (AAAA BB CC [DDD])
_SWIFT_RE = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")

_SWIFT_CONTEXT = re.compile(
    r"(?:SWIFT|BIC|bank\s+identifier|wire\s+transfer|correspondent\s+bank)",
    re.I,
)

# ── Cryptocurrency ───────────────────────────────────────────────────────────

# Bitcoin (legacy P2PKH, P2SH, and bech32)
_BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{39,59})\b")

# Ethereum (0x + 40 hex chars)
_ETH_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")

# ── Public API ───────────────────────────────────────────────────────────────

def scan_for_financial(text: str) -> list[FinancialMatch]:
    """Scan *text* for financial data and return redacted matches.

    Credit card numbers are validated using the Luhn algorithm —
    random 16-digit sequences are NOT flagged.
    Returns a list sorted by offset.
    """
    hits: list[FinancialMatch] = []

    # Credit cards (with Luhn validation)
    for m in _CC_RE.finditer(text):
        raw = m.group(0)
        digits_only = re.sub(r"\D", "", raw)
        if _luhn_check(digits_only):
            last4 = digits_only[-4:]
            # Determine card brand
            brand = _detect_brand(digits_only)
            hits.append(
                FinancialMatch(
                    data_type="CREDIT_CARD",
                    redacted_value=f"****-****-****-{last4}",
                    offset=m.start(),
                    length=len(raw),
                    confidence=0.99,
                    context=f"Luhn check passed{f', {brand}' if brand else ''}",
                )
            )

    # Routing numbers
    for m in _ROUTING_RE.finditer(text):
        routing = m.group(1)
        hits.append(
            FinancialMatch(
                data_type="ROUTING_NUMBER",
                redacted_value=f"***{routing[-3:]}",
                offset=m.start(),
                length=len(m.group(0)),
                confidence=0.85,
                context="US routing number near keyword",
            )
        )

    # Bank accounts
    for m in _BANK_ACCT_RE.finditer(text):
        acct = m.group(1)
        hits.append(
            FinancialMatch(
                data_type="BANK_ACCOUNT",
                redacted_value=f"***{acct[-4:]}",
                offset=m.start(),
                length=len(m.group(0)),
                confidence=0.85,
                context="bank account near keyword",
            )
        )

    # IBAN (with context)
    has_iban_context = bool(_IBAN_CONTEXT.search(text))
    if has_iban_context:
        for m in _IBAN_RE.finditer(text):
            iban = m.group(0)
            # Basic IBAN length validation: must be 15+ chars
            if len(iban) >= 15:
                start = max(0, m.start() - 60)
                end = min(len(text), m.end() + 60)
                window = text[start:end]
                if _IBAN_CONTEXT.search(window):
                    hits.append(
                        FinancialMatch(
                            data_type="IBAN",
                            redacted_value=f"{iban[:4]}***{iban[-4:]}",
                            offset=m.start(),
                            length=len(iban),
                            confidence=0.90,
                            context="IBAN format near banking keyword",
                        )
                    )

    # SWIFT/BIC (with context)
    has_swift_context = bool(_SWIFT_CONTEXT.search(text))
    if has_swift_context:
        for m in _SWIFT_RE.finditer(text):
            swift = m.group(0)
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            window = text[start:end]
            if _SWIFT_CONTEXT.search(window):
                hits.append(
                    FinancialMatch(
                        data_type="SWIFT",
                        redacted_value=f"{swift[:4]}***",
                        offset=m.start(),
                        length=len(swift),
                        confidence=0.85,
                        context="SWIFT/BIC code near banking keyword",
                    )
                )

    # Cryptocurrency
    for m in _BTC_RE.finditer(text):
        addr = m.group(0)
        hits.append(
            FinancialMatch(
                data_type="CRYPTO_BTC",
                redacted_value=f"{addr[:6]}***{addr[-4:]}",
                offset=m.start(),
                length=len(addr),
                confidence=0.90,
                context="Bitcoin address format",
            )
        )

    for m in _ETH_RE.finditer(text):
        addr = m.group(0)
        hits.append(
            FinancialMatch(
                data_type="CRYPTO_ETH",
                redacted_value=f"{addr[:6]}***{addr[-4:]}",
                offset=m.start(),
                length=len(addr),
                confidence=0.90,
                context="Ethereum address format",
            )
        )

    hits.sort(key=lambda h: h.offset)
    return hits

def _detect_brand(digits: str) -> str:
    """Identify card brand from the leading digits."""
    for prefix, brand in sorted(_CARD_PREFIXES.items(), key=lambda x: -len(x[0])):
        if digits.startswith(prefix):
            return brand
    return ""

# Expose Luhn for direct testing
luhn_check = _luhn_check
