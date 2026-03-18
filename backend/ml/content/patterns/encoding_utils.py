# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Encoding Utilities.

Attackers encode injection payloads to bypass regex detection.  This
module normalises content through multiple decode passes so that the
pattern matcher sees the *decoded* payload.

Decode chain (applied in order):
  1. Unicode NFC normalisation + homoglyph mapping
  2. Zero-width character removal
  3. HTML entity decode
  4. URL percent-decode
  5. Base64 detection + decode (sections ≥ 20 chars matching b64 alphabet)
  6. Hex-string decode (0x… or continuous hex ≥ 16 chars)

All operations are safe for arbitrary binary and will never raise.
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
from urllib.parse import unquote

# ── Homoglyph map  (Cyrillic / Greek → Latin) ────────────────────────────────
_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і (Ukrainian)
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0391": "A",  # Greek Α
    "\u0392": "B",  # Greek Β
    "\u0395": "E",  # Greek Ε
    "\u0397": "H",  # Greek Η
    "\u0399": "I",  # Greek Ι
    "\u039a": "K",  # Greek Κ
    "\u039c": "M",  # Greek Μ
    "\u039d": "N",  # Greek Ν
    "\u039f": "O",  # Greek Ο
    "\u03a1": "P",  # Greek Ρ
    "\u03a4": "T",  # Greek Τ
    "\u03a5": "Y",  # Greek Υ
    "\u03a7": "X",  # Greek Χ
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    # Additional Cyrillic / Greek lowercase confusables
    "\u0455": "s",  # Cyrillic ѕ (DZE)
    "\u03bd": "v",  # Greek ν (nu)
    "\u03b7": "n",  # Greek η (eta)
    "\u03c1": "p",  # Greek ρ (rho)
    "\u03c4": "t",  # Cyrillic
    "\uff49": "i",  # Fullwidth ｉ
    "\uff4e": "n",  # Fullwidth ｎ
    "\uff47": "g",  # Fullwidth ｇ
    "\uff4f": "o",  # Fullwidth ｏ
    "\uff52": "r",  # Fullwidth ｒ
    # Fullwidth uppercase Latin (FF21-FF3A → A-Z)
    **{chr(c): chr(c - 0xFF21 + 0x41) for c in range(0xFF21, 0xFF3B)},
    # Fullwidth lowercase Latin (FF41-FF5A → a-z)
    **{chr(c): chr(c - 0xFF41 + 0x61) for c in range(0xFF41, 0xFF5B)},
    "\uff45": "e",  # Fullwidth ｅ
}

# Zero-width chars to strip
_ZERO_WIDTH = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff]",
)

# Base64 chunk: 20+ chars from the b64 alphabet, possibly padded
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Hex chunk: 0x prefix or 16+ contiguous hex chars
_HEX_PREFIX_RE = re.compile(r"0x([0-9a-fA-F]{2,})")
_HEX_LONG_RE = re.compile(r"(?<![a-zA-Z0-9])([0-9a-fA-F]{16,})(?![a-zA-Z0-9])")

# ── Public API ────────────────────────────────────────────────────────────────

def normalize(text: str) -> str:
    """Apply the full decode chain and return normalised text.

    The result is always a valid Python ``str``; binary decode
    failures are silently skipped.
    """
    text = _unicode_normalise(text)
    text = _strip_zero_width(text)
    text = _html_decode(text)
    text = _url_decode(text)
    # Hex decode BEFORE base64: hex chars are a subset of base64 alphabet,
    # so base64 would corrupt hex strings if it ran first.
    text = _hex_decode_sections(text)
    text = _base64_decode_sections(text)
    return text

def normalize_light(text: str) -> str:
    """Quick normalisation: unicode NFC + zero-width + html + homoglyphs.

    Cheaper than full ``normalize()``; suitable for the fast path.
    """
    text = _unicode_normalise(text)
    text = _strip_zero_width(text)
    text = _html_decode(text)
    return text

# ── Internals ─────────────────────────────────────────────────────────────────

def _unicode_normalise(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    return text.translate(str.maketrans(_HOMOGLYPHS))

def _strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH.sub("", text)

def _html_decode(text: str) -> str:
    return html.unescape(text)

def _url_decode(text: str) -> str:
    return unquote(text)

def _base64_decode_sections(text: str) -> str:
    """Detect and inline-decode base64 chunks ≥ 20 chars."""

    def _try_decode(m: re.Match[str]) -> str:
        raw = m.group(0)
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
            # Only substitute if decode produces mostly-printable ASCII
            if sum(c.isprintable() for c in decoded) / max(len(decoded), 1) > 0.7:
                return decoded
        except Exception:
            pass
        return raw

    return _BASE64_RE.sub(_try_decode, text)

def _hex_decode_sections(text: str) -> str:
    """Decode 0x-prefixed or long hex strings."""

    def _decode(m: re.Match[str]) -> str:
        # 0x-prefixed: group(1) has the hex chars; long hex: group(0) is all hex
        hex_str = m.group(1) if m.group(0).startswith("0x") else m.group(0)
        try:
            decoded = bytes.fromhex(hex_str).decode("utf-8", errors="replace")
            if sum(c.isprintable() for c in decoded) / max(len(decoded), 1) > 0.7:
                return decoded
        except Exception:
            pass
        return m.group(0)

    text = _HEX_PREFIX_RE.sub(_decode, text)
    text = _HEX_LONG_RE.sub(
        lambda m: _try_hex(m.group(0)),
        text,
    )
    return text

def _try_hex(raw: str) -> str:
    try:
        decoded = bytes.fromhex(raw).decode("utf-8", errors="replace")
        if sum(c.isprintable() for c in decoded) / max(len(decoded), 1) > 0.7:
            return decoded
    except Exception:
        pass
    return raw
