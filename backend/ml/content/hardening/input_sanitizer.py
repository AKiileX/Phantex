# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Input Sanitizer (JB6 Hardening).

Pre-processes raw content *before* any classifier / scanner to:
  1. Enforce length caps (default 32 KB)
  2. Unicode NFC normalization
  3. Null-byte removal
  4. Control-character stripping (keep \\n, \\r, \\t)
  5. Optional timing jitter (anti-timing-oracle, ±1 ms)

All operations are O(n) or better — no regex in the hot path.
"""

from __future__ import annotations

import random
import time
import unicodedata

# Hard maximum — protects against OOM / ReDoS amplification
MAX_CONTENT_BYTES: int = 32 * 1024  # 32 KB

# Characters we keep (printable + common whitespace)
_KEEP_CONTROL = frozenset({"\n", "\r", "\t"})

def sanitize(
    content: str,
    *,
    max_bytes: int = MAX_CONTENT_BYTES,
    add_jitter: bool = False,
    jitter_ms: float = 1.0,
) -> str:
    """Return sanitized content, safe for classification.

    Parameters
    ----------
    content:
        Raw input string.
    max_bytes:
        Maximum byte length after encoding to UTF-8.
    add_jitter:
        If ``True``, sleep 0–*jitter_ms* ms to defeat timing oracles.
    jitter_ms:
        Maximum jitter in milliseconds (default 1.0).  Sourced from
        ``ContentAnalysisConfig.timing_jitter_ms``.
    """
    if not content:
        return ""

    # 1. Truncate to byte limit (UTF-8 safe)
    encoded = content.encode("utf-8", errors="replace")[:max_bytes]
    text = encoded.decode("utf-8", errors="replace")

    # 2. NFC normalize (canonical decomposition → composition)
    text = unicodedata.normalize("NFC", text)

    # 3. Null-byte removal
    text = text.replace("\x00", "")

    # 4. Strip non-printable control characters (keep \n \r \t)
    text = _strip_control(text)

    # 5. Optional timing jitter
    if add_jitter:
        time.sleep(random.uniform(0, max(0.0, jitter_ms) / 1000.0))

    return text

def _strip_control(text: str) -> str:
    """Remove Unicode control characters except newline / tab / CR."""
    out: list[str] = []
    for ch in text:
        if ch in _KEEP_CONTROL or ch.isprintable():
            out.append(ch)
    return "".join(out)

def is_oversized(content: str, max_bytes: int = MAX_CONTENT_BYTES) -> bool:
    """Return True if content exceeds the byte limit."""
    return len(content.encode("utf-8", errors="replace")) > max_bytes
