# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Encoding / Exfiltration Detector (JB3).

Detect encoded exfiltration in agent output: base64 blobs, hex-encoded
data, suspicious JSON-in-string nesting, and high-entropy segments that
suggest the agent is smuggling data out.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class EncodingHit:
    """A detected encoding anomaly."""

    pattern_name: str
    position: int
    length: int
    entropy: float  # Shannon entropy of the segment
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

# ── Detection patterns ───────────────────────────────────────────────────────

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
_HEX_BLOB = re.compile(r"(?<![a-zA-Z0-9])[0-9a-fA-F]{64,}(?![a-zA-Z0-9])")
_NESTED_JSON = re.compile(r'"[^"]*\\?"[^"]*":\s*"[^"]*\\?"[^"]*"')  # JSON-in-string

class EncodingDetector:
    """Detect encoded exfiltration patterns in text.

    Parameters
    ----------
    min_entropy:
        Shannon entropy threshold (bits/char) above which a segment
        is considered suspicious (default 4.5).
    min_blob_length:
        Minimum length for base64/hex blobs to trigger (default 100).
    """

    def __init__(
        self,
        min_entropy: float = 4.5,
        min_blob_length: int = 100,
    ) -> None:
        self._min_entropy = min_entropy
        self._min_blob_length = min_blob_length

    def scan(self, text: str) -> list[EncodingHit]:
        """Scan *text* for encoding anomalies."""
        hits: list[EncodingHit] = []

        # Base64 blobs
        for m in _BASE64_BLOB.finditer(text):
            segment = m.group(0)
            ent = self._shannon_entropy(segment)
            if ent >= self._min_entropy and len(segment) >= self._min_blob_length:
                hits.append(
                    EncodingHit(
                        pattern_name="base64_blob",
                        position=m.start(),
                        length=len(segment),
                        entropy=round(ent, 3),
                        description=f"Base64 blob ({len(segment)} chars, entropy {ent:.2f})",
                    ),
                )

        # Hex blobs — entropy check uses lower threshold (hex alphabet max ≈ 4.0)
        for m in _HEX_BLOB.finditer(text):
            segment = m.group(0)
            ent = self._shannon_entropy(segment)
            if len(segment) >= self._min_blob_length and ent >= self._min_entropy * 0.75:
                hits.append(
                    EncodingHit(
                        pattern_name="hex_blob",
                        position=m.start(),
                        length=len(segment),
                        entropy=round(ent, 3),
                        description=f"Hex blob ({len(segment)} chars, entropy {ent:.2f})",
                    ),
                )

        # Nested JSON (potential structured exfiltration)
        for m in _NESTED_JSON.finditer(text):
            segment = m.group(0)
            if len(segment) > 50:
                ent = self._shannon_entropy(segment)
                hits.append(
                    EncodingHit(
                        pattern_name="nested_json",
                        position=m.start(),
                        length=len(segment),
                        entropy=round(ent, 3),
                        description="Suspicious nested JSON-in-string pattern",
                    ),
                )

        return hits

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Compute Shannon entropy in bits per character."""
        if not text:
            return 0.0
        freq = Counter(text)
        total = len(text)
        return -sum((count / total) * math.log2(count / total) for count in freq.values())
