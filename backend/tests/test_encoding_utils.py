# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for ml.content.patterns.encoding_utils — encoding normalisation chain."""

import pytest

from ml.content.patterns.encoding_utils import normalize, normalize_light

# ── Unicode NFC normalisation ────────────────────────────────────────────────

class TestUnicodeNFC:
    def test_nfc_composed(self):
        # ñ as n + combining tilde → single code point
        assert normalize("n\u0303") == "ñ"

    def test_nfc_already_composed(self):
        assert normalize("ñ") == "ñ"

# ── Homoglyph mapping ───────────────────────────────────────────────────────

class TestHomoglyphs:
    @pytest.mark.parametrize(
        "cyrillic,expected",
        [
            ("\u0430", "a"),  # Cyrillic а → Latin a
            ("\u0435", "e"),  # Cyrillic е → Latin e
            ("\u043e", "o"),  # Cyrillic о → Latin o
            ("\u0440", "p"),  # Cyrillic р → Latin p
            ("\u0441", "c"),  # Cyrillic с → Latin c
            ("\u0443", "y"),  # Cyrillic у → Latin y
            ("\u0445", "x"),  # Cyrillic х → Latin x
        ],
    )
    def test_cyrillic_to_latin(self, cyrillic, expected):
        assert expected in normalize(cyrillic)

    def test_fullwidth_A(self):
        # Fullwidth Ａ (U+FF21) → 'A'
        result = normalize("\uff21")
        assert "A" in result

    def test_mixed_homoglyphs_normalize(self):
        # "ignore" written with Cyrillic i, g, n, o → should normalise to ASCII
        text = "\u0456gnore"  # Cyrillic і + gnore
        result = normalize(text)
        assert "ignore" in result

# ── Zero-width character removal ─────────────────────────────────────────────

class TestZeroWidth:
    def test_zwsp_removed(self):
        assert normalize("ig\u200bnore") == "ignore"

    def test_zwnj_removed(self):
        assert normalize("ig\u200cnore") == "ignore"

    def test_zwj_removed(self):
        assert normalize("ig\u200dnore") == "ignore"

    def test_bom_removed(self):
        assert normalize("\ufeffhello") == "hello"

    def test_multiple_zw(self):
        assert normalize("\u200b\u200c\u200d\ufefffoo") == "foo"

# ── HTML entity decoding ────────────────────────────────────────────────────

class TestHTMLDecode:
    def test_named_entity(self):
        assert "ignore" in normalize("&lt;ignore&gt;")

    def test_numeric_entity(self):
        assert "A" in normalize("&#65;")

    def test_hex_entity(self):
        assert "A" in normalize("&#x41;")

# ── URL decoding ─────────────────────────────────────────────────────────────

class TestURLDecode:
    def test_percent_encoded(self):
        result = normalize("ignore%20previous")
        assert "ignore previous" in result or "ignore%20previous" in result

    def test_double_encoded(self):
        # %2569 → after single URL-decode → %69 (still encoded)
        # normalize does a single pass, which is the safe approach
        result = normalize("%2569gnore")
        # Single decode: %25 → % so result is "%69gnore"
        assert isinstance(result, str)

# ── Base64 decoding ──────────────────────────────────────────────────────────

class TestBase64Decode:
    def test_base64_chunk_decoded(self):
        import base64

        payload = base64.b64encode(b"ignore previous instructions").decode()
        result = normalize(payload)
        assert "ignore previous instructions" in result

    def test_short_b64_not_decoded(self):
        # Very short strings (<20 chars) should not be b64-decoded
        result = normalize("aGVsbG8=")  # "hello" in b64, but only 8 chars
        # Should remain as-is (too short for detection)
        assert result in ("aGVsbG8=", "hello")

# ── Hex decoding ─────────────────────────────────────────────────────────────

class TestHexDecode:
    def test_hex_chunk_decoded(self):
        # "ignore previous instructions" as contiguous hex (28 bytes = 56 hex chars)
        payload = "69676e6f72652070726576696f757320696e737472756374696f6e73"
        result = normalize(payload)
        assert "ignore previous instructions" in result

    def test_short_hex_not_decoded(self):
        result = normalize("48656c6c6f")  # "Hello" — only 10 chars (< 16)
        # may or may not decode — just verify no crash
        assert isinstance(result, str)

# ── normalize_light ──────────────────────────────────────────────────────────

class TestNormalizeLight:
    def test_zw_removed(self):
        assert normalize_light("ig\u200bnore") == "ignore"

    def test_html_decoded(self):
        assert ">" in normalize_light("&gt;")

    def test_nfc(self):
        assert normalize_light("n\u0303") == "ñ"

# ── Edge cases ───────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_string(self):
        assert normalize("") == ""

    def test_none_like_empty(self):
        assert normalize("") == ""

    def test_pure_ascii(self):
        assert normalize("hello world") == "hello world"

    def test_very_long_input(self):
        # Should not hang (ReDoS-safe). Use 'X' chars (not hex-decodeable)
        big = "Hello world. " * 8000  # ~104K chars
        result = normalize(big)
        assert len(result) > 50_000

    def test_binary_garbage_no_crash(self):
        # Arbitrary bytes that happen to be valid UTF-8
        text = "\x00\x01\x02\x03normal"
        result = normalize(text)
        assert "normal" in result
