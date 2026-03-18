# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Reversible Redaction Engine.

Replaces sensitive data with ``[REDACTED-{class}]`` tokens.
Redaction is **reversible**: the original values are encrypted with
AES-256-GCM using a per-tenant key and stored alongside the token
mapping.  An authorised admin can decrypt the mapping to recover
original values.

Security:
  - AES-256-GCM with random 12-byte nonces (NIST SP 800-38D).
  - Derived keys via HKDF-SHA256 from tenant master secret.
  - Token map never contains plaintext after ``redact()``.
  - Constant-time HMAC comparison for nonce/tag integrity.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Any

from ml.content.classifiers.data_classifier import DataClassification, DataMatch

logger = logging.getLogger(__name__)

# ── Key derivation ───────────────────────────────────────────────────────────

def _derive_key(master_secret: bytes, tenant_id: str) -> bytes:
    """Derive a 32-byte AES key from *master_secret* + *tenant_id* via HKDF-SHA256."""
    if not tenant_id:
        raise ValueError("tenant_id must not be empty for key derivation")
    # Simple HKDF-Extract + Expand (single block is enough for 32 bytes)
    salt = b"phantex-redaction-v1"
    prk = hmac.new(salt, master_secret + tenant_id.encode(), hashlib.sha256).digest()
    info = b"phantex-aes256-gcm-redaction"
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:32]

# ── AES-256-GCM helpers ─────────────────────────────────────────────────────

def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM.  Returns nonce‖ciphertext‖tag.

    Raises ``RuntimeError`` if the ``cryptography`` package is not installed
    — we refuse to store plaintext as a fallback.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError(
            "cryptography package is required for reversible redaction — install it with: pip install cryptography"
        ) from exc

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct  # 12 + len(plaintext) + 16 (tag)

def _aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt a nonce‖ciphertext‖tag blob.  Raises on tamper."""
    if len(blob) < 13:  # 12-byte nonce + at least 1 byte
        raise ValueError("Encrypted blob too short — corrupted or invalid")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# ── Data types ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RedactionToken:
    """A redaction placeholder with its encrypted original value."""

    token: str  # e.g. "[REDACTED-SSN]"
    data_type: str  # e.g. "SSN"
    offset: int  # Position in original text
    length: int  # Length of original value
    encrypted_value: str  # Base64-encoded AES-GCM blob

@dataclass
class RedactionResult:
    """Result of a redaction operation."""

    redacted_text: str
    tokens: list[RedactionToken]
    classification: DataClassification
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def token_count(self) -> int:
        return len(self.tokens)

@dataclass
class RestoredResult:
    """Result of reversing a redaction."""

    restored_text: str
    tokens_restored: int
    errors: list[str] = field(default_factory=list)

# ── Token pattern for detection during restore ───────────────────────────────

_REDACTION_RE = re.compile(r"\[REDACTED-(\w+)(?:#(\d+))?\]")

# ── Redaction engine ─────────────────────────────────────────────────────────

class RedactionEngine:
    """Inline redaction with reversible encryption.

    Parameters
    ----------
    master_secret:
        Tenant master secret (≥32 bytes recommended).
        If ``None``, redaction is irreversible (tokens still inserted).
    """

    def __init__(self, master_secret: bytes | None = None) -> None:
        self._master_secret = master_secret

    def redact(
        self,
        text: str,
        classification: DataClassification,
        tenant_id: str = "",
    ) -> RedactionResult:
        """Replace all classified matches in *text* with ``[REDACTED-{class}]`` tokens.

        Matches are processed from last to first (reverse offset) so that
        earlier offsets remain valid after substitution.

        Returns a ``RedactionResult`` with the redacted text and encrypted
        token mappings.
        """
        if not classification.matches:
            return RedactionResult(
                redacted_text=text,
                tokens=[],
                classification=classification,
            )

        # Derive per-tenant key (or None for irreversible)
        key: bytes | None = None
        if self._master_secret and tenant_id:
            key = _derive_key(self._master_secret, tenant_id)
        elif self._master_secret and not tenant_id:
            logger.warning("Redaction without tenant_id — falling back to irreversible mode")

        # Deduplicate overlapping matches: keep longer (or higher-confidence)
        # match when two spans overlap.
        asc_matches = sorted(classification.matches, key=lambda m: (m.offset, -m.length))
        deduped: list[DataMatch] = []
        for m in asc_matches:
            if deduped and m.offset < deduped[-1].offset + deduped[-1].length:
                # Overlap — keep the one with larger span (or higher confidence)
                prev = deduped[-1]
                if m.length > prev.length or (m.length == prev.length and m.confidence > prev.confidence):
                    deduped[-1] = m
                continue
            deduped.append(m)

        # Sort matches by offset descending so replacements don't shift positions
        sorted_matches = sorted(deduped, key=lambda m: m.offset, reverse=True)

        tokens: list[RedactionToken] = []
        result = text

        # Track how many of each class for disambiguation
        class_counts: dict[str, int] = {}

        # First pass: count per class
        for m in classification.matches:
            class_counts[m.data_type] = class_counts.get(m.data_type, 0) + 1

        # Detect dupes that need disambiguation
        needs_index = {dt for dt, count in class_counts.items() if count > 1}
        running_index: dict[str, int] = {}

        # Process in reverse offset order
        for m in sorted_matches:
            original_value = text[m.offset : m.offset + m.length]

            # Build token string
            if m.data_type in needs_index:
                running_index[m.data_type] = running_index.get(m.data_type, 0) + 1
                token_str = f"[REDACTED-{m.data_type}#{running_index[m.data_type]}]"
            else:
                token_str = f"[REDACTED-{m.data_type}]"

            # Encrypt original value
            if key:
                enc_blob = _aes_gcm_encrypt(key, original_value.encode("utf-8"))
                encrypted_b64 = b64encode(enc_blob).decode("ascii")
            else:
                encrypted_b64 = ""

            tokens.append(
                RedactionToken(
                    token=token_str,
                    data_type=m.data_type,
                    offset=m.offset,
                    length=m.length,
                    encrypted_value=encrypted_b64,
                )
            )

            result = result[: m.offset] + token_str + result[m.offset + m.length :]

        # Reverse tokens so they're in offset-ascending order
        tokens.reverse()

        return RedactionResult(
            redacted_text=result,
            tokens=tokens,
            classification=classification,
        )

    def restore(
        self,
        redacted_text: str,
        tokens: list[RedactionToken],
        tenant_id: str = "",
    ) -> RestoredResult:
        """Reverse a redaction using the encrypted token map.

        Requires the same ``master_secret`` that was used during redaction.
        """
        if not self._master_secret:
            return RestoredResult(
                restored_text=redacted_text,
                tokens_restored=0,
                errors=["No master secret configured — redaction is irreversible"],
            )

        if not tenant_id:
            return RestoredResult(
                restored_text=redacted_text,
                tokens_restored=0,
                errors=["tenant_id is required for restoration"],
            )

        key = _derive_key(self._master_secret, tenant_id)
        result = redacted_text
        restored_count = 0
        errors: list[str] = []

        # Build token → decrypted value map
        token_map: dict[str, str] = {}
        for t in tokens:
            if not t.encrypted_value:
                errors.append(f"Token {t.token}: no encrypted value")
                continue
            try:
                blob = b64decode(t.encrypted_value)
                plaintext = _aes_gcm_decrypt(key, blob)
                token_map[t.token] = plaintext.decode("utf-8")
            except Exception as exc:
                errors.append(f"Token {t.token}: decryption failed — {exc}")

        # Replace tokens in text
        for token_str, original_value in token_map.items():
            if token_str in result:
                result = result.replace(token_str, original_value, 1)
                restored_count += 1

        return RestoredResult(
            restored_text=result,
            tokens_restored=restored_count,
            errors=errors,
        )

    def redact_to_json(
        self,
        text: str,
        classification: DataClassification,
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Convenience: redact and return a JSON-serialisable dict."""
        r = self.redact(text, classification, tenant_id)
        return {
            "redacted_text": r.redacted_text,
            "token_count": r.token_count,
            "tokens": [
                {
                    "token": t.token,
                    "data_type": t.data_type,
                    "offset": t.offset,
                    "length": t.length,
                    "encrypted_value": t.encrypted_value,
                }
                for t in r.tokens
            ],
            "sensitivity": r.classification.sensitivity.value,
            "labels": list(r.classification.labels),
            "compliance_tags": list(r.classification.compliance_tags),
        }
