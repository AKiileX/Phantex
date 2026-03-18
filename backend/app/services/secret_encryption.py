# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Secret Encryption Service (M-1 Hardening).

Encrypts sensitive secrets (OIDC client_secret, API keys, etc.) at rest.

Strategy:
  - When Vault is enabled: uses Vault Transit engine (encrypt/decrypt)
    → private key never leaves Vault, backed by HSM in prod
  - When Vault is disabled (dev): uses Fernet symmetric encryption
    with a key derived from PHANTEX_SECRET_KEY via HKDF

Encrypted values are prefixed with a scheme tag so the correct backend
is chosen automatically on decryption:
  - "vault:v1:..."   → Vault Transit ciphertext
  - "fernet:1:..."   → Fernet-encrypted ciphertext
  - plain text        → legacy unencrypted (migrated on next write)
"""

from __future__ import annotations

import base64
from typing import Any

import structlog

from app.config import get_settings

logger = structlog.get_logger("phantex.services.secret_encryption")

# ── Fernet Fallback (dev mode) ────────────────────────────────────────────────

_fernet_key: bytes | None = None

def _get_fernet_key() -> bytes:
    """Derive a 32-byte Fernet key from PHANTEX_SECRET_KEY using HKDF."""
    global _fernet_key
    if _fernet_key is not None:
        return _fernet_key

    settings = get_settings()
    secret = settings.jwt_secret.encode("utf-8")

    # HKDF-SHA256 to derive a Fernet key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"phantex-oidc-secret-v1",
        info=b"oidc-client-secret-encryption",
    )
    raw_key = hkdf.derive(secret)
    # Fernet requires base64-encoded 32-byte key
    _fernet_key = base64.urlsafe_b64encode(raw_key)
    return _fernet_key

def _fernet_encrypt(plaintext: str) -> str:
    """Encrypt with Fernet (dev fallback). Returns 'fernet:1:<token>'."""
    from cryptography.fernet import Fernet

    f = Fernet(_get_fernet_key())
    token = f.encrypt(plaintext.encode("utf-8")).decode("ascii")
    return f"fernet:1:{token}"

def _fernet_decrypt(ciphertext: str) -> str:
    """Decrypt a 'fernet:1:<token>' value."""
    from cryptography.fernet import Fernet

    # Strip prefix
    parts = ciphertext.split(":", 2)
    if len(parts) != 3 or parts[0] != "fernet":
        raise ValueError("Invalid Fernet ciphertext format")

    token = parts[2]
    f = Fernet(_get_fernet_key())
    return f.decrypt(token.encode("ascii")).decode("utf-8")

# ── Vault Transit Encryption ─────────────────────────────────────────────────

_vault_client: Any = None  # Lazy-initialized VaultClient

async def _get_vault_client():
    """Get or create the Vault client singleton."""
    global _vault_client
    if _vault_client is not None:
        return _vault_client

    settings = get_settings()
    if not settings.vault_enabled:
        return None

    from app.services.vault_client import VaultClient

    _vault_client = VaultClient(
        addr=settings.vault_addr,
        role_id=settings.vault_role_id,
        secret_id=settings.vault_secret_id,
        token=settings.vault_token,
    )
    return _vault_client

async def _vault_encrypt(plaintext: str) -> str:
    """Encrypt via Vault Transit engine. Returns the vault ciphertext string."""
    client = await _get_vault_client()
    if client is None:
        raise RuntimeError("Vault not available for encryption")

    await client._ensure_token()
    b64_input = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")

    resp = await client._client.post(
        f"/v1/{client._transit_mount}/encrypt/phantex-secrets",
        headers=client._headers(),
        json={"plaintext": b64_input},
    )
    resp.raise_for_status()
    client._check_response_size(resp)
    # Returns "vault:v1:<ciphertext>"
    return resp.json()["data"]["ciphertext"]

async def _vault_decrypt(ciphertext: str) -> str:
    """Decrypt a Vault Transit ciphertext string."""
    client = await _get_vault_client()
    if client is None:
        raise RuntimeError("Vault not available for decryption")

    await client._ensure_token()

    resp = await client._client.post(
        f"/v1/{client._transit_mount}/decrypt/phantex-secrets",
        headers=client._headers(),
        json={"ciphertext": ciphertext},
    )
    resp.raise_for_status()
    client._check_response_size(resp)
    b64_plaintext = resp.json()["data"]["plaintext"]
    return base64.b64decode(b64_plaintext).decode("utf-8")

# ── Public API ────────────────────────────────────────────────────────────────

async def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt a secret string for at-rest storage.

    Uses Vault Transit when available, Fernet fallback in dev mode.
    Returns a tagged ciphertext string.
    """
    if not plaintext:
        return plaintext

    settings = get_settings()

    if settings.vault_enabled:
        try:
            result = await _vault_encrypt(plaintext)
            logger.debug("secret_encrypted", backend="vault")
            return result
        except Exception as e:
            logger.warning("vault_encrypt_failed_fallback_fernet", error=str(e))
            # Fall through to Fernet

    result = _fernet_encrypt(plaintext)
    logger.debug("secret_encrypted", backend="fernet")
    return result

async def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt a secret string from storage.

    Automatically detects the encryption scheme from the ciphertext prefix.
    Returns the original plaintext.
    Handles legacy unencrypted values gracefully (returns as-is).
    """
    if not ciphertext:
        return ciphertext

    # Vault Transit ciphertext
    if ciphertext.startswith("vault:v"):
        try:
            return await _vault_decrypt(ciphertext)
        except Exception as e:
            logger.error("vault_decrypt_failed", error=str(e))
            raise ValueError("Failed to decrypt secret from Vault") from e

    # Fernet ciphertext
    if ciphertext.startswith("fernet:"):
        try:
            return _fernet_decrypt(ciphertext)
        except Exception as e:
            logger.error("fernet_decrypt_failed", error=str(e))
            raise ValueError("Failed to decrypt secret") from e

    # Legacy plaintext — return as-is (will be re-encrypted on next config update)
    logger.warning(
        "legacy_plaintext_secret_detected",
        hint="Secret will be encrypted on next SSO config update",
    )
    return ciphertext
