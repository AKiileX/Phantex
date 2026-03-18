# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Vault Client for Secret Management & JWT Signing.

Provides:
  - VaultClient: AppRole-authenticated client for reading KV secrets
  - VaultJWTSigner: Transit-engine-based RS256 JWT signing & verification

In dev mode (PHANTEX_VAULT_ENABLED=false), falls back to local secrets
from environment variables / config.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger("phantex.services.vault")

class VaultClient:
    """
    HashiCorp Vault client using AppRole authentication.

    Handles:
      - AppRole login + automatic token renewal
      - KV v2 secret reads
      - Transit sign/verify operations for JWT RS256
    """

    def __init__(
        self,
        addr: str = "http://127.0.0.1:8200",
        role_id: str = "",
        secret_id: str = "",
        *,
        token: str = "",
        mount_path: str = "secret",
        transit_mount: str = "transit",
    ) -> None:
        self._addr = addr.rstrip("/")
        self._role_id = role_id
        self._secret_id = secret_id
        self._mount_path = mount_path
        self._transit_mount = transit_mount
        self._token = token
        self._token_expiry = 0.0
        self._client = httpx.AsyncClient(
            base_url=self._addr,
            timeout=10.0,
        )
        self._max_response_bytes = 1_048_576  # 1MB response body limit

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def _ensure_token(self) -> None:
        """Authenticate via AppRole if token is missing or expired."""
        if self._token and time.time() < self._token_expiry - 60:
            return

        if not self._role_id:
            # Using static token (dev mode)
            return

        resp = await self._client.post(
            "/v1/auth/approle/login",
            json={
                "role_id": self._role_id,
                "secret_id": self._secret_id,
            },
        )
        resp.raise_for_status()
        data = resp.json()

        self._token = data["auth"]["client_token"]
        lease_duration = data["auth"].get("lease_duration", 3600)
        self._token_expiry = time.time() + lease_duration

        logger.info(
            "vault_approle_login",
            lease_duration=lease_duration,
        )

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._token}

    def _check_response_size(self, resp: httpx.Response) -> None:
        """Reject oversized responses to prevent memory exhaustion.

        Note: httpx eagerly buffers the body, so this is a best-effort
        guard using Content-Length.  Chunked responses without the header
        bypass this check — acceptable for an internal Vault client where
        responses are typically small (< 10 KB).
        """
        cl = resp.headers.get("content-length")
        if not cl:
            return
        try:
            size = int(cl)
        except (ValueError, OverflowError):
            return  # malformed header — skip check
        if size < 0:
            raise ValueError(f"Vault response has negative Content-Length: {size}")
        if size > self._max_response_bytes:
            raise ValueError(f"Vault response too large: {size} bytes (max {self._max_response_bytes})")

    @staticmethod
    def _validate_path(path: str) -> None:
        """Reject path traversal attempts and absolute paths."""
        if ".." in path or path.startswith("/"):
            raise ValueError(f"Invalid Vault path: {path!r} — must not contain '..' or start with '/'")

    async def read_secret(self, path: str) -> dict[str, Any]:
        """
        Read a KV v2 secret.

        Args:
            path: Secret path relative to mount (e.g., "phantex/database")

        Returns:
            Secret data dict
        """
        self._validate_path(path)
        await self._ensure_token()
        url = f"/v1/{self._mount_path}/data/{path}"
        resp = await self._client.get(url, headers=self._headers())
        resp.raise_for_status()
        self._check_response_size(resp)
        return resp.json()["data"]["data"]

    async def transit_sign(self, key_name: str, payload: bytes) -> str:
        """
        Sign data using Vault Transit engine (RS256 / RSA-PSS).

        Args:
            key_name: Transit key name (e.g., "jwt-signing")
            payload: Raw bytes to sign

        Returns:
            Base64-encoded signature (vault:v1:... prefix stripped)
        """
        self._validate_path(key_name)
        await self._ensure_token()
        b64_input = base64.b64encode(payload).decode()

        resp = await self._client.post(
            f"/v1/{self._transit_mount}/sign/{key_name}",
            headers=self._headers(),
            json={
                "input": b64_input,
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pkcs1v15",
            },
        )
        resp.raise_for_status()
        self._check_response_size(resp)
        # Vault returns "vault:v1:<base64_sig>"
        sig = resp.json()["data"]["signature"]
        return sig

    async def transit_verify(self, key_name: str, payload: bytes, signature: str) -> bool:
        """
        Verify a signature using Vault Transit engine.

        Args:
            key_name: Transit key name
            payload: Original data bytes
            signature: Vault signature string (vault:v1:...)

        Returns:
            True if valid
        """
        self._validate_path(key_name)
        await self._ensure_token()
        b64_input = base64.b64encode(payload).decode()

        resp = await self._client.post(
            f"/v1/{self._transit_mount}/verify/{key_name}",
            headers=self._headers(),
            json={
                "input": b64_input,
                "signature": signature,
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pkcs1v15",
            },
        )
        resp.raise_for_status()
        self._check_response_size(resp)
        return resp.json()["data"]["valid"]

    async def transit_get_public_key(self, key_name: str) -> str:
        """
        Get the public key from a Transit key (for offline JWT verification).

        Returns:
            PEM-encoded public key string
        """
        self._validate_path(key_name)
        await self._ensure_token()
        resp = await self._client.get(
            f"/v1/{self._transit_mount}/keys/{key_name}",
            headers=self._headers(),
        )
        resp.raise_for_status()
        self._check_response_size(resp)
        keys = resp.json()["data"]["keys"]
        # Latest version's public key
        latest = max(keys.keys(), key=int)
        return keys[latest]["public_key"]

class VaultJWTSigner:
    """
    JWT signer/verifier backed by Vault Transit engine.

    Produces standard RS256 JWTs where the private key never leaves Vault.
    Verification can be done either via Vault or locally using the cached
    public key.
    """

    def __init__(
        self,
        vault: VaultClient,
        key_name: str = "jwt-signing",
    ) -> None:
        self._vault = vault
        self._key_name = key_name
        self._public_key_pem: str | None = None

    async def sign_jwt(self, claims: dict[str, Any]) -> str:
        """
        Create a signed JWT token.

        Args:
            claims: JWT payload claims (sub, exp, iat, etc.)

        Returns:
            Compact JWT string (header.payload.signature)
        """
        # Build header
        header = {"alg": "RS256", "typ": "JWT"}
        header_b64 = _b64url_encode(json.dumps(header).encode())
        payload_b64 = _b64url_encode(json.dumps(claims).encode())

        signing_input = f"{header_b64}.{payload_b64}"

        # Sign via Vault Transit
        vault_sig = await self._vault.transit_sign(self._key_name, signing_input.encode())

        # Vault returns "vault:v1:<base64>" — extract raw signature
        # and convert to URL-safe base64
        sig_parts = vault_sig.split(":")
        raw_b64 = sig_parts[-1]  # last part is the base64 signature
        # Convert standard base64 to URL-safe base64
        sig_b64url = raw_b64.replace("+", "-").replace("/", "_").rstrip("=")

        return f"{signing_input}.{sig_b64url}"

    async def verify_jwt(self, token: str) -> dict[str, Any] | None:
        """
        Verify a JWT token signature via Vault Transit.

        Returns:
            Decoded claims dict if valid, None if invalid
        """
        parts = token.split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}"

        # Convert URL-safe base64 back to standard base64 for Vault
        sig_std = parts[2].replace("-", "+").replace("_", "/")
        # Add padding
        padding = 4 - len(sig_std) % 4
        if padding != 4:
            sig_std += "=" * padding

        vault_sig = f"vault:v1:{sig_std}"

        try:
            valid = await self._vault.transit_verify(self._key_name, signing_input.encode(), vault_sig)
        except Exception as e:
            logger.warning("vault_jwt_verify_error", error=str(e))
            return None

        if not valid:
            return None

        # Decode payload
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        claims = json.loads(payload_bytes)

        # Check expiration
        if "exp" in claims and claims["exp"] < time.time():
            return None

        # Reject tokens with iat in the future (clock skew allowance: 60s)
        if "iat" in claims and claims["iat"] > time.time() + 60:
            return None

        return claims

    async def get_public_key_pem(self) -> str:
        """Get cached public key PEM for offline verification."""
        if self._public_key_pem is None:
            self._public_key_pem = await self._vault.transit_get_public_key(self._key_name)
        return self._public_key_pem

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
