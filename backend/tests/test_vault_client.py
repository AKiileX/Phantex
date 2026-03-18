# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for backend/app/services/vault_client.py

Covers:
  - VaultClient: AppRole login, token caching, KV read, Transit sign/verify,
    public key fetch, response size guard, _check_response_size edge cases
  - VaultJWTSigner: sign_jwt, verify_jwt, expired token rejection, malformed
    token handling, public key caching
  - _b64url_encode helper
"""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.services.vault_client import (
    VaultClient,
    VaultJWTSigner,
    _b64url_encode,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_response(
    status_code: int = 200,
    json_data: dict | None = None,
    headers: dict | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response with given status, JSON body, and headers."""
    resp = httpx.Response(
        status_code=status_code,
        json=json_data,
        headers=headers or {},
        request=httpx.Request("GET", "http://fake:8200/"),
    )
    return resp

# ── _b64url_encode ───────────────────────────────────────────────────────────

class TestB64UrlEncode:
    def test_basic(self):
        result = _b64url_encode(b"hello")
        # Should be URL-safe and unpadded
        assert "+" not in result
        assert "/" not in result
        assert "=" not in result
        # Should decode back
        padded = result + "=" * (4 - len(result) % 4) if len(result) % 4 else result
        assert base64.urlsafe_b64decode(padded) == b"hello"

    def test_empty(self):
        assert _b64url_encode(b"") == ""

# ── VaultClient._check_response_size ────────────────────────────────────────

class TestCheckResponseSize:
    def setup_method(self):
        self.client = VaultClient(addr="http://fake:8200", token="dev-token")

    def test_small_response_ok(self):
        resp = _make_response(headers={"content-length": "100"})
        self.client._check_response_size(resp)  # should not raise

    def test_over_limit_raises(self):
        resp = _make_response(headers={"content-length": "2000000"})
        with pytest.raises(ValueError, match="too large"):
            self.client._check_response_size(resp)

    def test_no_content_length_ok(self):
        resp = _make_response(headers={})
        self.client._check_response_size(resp)  # should not raise

    def test_malformed_content_length_ignored(self):
        resp = _make_response(headers={"content-length": "not-a-number"})
        self.client._check_response_size(resp)  # should not raise

    def test_negative_content_length_rejected(self):
        resp = _make_response(headers={"content-length": "-1"})
        with pytest.raises(ValueError, match="negative Content-Length"):
            self.client._check_response_size(resp)

    def test_overflow_content_length_rejected(self):
        resp = _make_response(headers={"content-length": "99999999999999999999999999999"})
        # Python int() handles big numbers — value exceeds max → rejected
        with pytest.raises(ValueError, match="too large"):
            self.client._check_response_size(resp)

# ── VaultClient._ensure_token ───────────────────────────────────────────────

class TestEnsureToken:
    @pytest.mark.asyncio
    async def test_static_token_skips_login(self):
        client = VaultClient(addr="http://fake:8200", token="my-static-token")
        await client._ensure_token()
        # Should still have the static token
        assert client._token == "my-static-token"

    @pytest.mark.asyncio
    async def test_cached_token_skips_login(self):
        client = VaultClient(
            addr="http://fake:8200",
            role_id="role",
            secret_id="secret",
            token="cached-token",
        )
        client._token_expiry = time.time() + 3600  # expires in 1h
        # Should NOT make network call
        await client._ensure_token()
        assert client._token == "cached-token"

    @pytest.mark.asyncio
    async def test_approle_login(self):
        client = VaultClient(
            addr="http://fake:8200",
            role_id="test-role",
            secret_id="test-secret",
        )
        mock_resp = _make_response(
            json_data={
                "auth": {
                    "client_token": "new-token-123",
                    "lease_duration": 3600,
                }
            }
        )
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        await client._ensure_token()

        assert client._token == "new-token-123"
        assert client._token_expiry > time.time()
        client._client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_approle_login_failure_raises(self):
        client = VaultClient(
            addr="http://fake:8200",
            role_id="test-role",
            secret_id="bad-secret",
        )
        mock_resp = _make_response(status_code=403, json_data={"errors": ["permission denied"]})
        mock_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=mock_resp)
        )
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(httpx.HTTPStatusError):
            await client._ensure_token()

# ── VaultClient.read_secret ─────────────────────────────────────────────────

class TestReadSecret:
    @pytest.mark.asyncio
    async def test_read_secret_returns_data(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        mock_resp = _make_response(json_data={"data": {"data": {"db_password": "s3cret", "db_user": "admin"}}})
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        result = await client.read_secret("phantex/database")

        assert result == {"db_password": "s3cret", "db_user": "admin"}
        client._client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_read_secret_oversized_response_rejected(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        mock_resp = _make_response(
            json_data={"data": {"data": {}}},
            headers={"content-length": "9999999"},
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(ValueError, match="too large"):
            await client.read_secret("phantex/database")

# ── VaultClient.transit_sign ─────────────────────────────────────────────────

class TestTransitSign:
    @pytest.mark.asyncio
    async def test_sign_returns_vault_signature(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        mock_resp = _make_response(json_data={"data": {"signature": "vault:v1:abc123def456"}})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        sig = await client.transit_sign("jwt-signing", b"test-payload")

        assert sig == "vault:v1:abc123def456"
        call_args = client._client.post.call_args
        body = call_args.kwargs.get("json") or call_args[1].get("json")
        assert body["hash_algorithm"] == "sha2-256"
        assert body["signature_algorithm"] == "pkcs1v15"

# ── VaultClient.transit_verify ───────────────────────────────────────────────

class TestTransitVerify:
    @pytest.mark.asyncio
    async def test_verify_valid(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        mock_resp = _make_response(json_data={"data": {"valid": True}})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        assert await client.transit_verify("jwt-signing", b"data", "vault:v1:sig") is True

    @pytest.mark.asyncio
    async def test_verify_invalid(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        mock_resp = _make_response(json_data={"data": {"valid": False}})
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_resp)

        assert await client.transit_verify("jwt-signing", b"data", "vault:v1:bad") is False

# ── VaultClient.transit_get_public_key ───────────────────────────────────────

class TestTransitGetPublicKey:
    @pytest.mark.asyncio
    async def test_returns_latest_version_key(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        mock_resp = _make_response(
            json_data={
                "data": {
                    "keys": {
                        "1": {"public_key": "-----BEGIN PUBLIC KEY-----\nOLD\n-----END PUBLIC KEY-----"},
                        "2": {"public_key": "-----BEGIN PUBLIC KEY-----\nLATEST\n-----END PUBLIC KEY-----"},
                    }
                }
            }
        )
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_resp)

        pem = await client.transit_get_public_key("jwt-signing")
        assert "LATEST" in pem

# ── VaultClient.close ────────────────────────────────────────────────────────

class TestVaultClientClose:
    @pytest.mark.asyncio
    async def test_close(self):
        client = VaultClient(addr="http://fake:8200", token="dev-token")
        client._client = AsyncMock()
        await client.close()
        client._client.aclose.assert_called_once()

# ── VaultClient._headers ────────────────────────────────────────────────────

class TestHeaders:
    def test_headers_contain_token(self):
        client = VaultClient(addr="http://fake:8200", token="my-token")
        assert client._headers() == {"X-Vault-Token": "my-token"}

# ── VaultJWTSigner ──────────────────────────────────────────────────────────

class TestVaultJWTSigner:
    @pytest.mark.asyncio
    async def test_sign_jwt_produces_three_part_token(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_sign = AsyncMock(return_value="vault:v1:dGVzdHNpZw")
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        token = await signer.sign_jwt({"sub": "user-1", "exp": int(time.time()) + 300})

        parts = token.split(".")
        assert len(parts) == 3
        # Header should decode to RS256
        header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))
        assert header == {"alg": "RS256", "typ": "JWT"}

    @pytest.mark.asyncio
    async def test_verify_jwt_valid(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=True)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        # Build a fake token
        header = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "exp": int(time.time()) + 300,
                }
            ).encode()
        )
        sig = _b64url_encode(b"fake-signature")
        token = f"{header}.{payload}.{sig}"

        claims = await signer.verify_jwt(token)
        assert claims is not None
        assert claims["sub"] == "user-1"

    @pytest.mark.asyncio
    async def test_verify_jwt_expired(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=True)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        header = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "exp": int(time.time()) - 100,  # already expired
                }
            ).encode()
        )
        sig = _b64url_encode(b"fake-signature")
        token = f"{header}.{payload}.{sig}"

        claims = await signer.verify_jwt(token)
        assert claims is None  # expired

    @pytest.mark.asyncio
    async def test_verify_jwt_invalid_signature(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=False)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        token = "aaa.bbb.ccc"
        claims = await signer.verify_jwt(token)
        assert claims is None

    @pytest.mark.asyncio
    async def test_verify_jwt_malformed(self):
        vault = AsyncMock(spec=VaultClient)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        # Too few parts
        assert await signer.verify_jwt("only-one-part") is None
        assert await signer.verify_jwt("two.parts") is None

    @pytest.mark.asyncio
    async def test_verify_jwt_transit_error(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(side_effect=Exception("connection refused"))
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        token = "aaa.bbb.ccc"
        claims = await signer.verify_jwt(token)
        assert claims is None

    @pytest.mark.asyncio
    async def test_get_public_key_pem_caches(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_get_public_key = AsyncMock(
            return_value="-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
        )
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        pem1 = await signer.get_public_key_pem()
        pem2 = await signer.get_public_key_pem()

        assert pem1 == pem2
        # Should only call Vault once (cached)
        vault.transit_get_public_key.assert_called_once()
