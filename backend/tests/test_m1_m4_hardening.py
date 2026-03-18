# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for M-1 (OIDC secret encryption) and M-4 (SSO rate limiting).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

# ── M-1: Secret Encryption Tests ─────────────────────────────────────────────

class TestSecretEncryption:
    """M-1: OIDC client_secret must be encrypted at rest."""

    @pytest.mark.asyncio
    async def test_fernet_encrypt_decrypt_roundtrip(self):
        """Fernet encrypt → decrypt returns original plaintext."""
        from app.services.secret_encryption import decrypt_secret, encrypt_secret

        plaintext = "my-super-secret-client-secret-12345"
        ciphertext = await encrypt_secret(plaintext)

        # Must be tagged with scheme prefix
        assert ciphertext.startswith("fernet:1:")
        # Must not contain the plaintext
        assert plaintext not in ciphertext

        # Decrypt roundtrip
        decrypted = await decrypt_secret(ciphertext)
        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_fernet_different_ciphertexts(self):
        """Two encryptions of the same value produce different ciphertexts (Fernet uses random IV)."""
        from app.services.secret_encryption import encrypt_secret

        ct1 = await encrypt_secret("same-secret")
        ct2 = await encrypt_secret("same-secret")
        assert ct1 != ct2  # Fernet uses random IV per encryption

    @pytest.mark.asyncio
    async def test_empty_string_passthrough(self):
        """Empty strings are returned as-is (no encryption needed)."""
        from app.services.secret_encryption import decrypt_secret, encrypt_secret

        assert await encrypt_secret("") == ""
        assert await decrypt_secret("") == ""

    @pytest.mark.asyncio
    async def test_legacy_plaintext_passthrough(self):
        """Legacy unencrypted values are returned as-is on decrypt."""
        from app.services.secret_encryption import decrypt_secret

        legacy = "old-plaintext-secret"
        assert await decrypt_secret(legacy) == legacy

    @pytest.mark.asyncio
    async def test_invalid_fernet_raises(self):
        """Invalid Fernet ciphertext raises ValueError."""
        from app.services.secret_encryption import decrypt_secret

        with pytest.raises(ValueError, match="Failed to decrypt"):
            await decrypt_secret("fernet:1:invalid-garbage-data")

    @pytest.mark.asyncio
    async def test_sso_create_config_encrypts_secret(self):
        """create_sso_config encrypts oidc_client_secret before storage."""
        from app.services.secret_encryption import decrypt_secret

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()

        import uuid

        from app.services.sso_service import create_sso_config

        data = {
            "provider_type": "oidc",
            "oidc_client_id": "test-client-id",
            "oidc_client_secret": "my-secret-value",
            "oidc_issuer": "https://idp.example.com",
            "is_enabled": True,
        }

        config = await create_sso_config(mock_db, uuid.uuid4(), data)

        # The stored secret should be encrypted (not plaintext)
        stored_secret = config.oidc_client_secret
        assert stored_secret is not None
        assert stored_secret.startswith("fernet:1:")
        assert "my-secret-value" not in stored_secret

        # And decrypts back correctly
        decrypted = await decrypt_secret(stored_secret)
        assert decrypted == "my-secret-value"

# ── M-4: SSO Rate Limiting Tests ─────────────────────────────────────────────

class TestSSOrateLimiting:
    """M-4: SSO endpoints must enforce per-IP rate limiting."""

    def test_sso_rate_limiter_exists(self):
        """SSO rate limiter is defined in rate_limit module."""
        from app.middleware.rate_limit import _sso_rate_limiter

        assert _sso_rate_limiter is not None
        assert _sso_rate_limiter.rate == pytest.approx(10.0 / 60.0, rel=0.01)
        assert _sso_rate_limiter.capacity == 5

    def test_sso_rate_limiter_allows_burst(self):
        """SSO rate limiter allows initial burst of 5 requests."""
        from app.middleware.rate_limit import _sso_rate_limiter

        # Use a unique key to avoid interference from other tests
        key = "test-sso-burst-key"
        for i in range(5):
            assert _sso_rate_limiter.allow(key), f"Request {i + 1} should be allowed"

        # 6th request within the same instant should be denied
        assert not _sso_rate_limiter.allow(key), "6th request should be rate-limited"

    @pytest.mark.asyncio
    async def test_sso_rate_limit_returns_429(self):
        """sso_rate_limit raises 429 when limit exceeded."""
        from fastapi import HTTPException

        from app.middleware.rate_limit import sso_rate_limit

        mock_request = MagicMock()
        mock_request.client = MagicMock()
        mock_request.client.host = "192.168.99.99"  # Use unique IP

        # Exhaust the burst capacity
        for _ in range(5):
            await sso_rate_limit(mock_request)

        # Next request should be 429
        with pytest.raises(HTTPException) as exc_info:
            await sso_rate_limit(mock_request)
        assert exc_info.value.status_code == 429
        assert "SSO" in exc_info.value.detail

    def test_sso_routes_have_rate_limit_dependency(self):
        """All 4 SSO login/callback endpoints have sso_rate_limit dependency."""
        from app.routers.sso import router

        sso_endpoints = {
            "/api/v1/sso/saml/login",
            "/api/v1/sso/saml/acs",
            "/api/v1/sso/oidc/login",
            "/api/v1/sso/oidc/callback",
        }

        for route in router.routes:
            if hasattr(route, "path") and route.path in sso_endpoints:
                dep_funcs = [d.dependency for d in (route.dependencies or [])]
                from app.middleware.rate_limit import sso_rate_limit as srl

                assert srl in dep_funcs, f"Route {route.path} missing sso_rate_limit dependency"

    def test_cleanup_includes_sso_limiter(self):
        """cleanup_all processes SSO rate limiter too."""
        from app.middleware.rate_limit import _sso_rate_limiter, cleanup_all

        # Add a test entry
        _sso_rate_limiter._buckets["test-cleanup"] = (5.0, 0.0)  # ancient timestamp

        cleanup_all(max_age=0.0)
        assert "test-cleanup" not in _sso_rate_limiter._buckets
