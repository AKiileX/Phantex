# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
H-Block Hardening Tests —

Covers all 7 findings from the H1-H3 (mTLS, Vault, WS Ticket Auth) audit:
  H-01 HIGH:   WS ticket uses correct .user_id attribute (not .id)
  H-02 HIGH:   Vault path traversal rejected in Python client
  H-04 MEDIUM: Production config rejects ws_legacy_token_enabled=True
  H-05 MEDIUM: VaultJWTSigner.verify_jwt rejects future-iat tokens
  H-06 LOW:    VaultClient._check_response_size rejects negative Content-Length
  H-07 LOW:    RedisWSTicketStore.consume_ticket handles corrupt JSON

Go fixes (H-03 TLS double-close) are tested by Go test suites.
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock

import httpx
import pytest

from app.services.vault_client import VaultClient, VaultJWTSigner, _b64url_encode
from app.services.ws_ticket import WSTicketStore

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_response(
    status_code: int = 200,
    json_data: dict | None = None,
    headers: dict | None = None,
) -> httpx.Response:
    resp = httpx.Response(
        status_code=status_code,
        json=json_data,
        headers=headers or {},
        request=httpx.Request("GET", "http://fake:8200/"),
    )
    return resp

def _prod_settings(**overrides) -> dict:
    """Base kwargs for a production Settings instance."""
    base = {
        "environment": "production",
        "jwt_secret": "a-real-production-secret-that-is-at-least-32-chars",
        "db_password": "real-db-password",
        "db_admin_password": "real-admin-password",
        "cors_origins": ["https://phantex.example.com"],
        "redis_url": "redis://prod-redis:6379/0",
        "debug": False,
        "db_echo_sql": False,
        "db_ssl_mode": "require",
        "ws_legacy_token_enabled": False,
        "vault_enabled": True,
        "vault_role_id": "test-role-id",
        "vault_secret_id": "test-secret-id",
    }
    base.update(overrides)
    return base

# ═════════════════════════════════════════════════════════════════════════════
# H-01: WS ticket endpoint uses correct .user_id attribute
# ═════════════════════════════════════════════════════════════════════════════

class TestH01WSTicketUserIdAttribute:
    """Verify ws.py create_ws_ticket reads .user_id (not .id) from CurrentUser."""

    def test_create_ws_ticket_reads_user_id(self):
        """Importing the router module and checking the create_ws_ticket
        function uses the correct attribute .user_id on CurrentUser."""
        import inspect

        from app.routers.ws import create_ws_ticket

        source = inspect.getsource(create_ws_ticket)
        # Must NOT reference ".id" for user — must use ".user_id"
        assert 'getattr(current_user, "user_id"' in source or "current_user.user_id" in source, (
            "create_ws_ticket must use .user_id, not .id"
        )

    def test_create_ws_ticket_does_not_use_dot_id(self):
        """The old buggy pattern getattr(current_user, "id", ...) must not appear."""
        import inspect

        from app.routers.ws import create_ws_ticket

        source = inspect.getsource(create_ws_ticket)
        assert 'getattr(current_user, "id"' not in source, (
            'create_ws_ticket must not use getattr(current_user, "id", ...) — use .user_id'
        )

    def test_current_user_schema_has_user_id(self):
        """CurrentUser Pydantic model must have user_id field."""
        from app.schemas.auth import CurrentUser

        assert "user_id" in CurrentUser.model_fields, "CurrentUser must have user_id field"

    def test_current_user_schema_has_no_id_field(self):
        """CurrentUser must NOT have a plain 'id' field — prevents confusion."""
        from app.schemas.auth import CurrentUser

        assert "id" not in CurrentUser.model_fields, "CurrentUser must not have 'id' field (use 'user_id')"

# ═════════════════════════════════════════════════════════════════════════════
# H-02: Vault path traversal rejection
# ═════════════════════════════════════════════════════════════════════════════

class TestH02VaultPathTraversal:
    """Vault client must reject paths containing '..' or starting with '/'."""

    def setup_method(self):
        self.client = VaultClient(addr="http://fake:8200", token="dev-token")

    @pytest.mark.asyncio
    async def test_read_secret_rejects_dotdot(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.read_secret("../../sys/seal")

    @pytest.mark.asyncio
    async def test_read_secret_rejects_absolute_path(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.read_secret("/sys/seal")

    @pytest.mark.asyncio
    async def test_read_secret_rejects_embedded_dotdot(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.read_secret("phantex/../sys/seal")

    @pytest.mark.asyncio
    async def test_read_secret_allows_normal_path(self):
        """Normal paths should not be rejected by validation."""
        mock_resp = _make_response(json_data={"data": {"data": {"key": "value"}}})
        self.client._client = AsyncMock()
        self.client._client.get = AsyncMock(return_value=mock_resp)

        result = await self.client.read_secret("phantex/database")
        assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_transit_sign_rejects_dotdot(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.transit_sign("../sys/seal", b"payload")

    @pytest.mark.asyncio
    async def test_transit_verify_rejects_dotdot(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.transit_verify("../sys/seal", b"data", "sig")

    @pytest.mark.asyncio
    async def test_transit_get_public_key_rejects_dotdot(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.transit_get_public_key("../sys/seal")

    @pytest.mark.asyncio
    async def test_transit_get_public_key_rejects_absolute(self):
        with pytest.raises(ValueError, match="must not contain"):
            await self.client.transit_get_public_key("/transit/keys/jwt")

    def test_validate_path_static_method(self):
        """_validate_path is a static method and can be called directly."""
        VaultClient._validate_path("normal/path")  # should not raise
        with pytest.raises(ValueError):
            VaultClient._validate_path("../../bad")
        with pytest.raises(ValueError):
            VaultClient._validate_path("/absolute")

# ═════════════════════════════════════════════════════════════════════════════
# H-04: Production config rejects ws_legacy_token_enabled=True
# ═════════════════════════════════════════════════════════════════════════════

class TestH04ProductionLegacyWSGuard:
    """Production/staging must reject ws_legacy_token_enabled=True."""

    def test_legacy_ws_rejected_in_production(self):
        from pydantic import ValidationError

        from app.config import Settings

        with pytest.raises(ValidationError, match="ws_legacy_token_enabled"):
            Settings(**_prod_settings(ws_legacy_token_enabled=True))

    def test_legacy_ws_rejected_in_staging(self):
        from pydantic import ValidationError

        from app.config import Settings

        with pytest.raises(ValidationError, match="ws_legacy_token_enabled"):
            Settings(
                **_prod_settings(
                    environment="staging",
                    ws_legacy_token_enabled=True,
                )
            )

    def test_legacy_ws_disabled_accepted_in_production(self):
        import os
        from unittest.mock import patch

        from app.config import Settings

        env_overrides = {
            "PHANTEX_DECOY_KEY_PASSPHRASE": "strong-production-decoy-passphrase",
            "PHANTEX_SIGNING_KEY": "real-ed25519-signing-key",
        }
        with patch.dict(os.environ, env_overrides):
            s = Settings(**_prod_settings(ws_legacy_token_enabled=False))
        assert s.ws_legacy_token_enabled is False

    def test_legacy_ws_allowed_in_dev(self):
        from app.config import Settings

        s = Settings(environment="development", ws_legacy_token_enabled=True)
        assert s.ws_legacy_token_enabled is True

# ═════════════════════════════════════════════════════════════════════════════
# H-05: VaultJWTSigner.verify_jwt rejects future-iat tokens
# ═════════════════════════════════════════════════════════════════════════════

class TestH05VaultJWTIatFreshness:
    """verify_jwt must reject tokens with iat in the remote future."""

    @pytest.mark.asyncio
    async def test_reject_future_iat(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=True)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        # Token with iat 1 hour in the future (exceeds 60s clock skew)
        header = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "exp": int(time.time()) + 7200,
                    "iat": int(time.time()) + 3600,  # 1 hour in the future
                }
            ).encode()
        )
        sig = _b64url_encode(b"fake-sig")
        token = f"{header}.{payload}.{sig}"

        result = await signer.verify_jwt(token)
        assert result is None, "Tokens with iat far in the future must be rejected"

    @pytest.mark.asyncio
    async def test_accept_iat_within_skew(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=True)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        # Token with iat 30s in the future (within 60s clock skew)
        header = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "exp": int(time.time()) + 3600,
                    "iat": int(time.time()) + 30,  # 30s in the future — acceptable skew
                }
            ).encode()
        )
        sig = _b64url_encode(b"fake-sig")
        token = f"{header}.{payload}.{sig}"

        result = await signer.verify_jwt(token)
        assert result is not None, "Tokens with iat within clock skew should be accepted"
        assert result["sub"] == "user-1"

    @pytest.mark.asyncio
    async def test_accept_normal_iat(self):
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=True)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        header = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "exp": int(time.time()) + 3600,
                    "iat": int(time.time()),
                }
            ).encode()
        )
        sig = _b64url_encode(b"fake-sig")
        token = f"{header}.{payload}.{sig}"

        result = await signer.verify_jwt(token)
        assert result is not None
        assert result["sub"] == "user-1"

    @pytest.mark.asyncio
    async def test_no_iat_still_accepted(self):
        """Tokens without iat should still work (iat check is opt-in)."""
        vault = AsyncMock(spec=VaultClient)
        vault.transit_verify = AsyncMock(return_value=True)
        signer = VaultJWTSigner(vault, key_name="jwt-signing")

        header = _b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url_encode(
            json.dumps(
                {
                    "sub": "user-1",
                    "exp": int(time.time()) + 3600,
                }
            ).encode()
        )
        sig = _b64url_encode(b"fake-sig")
        token = f"{header}.{payload}.{sig}"

        result = await signer.verify_jwt(token)
        assert result is not None

# ═════════════════════════════════════════════════════════════════════════════
# H-06: VaultClient._check_response_size rejects negative Content-Length
# ═════════════════════════════════════════════════════════════════════════════

class TestH06NegativeContentLength:
    """_check_response_size must reject negative Content-Length values."""

    def setup_method(self):
        self.client = VaultClient(addr="http://fake:8200", token="dev-token")

    def test_negative_content_length_rejected(self):
        resp = _make_response(headers={"content-length": "-1"})
        with pytest.raises(ValueError, match="negative Content-Length"):
            self.client._check_response_size(resp)

    def test_negative_large_content_length_rejected(self):
        resp = _make_response(headers={"content-length": "-99999"})
        with pytest.raises(ValueError, match="negative Content-Length"):
            self.client._check_response_size(resp)

    def test_zero_content_length_accepted(self):
        resp = _make_response(headers={"content-length": "0"})
        self.client._check_response_size(resp)  # should not raise

    def test_normal_content_length_accepted(self):
        resp = _make_response(headers={"content-length": "500"})
        self.client._check_response_size(resp)  # should not raise

    def test_over_limit_still_rejected(self):
        resp = _make_response(headers={"content-length": "2000000"})
        with pytest.raises(ValueError, match="too large"):
            self.client._check_response_size(resp)

# ═════════════════════════════════════════════════════════════════════════════
# H-07: RedisWSTicketStore.consume_ticket handles corrupt JSON
# ═════════════════════════════════════════════════════════════════════════════

class TestH07RedisTicketCorruptJSON:
    """RedisWSTicketStore.consume_ticket must handle corrupt JSON gracefully."""

    @pytest.mark.asyncio
    async def test_corrupt_json_returns_none(self):
        from app.services.redis_rate_limit import RedisWSTicketStore

        mock_redis = AsyncMock()
        mock_redis.getdel = AsyncMock(return_value=b"not-valid-json{{{")
        mock_redis.decr = AsyncMock()

        store = RedisWSTicketStore(mock_redis)
        result = await store.consume_ticket("some-ticket")

        assert result is None, "Corrupt JSON must return None, not crash"

    @pytest.mark.asyncio
    async def test_valid_json_returns_data(self):
        from app.services.redis_rate_limit import RedisWSTicketStore

        mock_redis = AsyncMock()
        mock_redis.getdel = AsyncMock(return_value=b'{"tenant_id":"t-1","user_id":"u-1","role":"admin"}')
        mock_redis.decr = AsyncMock()

        store = RedisWSTicketStore(mock_redis)
        result = await store.consume_ticket("some-ticket")

        assert result is not None
        assert result["tenant_id"] == "t-1"

    @pytest.mark.asyncio
    async def test_missing_ticket_returns_none(self):
        from app.services.redis_rate_limit import RedisWSTicketStore

        mock_redis = AsyncMock()
        mock_redis.getdel = AsyncMock(return_value=None)

        store = RedisWSTicketStore(mock_redis)
        result = await store.consume_ticket("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_bytes_returns_none(self):
        from app.services.redis_rate_limit import RedisWSTicketStore

        mock_redis = AsyncMock()
        mock_redis.getdel = AsyncMock(return_value=b"")
        mock_redis.decr = AsyncMock()

        store = RedisWSTicketStore(mock_redis)
        result = await store.consume_ticket("some-ticket")

        assert result is None

# ═════════════════════════════════════════════════════════════════════════════
# Additional hardening: WSTicketStore edge cases
# ═════════════════════════════════════════════════════════════════════════════

class TestWSTicketStoreEdgeCases:
    """Additional edge-case coverage for in-memory WSTicketStore."""

    def test_consume_empty_string_ticket(self):
        store = WSTicketStore()
        assert store.consume_ticket("") is None

    def test_create_ticket_returns_sufficient_entropy(self):
        """Tickets must have at least 256 bits of entropy (>= 43 chars base64url)."""
        store = WSTicketStore()
        ticket = store.create_ticket("t-1", "u-1", "admin")
        # secrets.token_urlsafe(36) produces 48 chars = 36 bytes = 288 bits
        assert len(ticket) >= 43, f"Ticket too short ({len(ticket)} chars), need >= 256 bits"

    def test_ticket_not_predictable(self):
        """Two consecutive tickets must differ."""
        store = WSTicketStore()
        t1 = store.create_ticket("t-1", "u-1", "admin")
        t2 = store.create_ticket("t-1", "u-1", "admin")
        assert t1 != t2
