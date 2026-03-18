# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for backend/app/config.py — Production Secret Guard.

Covers:
  - Dev-default secret rejection in production/staging
  - Vault credential enforcement when vault_enabled
  - Redis URL default rejection
  - Debug mode rejection in production
  - db_echo_sql rejection in production
  - ws_legacy_token_enabled config field
  - Dev mode allows all defaults
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings

# ── Helpers ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _prod_env_vars(monkeypatch):
    """Set required production env vars so validators pass."""
    monkeypatch.setenv("PHANTEX_DECOY_KEY_PASSPHRASE", "test-strong-passphrase-32chars!!")
    monkeypatch.setenv("PHANTEX_SIGNING_KEY", "test-ed25519-signing-key-for-ci")

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
        "vault_role_id": "prod-role-id",
        "vault_secret_id": "prod-secret-id",
    }
    base.update(overrides)
    return base

# ── Dev Mode (everything allowed) ───────────────────────────────────────────

class TestDevMode:
    def test_dev_defaults_accepted(self):
        """Default dev secrets should be accepted in development."""
        s = Settings(environment="development")
        assert s.environment == "development"

    def test_test_defaults_accepted(self):
        s = Settings(environment="test")
        assert s.environment == "test"

# ── Production Secret Guard ──────────────────────────────────────────────────

class TestProductionSecretGuard:
    def test_dev_jwt_secret_rejected_in_production(self):
        with pytest.raises(ValidationError, match="jwt_secret"):
            Settings(**_prod_settings(jwt_secret="phantex-dev-jwt-secret-change-in-production-256bit-min"))

    def test_dev_db_password_rejected_in_production(self):
        with pytest.raises(ValidationError, match="db_password"):
            Settings(**_prod_settings(db_password="phantex-app-dev-password"))

    def test_dev_admin_password_rejected_in_production(self):
        with pytest.raises(ValidationError, match="db_admin_password"):
            Settings(**_prod_settings(db_admin_password="phantex-dev-password"))

    def test_valid_production_secrets_accepted(self):
        s = Settings(**_prod_settings())
        assert s.environment == "production"

    def test_staging_also_enforced(self):
        with pytest.raises(ValidationError, match="jwt_secret"):
            Settings(
                **_prod_settings(
                    environment="staging",
                    jwt_secret="phantex-dev-jwt-secret-change-in-production-256bit-min",
                )
            )

# ── Vault Credential Enforcement ────────────────────────────────────────────

class TestVaultCredentialGuard:
    def test_vault_enabled_requires_role_id(self):
        with pytest.raises(ValidationError, match="vault_role_id"):
            Settings(
                **_prod_settings(
                    vault_enabled=True,
                    vault_role_id="",
                    vault_secret_id="some-secret",
                )
            )

    def test_vault_enabled_requires_secret_id(self):
        with pytest.raises(ValidationError, match="vault_secret_id"):
            Settings(
                **_prod_settings(
                    vault_enabled=True,
                    vault_role_id="some-role",
                    vault_secret_id="",
                )
            )

    def test_vault_enabled_with_credentials_accepted(self):
        s = Settings(
            **_prod_settings(
                vault_enabled=True,
                vault_role_id="role-123",
                vault_secret_id="secret-456",
            )
        )
        assert s.vault_enabled is True

    def test_vault_disabled_no_credentials_needed(self):
        s = Settings(
            **_prod_settings(
                vault_enabled=False,
                jwt_algorithm="RS256",
                jwt_private_key_file="/etc/phantex/jwt.key",
                jwt_public_key_file="/etc/phantex/jwt.pub",
            )
        )
        assert s.vault_enabled is False

# ── Redis URL Guard ──────────────────────────────────────────────────────────

class TestRedisUrlGuard:
    def test_default_redis_url_rejected_in_production(self):
        with pytest.raises(ValidationError, match="redis_url"):
            Settings(**_prod_settings(redis_url="redis://localhost:6379/0"))

    def test_production_redis_url_accepted(self):
        s = Settings(**_prod_settings(redis_url="redis://redis-cluster:6379/0"))
        assert "redis-cluster" in s.redis_url

# ── Debug / Echo Guard ───────────────────────────────────────────────────────

class TestDebugGuard:
    def test_debug_rejected_in_production(self):
        with pytest.raises(ValidationError, match="debug"):
            Settings(**_prod_settings(debug=True))

    def test_db_echo_sql_rejected_in_production(self):
        with pytest.raises(ValidationError, match="db_echo_sql"):
            Settings(**_prod_settings(db_echo_sql=True))

# ── WebSocket Config ─────────────────────────────────────────────────────────

class TestWebSocketConfig:
    def test_ws_legacy_token_enabled_default_false(self):
        s = Settings(environment="development")
        assert s.ws_legacy_token_enabled is False

    def test_ws_legacy_token_enabled_can_be_disabled(self):
        s = Settings(environment="development", ws_legacy_token_enabled=False)
        assert s.ws_legacy_token_enabled is False

# ── CORS Localhost Guard ─────────────────────────────────────────────────────

class TestCORSLocalhostGuard:
    def test_localhost_cors_rejected_in_production(self):
        with pytest.raises(ValidationError, match="localhost"):
            Settings(**_prod_settings(cors_origins=["http://localhost:3000"]))

    def test_127_cors_rejected_in_production(self):
        with pytest.raises(ValidationError, match="localhost"):
            Settings(**_prod_settings(cors_origins=["http://127.0.0.1:3000"]))

    def test_production_domain_cors_accepted(self):
        s = Settings(**_prod_settings(cors_origins=["https://phantex.example.com"]))
        assert s.cors_origins == ["https://phantex.example.com"]

    def test_allow_localhost_cors_bypasses_guard(self):
        s = Settings(**_prod_settings(
            cors_origins=["http://localhost:3000"],
            allow_localhost_cors=True,
        ))
        assert s.cors_origins == ["http://localhost:3000"]
        assert s.allow_localhost_cors is True

    def test_allow_localhost_cors_default_false(self):
        s = Settings(environment="development")
        assert s.allow_localhost_cors is False
