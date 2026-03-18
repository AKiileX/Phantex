# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Backend — Application Configuration.

All settings loaded from environment variables with sensible dev defaults.
Uses pydantic-settings for validation and type coercion.
"""

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Application settings. Override via environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="PHANTEX_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── App ──────────────────────────────────────────────────────────────
    app_name: str = "Phantex API"
    app_version: str = "0.1.0"
    environment: Literal["development", "staging", "production", "test"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # ── Server ───────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # ── Database ─────────────────────────────────────────────────────────
    # App connects as phantex_app (restricted role with RLS).
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "phantex"
    db_user: str = "phantex_app"
    db_password: str = "phantex-app-dev-password"
    db_pool_size: int = 10
    db_pool_max_overflow: int = 20
    db_echo_sql: bool = False

    # ── Admin Database (for auth — bypasses RLS) ──────────────────────
    db_admin_user: str = "phantex_admin"
    db_admin_password: str = "phantex-dev-password"

    @property
    def admin_database_url(self) -> str:
        """Async PostgreSQL connection string for admin engine (bypasses RLS)."""
        return (
            f"postgresql+asyncpg://{self.db_admin_user}:{self.db_admin_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def database_url(self) -> str:
        """Async PostgreSQL connection string for SQLAlchemy."""
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def database_url_sync(self) -> str:
        """Sync PostgreSQL connection string (for Alembic migrations)."""
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    # ── JWT Auth ─────────────────────────────────────────────────────────
    jwt_secret: str = "phantex-dev-jwt-secret-change-in-production-256bit-min"
    jwt_algorithm: Literal["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"] = "HS256"
    jwt_private_key_file: str = ""  # PEM private key file (required for RS*/ES* algorithms)
    jwt_public_key_file: str = ""   # PEM public key file (required for RS*/ES* algorithms)
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # ── Rate Limiting ────────────────────────────────────────────────────
    rate_limit_per_second: int = 100

    # ── Kafka ────────────────────────────────────────────────────────────
    kafka_bootstrap: str = "localhost:9092"
    kafka_alert_topic_prefix: str = "phantex.alerts"
    kafka_consumer_group: str = "api-realtime"
    kafka_tls_enabled: bool = False
    kafka_tls_cert_file: str = ""
    kafka_tls_key_file: str = ""
    kafka_tls_ca_file: str = ""

    # ── Database TLS ─────────────────────────────────────────────────────
    db_ssl_mode: str = "prefer"  # disable / allow / prefer / require / verify-ca / verify-full
    db_ssl_cert_file: str = ""
    db_ssl_key_file: str = ""
    db_ssl_ca_file: str = ""

    # ── Redis ────────────────────────────────────────────────────────────
    redis_url: str = "redis://:phantex-dev-redis-pw@localhost:6379/0"
    redis_tls_enabled: bool = False
    redis_tls_cert_file: str = ""
    redis_tls_key_file: str = ""
    redis_tls_ca_file: str = ""

    # ── WebSocket ────────────────────────────────────────────────────────
    ws_max_connections_per_tenant: int = 50
    ws_legacy_token_enabled: bool = False  # Disabled by default — use ticket-based auth

    # ── ClickHouse (I2 — Event Analytics) ────────────────────────────────
    clickhouse_host: str = ""  # Empty = disabled; set to "clickhouse" in docker-compose
    clickhouse_port: int = 8123
    clickhouse_database: str = "phantex"
    clickhouse_user: str = "phantex"
    clickhouse_password: str = "phantex-dev-password"
    clickhouse_tls_enabled: bool = False
    clickhouse_tls_cert_file: str = ""
    clickhouse_tls_key_file: str = ""
    clickhouse_tls_ca_file: str = ""

    # ── Neo4j (I3 — Investigation Graphs) ────────────────────────────────
    neo4j_uri: str = ""  # Empty = disabled; set to "bolt://neo4j:7687" in docker-compose
    neo4j_user: str = "neo4j"
    neo4j_password: str = "phantex-dev-password"
    neo4j_database: str = "neo4j"
    neo4j_tls_enabled: bool = False

    # ── CORS ─────────────────────────────────────────────────────────────
    cors_origins: list[str] = ["http://localhost:3000"]
    allow_localhost_cors: bool = False  # Set True for on-prem/lab single-box deployments

    # ── Vault (H2 — Secret Management) ──────────────────────────────────
    vault_enabled: bool = False
    vault_addr: str = "http://127.0.0.1:8200"
    vault_token: str = ""  # Direct token (dev only)
    vault_role_id: str = ""  # AppRole auth
    vault_secret_id: str = ""  # AppRole auth
    vault_jwt_key_name: str = "jwt-signing"  # Transit key for JWT RS256

    # ── GraphQL ──────────────────────────────────────
    # Locked down by default — opt-in via env vars for dev/testing.
    graphql_introspection_enabled: bool = False  # Set True only for local dev
    graphql_ide_enabled: bool = False  # GraphiQL IDE — off by default
    graphql_max_depth: int = 10  # Max query nesting depth
    graphql_max_query_cost: int = 500  # Max estimated query cost units
    graphql_max_aliases: int = 10  # Max field aliases per operation
    graphql_batch_limit: int = 1  # Max operations per HTTP request (1 = no batching)

    # ── Security Headers ─────────────────────────────────────────────────
    # Applied in production only; dev mode is more permissive.

    # ── Production Secret Guard ──────────────────────────────────────────
    _DEV_SECRETS = {
        "phantex-dev-jwt-secret-change-in-production-256bit-min",
        "phantex-app-dev-password",
        "phantex-dev-password",
    }

    @model_validator(mode="after")
    def _reject_dev_secrets_in_production(self) -> "Settings":
        """Ensure dev-default secrets are replaced in production/staging."""
        if self.environment in ("production", "staging"):
            for field_name in ("jwt_secret", "db_password", "db_admin_password"):
                value = getattr(self, field_name)
                if value in self._DEV_SECRETS:
                    raise ValueError(
                        f"{field_name} still uses a default dev secret — "
                        f"set PHANTEX_{field_name.upper()} environment variable"
                    )
                # Catch .env.production.example placeholder values
                if isinstance(value, str) and value.startswith("CHANGE_ME"):
                    raise ValueError(
                        f"{field_name} still uses a CHANGE_ME placeholder — "
                        f"set PHANTEX_{field_name.upper()} to a real secret"
                    )
            # Vault and Redis credentials must be set in production
            if self.vault_enabled and not self.vault_role_id:
                raise ValueError(
                    "vault_role_id must be set in production when vault is enabled — set PHANTEX_VAULT_ROLE_ID"
                )
            if self.vault_enabled and not self.vault_secret_id:
                raise ValueError(
                    "vault_secret_id must be set in production when vault is enabled — set PHANTEX_VAULT_SECRET_ID"
                )
            if "localhost" in self.redis_url or "phantex-dev-redis-pw" in self.redis_url:
                raise ValueError("redis_url still uses default dev settings — set PHANTEX_REDIS_URL")
            # Prevent debug mode in production (leaks exception details)
            if self.debug:
                raise ValueError("debug must be False in production/staging — set PHANTEX_DEBUG=false")
            # Prevent SQL echo in production (logs queries with parameter values)
            if self.db_echo_sql:
                raise ValueError("db_echo_sql must be False in production/staging — set PHANTEX_DB_ECHO_SQL=false")
            # Legacy WS token auth passes JWT in URL query params (logged by
            # reverse proxies, browser history, etc.).  Must be disabled in
            # production to enforce ticket-based auth.
            if self.ws_legacy_token_enabled:
                raise ValueError(
                    "ws_legacy_token_enabled must be False in production/staging — "
                    "set PHANTEX_WS_LEGACY_TOKEN_ENABLED=false"
                )
            # Reject localhost CORS origins in production (unless explicitly allowed for on-prem)
            if not self.allow_localhost_cors:
                for origin in self.cors_origins:
                    if "localhost" in origin or "127.0.0.1" in origin:
                        raise ValueError(
                            f"CORS origin {origin!r} contains localhost — set PHANTEX_CORS_ORIGINS "
                            f"to production domain(s), or set PHANTEX_ALLOW_LOCALHOST_CORS=true "
                            f"for on-prem/lab deployments"
                        )
            # Reject plaintext database connections in production
            if self.db_ssl_mode == "disable":
                raise ValueError(
                    "db_ssl_mode must not be 'disable' in production/staging — "
                    "set PHANTEX_DB_SSL_MODE to 'require' or 'verify-full'"
                )
            # GraphQL introspection must be disabled in production
            if self.graphql_introspection_enabled:
                raise ValueError(
                    "graphql_introspection_enabled must be False in production/staging — "
                    "set PHANTEX_GRAPHQL_INTROSPECTION_ENABLED=false"
                )
            # Require asymmetric JWT signing in production (RS256/ES256)
            # Vault Transit provides RS256 signing without local key files.
            if self.jwt_algorithm.startswith("HS") and not self.vault_enabled:
                raise ValueError(
                    "jwt_algorithm must use asymmetric signing (RS256, ES256, etc.) in production — "
                    "set PHANTEX_JWT_ALGORITHM and provide key files, or enable Vault Transit via "
                    "PHANTEX_VAULT_ENABLED=true"
                )
            if self.jwt_algorithm.startswith(("RS", "ES")) and not self.vault_enabled:
                if not self.jwt_private_key_file:
                    raise ValueError(
                        "jwt_private_key_file is required for asymmetric JWT — "
                        "set PHANTEX_JWT_PRIVATE_KEY_FILE"
                    )
                if not self.jwt_public_key_file:
                    raise ValueError(
                        "jwt_public_key_file is required for asymmetric JWT — "
                        "set PHANTEX_JWT_PUBLIC_KEY_FILE"
                    )
            # Reject dev-default deception and model-signing secrets
            import os
            _decoy_pw = os.environ.get("PHANTEX_DECOY_KEY_PASSPHRASE", "")
            if not _decoy_pw or _decoy_pw == "phantex-decoy-key":
                raise ValueError(
                    "PHANTEX_DECOY_KEY_PASSPHRASE must be set to a strong secret in production"
                )
            _signing = os.environ.get("PHANTEX_SIGNING_KEY", "")
            if not _signing or _signing == "local-dev-key":
                raise ValueError(
                    "PHANTEX_SIGNING_KEY must be set to a real Ed25519 key in production"
                )
        return self

@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
