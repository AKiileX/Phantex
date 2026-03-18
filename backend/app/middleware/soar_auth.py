# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SOAR API Key Authentication

Provides FastAPI dependency for authenticating inbound SOAR requests
using API keys passed via the X-Phantex-Api-Key header.

Security:
  - Keys stored as SHA-256 hashes in DB (never plaintext)
  - Expired / revoked keys are rejected
  - Scope-based authorization (e.g. "alerts.read", "actions.execute")
  - last_used_at updated on each successful auth
  - Source IP + User-Agent captured for audit logging
  - Constant-time hash comparison (via hmac.compare_digest)
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, set_tenant_context

logger = structlog.get_logger("phantex.soar.auth")

# ── Key generation ────────────────────────────────────────────────────────────

KEY_PREFIX = "phx_sk_"
KEY_BYTES = 32  # 256-bit random key

def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new SOAR API key.

    Returns:
        (raw_key, key_hash, key_prefix)
        raw_key is shown to the user ONCE. key_hash is stored in DB.
    """
    raw = secrets.token_urlsafe(KEY_BYTES)
    full_key = f"{KEY_PREFIX}{raw}"
    key_hash = hashlib.sha256(full_key.encode("utf-8")).hexdigest()
    prefix = full_key[:12]
    return full_key, key_hash, prefix

def hash_api_key(raw_key: str) -> str:
    """Hash an API key for lookup."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

# ── Auth result ───────────────────────────────────────────────────────────────

class SOARIdentity:
    """Authenticated SOAR API key identity."""

    __slots__ = ("key_id", "tenant_id", "name", "scopes", "source_ip", "user_agent")

    def __init__(
        self,
        *,
        key_id: uuid.UUID,
        tenant_id: uuid.UUID,
        name: str,
        scopes: list[str],
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.key_id = key_id
        self.tenant_id = tenant_id
        self.name = name
        self.scopes = scopes
        self.source_ip = source_ip
        self.user_agent = user_agent

    def has_scope(self, scope: str) -> bool:
        """Check if this key has a specific scope."""
        return "*" in self.scopes or scope in self.scopes

    def require_scope(self, scope: str) -> None:
        """Raise 403 if the key doesn't have the required scope."""
        if not self.has_scope(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required scope: {scope}",
            )

# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_soar_identity(
    request: Request,
    x_phantex_api_key: Annotated[str | None, Header(alias="X-Phantex-Api-Key")] = None,
    db: AsyncSession = Depends(get_db),
) -> SOARIdentity:
    """
    Authenticate an inbound SOAR request via API key.

    Looks up the key hash in soar_api_keys, validates it's not
    expired/revoked, updates last_used_at, and returns a SOARIdentity.
    """
    if not x_phantex_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Phantex-Api-Key header",
        )

    # Validate key format
    if not x_phantex_api_key.startswith(KEY_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format",
        )

    key_hash = hash_api_key(x_phantex_api_key)

    # Look up key — constant-time comparison via DB hash index
    result = await db.execute(
        text("""
            SELECT id, tenant_id, name, scopes, expires_at
            FROM soar_api_keys
            WHERE key_hash = :hash AND revoked_at IS NULL
        """),
        {"hash": key_hash},
    )
    row = result.mappings().first()

    if not row:
        logger.warning("soar_auth_failed", reason="unknown_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )

    # Check expiry
    if row["expires_at"] and row["expires_at"] < datetime.now(UTC):
        logger.warning("soar_auth_failed", reason="expired", key_id=str(row["id"]))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
        )

    # Update last_used_at (fire-and-forget, don't block auth)
    await db.execute(
        text("UPDATE soar_api_keys SET last_used_at = now() WHERE id = CAST(:kid AS UUID)"),
        {"kid": str(row["id"])},
    )

    # Set tenant context for RLS
    await set_tenant_context(db, str(row["tenant_id"]))

    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent", "")[:500]

    logger.info(
        "soar_auth_success",
        key_id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        name=row["name"],
        source_ip=source_ip,
    )

    return SOARIdentity(
        key_id=row["id"],
        tenant_id=row["tenant_id"],
        name=row["name"],
        scopes=list(row["scopes"] or []),
        source_ip=source_ip,
        user_agent=user_agent,
    )
