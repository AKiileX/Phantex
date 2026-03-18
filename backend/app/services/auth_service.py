# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Auth Service.

Handles JWT creation/validation, password verification, refresh token management,
per-email rate limiting, and account lockout.
"""

import hashlib
import secrets
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import bcrypt
import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.audit import RefreshToken
from app.models.user import User
from app.schemas.auth import TokenPayload, TokenResponse
from app.utils.logging import get_logger

logger = get_logger("phantex.services.auth")
settings = get_settings()

# ── Vault Transit JWT Signing ─────────────────────────────────────────────────
# When vault_enabled=True, JWTs are signed via Vault Transit (RS256).
# The private key never leaves the Vault HSM boundary.
# Verification uses the cached public key fetched at startup.

_vault_jwt_signer = None   # VaultJWTSigner instance (set during startup)
_vault_public_key_pem: bytes | None = None  # Cached PEM for local verification

async def init_vault_jwt_signer() -> None:
    """Initialize Vault Transit JWT signing. Call during app startup."""
    global _vault_jwt_signer, _vault_public_key_pem

    if not settings.vault_enabled:
        logger.info("vault_jwt_disabled", msg="Using local JWT signing")
        return

    from app.services.vault_client import VaultClient, VaultJWTSigner

    vault = VaultClient(
        addr=settings.vault_addr,
        role_id=settings.vault_role_id,
        secret_id=settings.vault_secret_id,
        token=settings.vault_token,
    )
    signer = VaultJWTSigner(vault, key_name=settings.vault_jwt_key_name)

    # Fetch and cache public key for efficient local verification
    pem = await signer.get_public_key_pem()
    _vault_public_key_pem = pem.encode("utf-8") if isinstance(pem, str) else pem
    _vault_jwt_signer = signer

    # Clear cached verification key so next call picks up the Vault public key
    get_jwt_verification_key.cache_clear()

    logger.info(
        "vault_jwt_initialized",
        key=settings.vault_jwt_key_name,
        algorithm="RS256",
    )

async def close_vault_jwt_signer() -> None:
    """Clean up Vault JWT signer resources. Call during app shutdown."""
    global _vault_jwt_signer, _vault_public_key_pem
    if _vault_jwt_signer is not None:
        await _vault_jwt_signer._vault.close()
        _vault_jwt_signer = None
        _vault_public_key_pem = None

def get_effective_jwt_algorithm() -> str:
    """Return the effective JWT algorithm (RS256 when Vault Transit is active)."""
    if _vault_jwt_signer is not None:
        return "RS256"
    return settings.jwt_algorithm

# ── Per-Email Login Rate Limiting ─────────────────────────────────────────────
# Tracks login attempts per email: {email: [(timestamp, success)]}
# 5 attempts per minute per email (C3 spec requirement)

MAX_LOGIN_ATTEMPTS_PER_MINUTE = 5
ACCOUNT_LOCKOUT_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION_MINUTES = 15

_email_attempts: dict[str, list[float]] = defaultdict(list)

def _check_email_rate_limit(email: str) -> bool:
    """
    Check if an email has exceeded the per-email login rate limit.
    Returns True if allowed, False if rate-limited.
    Cleans up entries older than 60 seconds.
    """
    now = time.monotonic()
    cutoff = now - 60.0

    # Clean stale entries
    attempts = _email_attempts[email]
    _email_attempts[email] = [t for t in attempts if t > cutoff]

    if len(_email_attempts[email]) >= MAX_LOGIN_ATTEMPTS_PER_MINUTE:
        return False

    _email_attempts[email].append(now)
    return True

def cleanup_email_attempts(max_age: float = 300.0) -> int:
    """
    Remove stale entries from _email_attempts to prevent unbounded growth.
    Call periodically (e.g. every 60s) from the app lifespan.
    Returns the number of keys removed.
    """
    now = time.monotonic()
    cutoff = now - max_age
    stale_keys = [k for k, v in _email_attempts.items() if not v or max(v) < cutoff]
    for k in stale_keys:
        del _email_attempts[k]
    return len(stale_keys)

# ── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password with bcrypt cost 12."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False

# ── JWT Tokens ────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def get_jwt_signing_key() -> str | bytes:
    """Return the key used to sign JWTs (private key for RS*/ES*, secret for HS*)."""
    if settings.jwt_algorithm.startswith(("RS", "ES")):
        if not settings.jwt_private_key_file:
            raise RuntimeError(
                f"jwt_private_key_file is required for {settings.jwt_algorithm} — "
                "set PHANTEX_JWT_PRIVATE_KEY_FILE"
            )
        key_path = Path(settings.jwt_private_key_file)
        if not key_path.is_file():
            raise RuntimeError(f"JWT private key file not found: {key_path}")
        return key_path.read_bytes()
    return settings.jwt_secret

@lru_cache(maxsize=1)
def get_jwt_verification_key() -> str | bytes:
    """Return the key used to verify JWTs (Vault PEM, public key for RS*/ES*, or secret for HS*)."""
    # Vault Transit: use cached public key fetched at startup
    if _vault_public_key_pem is not None:
        return _vault_public_key_pem
    if settings.jwt_algorithm.startswith(("RS", "ES")):
        if not settings.jwt_public_key_file:
            raise RuntimeError(
                f"jwt_public_key_file is required for {settings.jwt_algorithm} — "
                "set PHANTEX_JWT_PUBLIC_KEY_FILE"
            )
        key_path = Path(settings.jwt_public_key_file)
        if not key_path.is_file():
            raise RuntimeError(f"JWT public key file not found: {key_path}")
        return key_path.read_bytes()
    return settings.jwt_secret

async def create_access_token(user_id: uuid.UUID, tenant_id: uuid.UUID, role: str, *, must_change_password: bool = False) -> str:
    """Create a short-lived JWT access token (15 min default)."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "role": role,
        "mcp": must_change_password,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_access_token_expire_minutes)).timestamp()),
    }
    # Vault Transit: sign via Vault (private key never leaves HSM boundary)
    if _vault_jwt_signer is not None:
        return await _vault_jwt_signer.sign_jwt(payload)
    # Fallback: local PyJWT signing
    return jwt.encode(payload, get_jwt_signing_key(), algorithm=settings.jwt_algorithm)

def decode_access_token(token: str) -> TokenPayload:
    """Decode and validate a JWT access token."""
    payload = jwt.decode(
        token,
        get_jwt_verification_key(),
        algorithms=[get_effective_jwt_algorithm()],
        options={"require": ["sub", "tenant_id", "role", "exp", "iat"]},
    )
    return TokenPayload(**payload)

# ── Refresh Tokens ────────────────────────────────────────────────────────────

def _hash_refresh_token(token: str) -> str:
    """SHA-256 hash of a refresh token (stored in DB instead of raw token)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

async def create_token_pair(db: AsyncSession, user: User) -> TokenResponse:
    """
    Create an access + refresh token pair.

    The refresh token is a cryptographically random string.
    Only its SHA-256 hash is stored in the database.
    """
    access_token = await create_access_token(
        user.id, user.tenant_id, user.role,
        must_change_password=getattr(user, "must_change_password", False),
    )
    refresh_token_raw = secrets.token_urlsafe(48)
    refresh_token_hash = _hash_refresh_token(refresh_token_raw)

    expires_at = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)

    db_token = RefreshToken(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=refresh_token_hash,
        expires_at=expires_at,
    )
    db.add(db_token)
    await db.flush()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_raw,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
        must_change_password=getattr(user, "must_change_password", False),
    )

async def refresh_token_pair(db: AsyncSession, refresh_token_raw: str) -> TokenResponse | None:
    """
    Rotate a refresh token: validate the old one, revoke it, issue new pair.

    Returns None if the refresh token is invalid or expired.
    Single-use: the old token is revoked after the new one is created.
    """
    token_hash = _hash_refresh_token(refresh_token_raw)

    # Row-level lock (SELECT ... FOR UPDATE) prevents TOCTOU race where two
    # concurrent requests with the same refresh token both read the unrevoked
    # row before either commits revocation.
    result = await db.execute(
        select(RefreshToken)
        .where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,  # noqa: E712
            RefreshToken.expires_at > datetime.now(UTC),
        )
        .with_for_update()
    )
    db_token = result.scalar_one_or_none()

    if db_token is None:
        # Check if this is a *revoked* token being replayed (token theft indicator).
        # Per RFC 6819 §5.2.2.3: if a previously-used refresh token is presented
        # again, revoke ALL tokens for that user as a defensive measure.
        revoked_result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked == True,  # noqa: E712
            )
        )
        revoked_token = revoked_result.scalar_one_or_none()
        if revoked_token is not None:
            await revoke_all_refresh_tokens(db, revoked_token.user_id)
            await db.commit()
            logger.warning(
                "refresh_token_reuse_detected",
                user_id=str(revoked_token.user_id),
                hint="All refresh tokens revoked — possible token theft",
            )
        return None

    # Revoke the old token (single-use)
    db_token.revoked = True

    # Load the user for the new token pair
    user_result = await db.execute(
        select(User).where(User.id == db_token.user_id, User.is_active == True)  # noqa: E712
    )
    user = user_result.scalar_one_or_none()

    if user is None:
        return None

    # Create new pair
    return await create_token_pair(db, user)

async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    """
    Authenticate a user by email + password.

    Includes:
    - Per-email rate limiting (5 attempts/minute)
    - Account lockout (5 consecutive failures → 15-min lock)
    - Constant-time comparison to prevent timing attacks

    Returns the User if valid, None otherwise.
    Raises ValueError with specific message for rate limit or lockout.
    NOTE: This query does NOT use RLS (needs to check across tenants by email).
    The caller should use a session without tenant context set.
    """
    # Normalize email case before both the rate-limit key lookup and DB query
    # to prevent inconsistencies between rate-limiting and authentication.
    normalized_email = email.strip().lower()

    # Per-email rate limit (5 attempts per minute)
    if not _check_email_rate_limit(normalized_email):
        raise ValueError("rate_limited")

    result = await db.execute(
        select(User).where(User.email == normalized_email, User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()

    if user is None:
        # Constant-time comparison to prevent timing attacks.
        # Use a pre-computed dummy hash (not gensalt which returns a salt, not a hash).
        _DUMMY_HASH = b"$2b$12$LJ3m4ys3Lz0SuYfP1HRnieGBKOliBFnUhFKjMzYTs.wBlhCOmRxa6"
        bcrypt.checkpw(b"dummy", _DUMMY_HASH)
        return None

    # Check account lockout BEFORE password check.
    # Return None (not raise) to prevent status-code oracle — the router
    # always sees None → 401 "Invalid credentials" regardless of whether
    # the account is locked, doesn't exist, or the password is wrong.
    if user.locked_until is not None and user.locked_until > datetime.now(UTC):
        # Still do constant-time password check to prevent timing oracle
        verify_password(password, user.password_hash)
        return None

    if not verify_password(password, user.password_hash):
        # Increment failed attempts
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        # Lock account after too many failures
        if user.failed_login_attempts >= ACCOUNT_LOCKOUT_ATTEMPTS:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=ACCOUNT_LOCKOUT_DURATION_MINUTES)

        # Commit lockout state now — the caller will raise HTTPException
        # which triggers session rollback, so we must persist first.
        await db.commit()
        return None

    # Successful login — reset lockout state
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(UTC)
    return user

async def revoke_all_refresh_tokens(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Revoke all refresh tokens for a user (used on password change/logout all)."""
    result = await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked == False)  # noqa: E712
        .values(revoked=True)
    )
    return result.rowcount
