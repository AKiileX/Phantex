# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Rate Limiter (Redis-backed with in-memory fallback).

Phase 2: Uses Redis sliding window when available.
Falls back to in-memory token bucket if Redis is unavailable.
"""

import time

from fastapi import HTTPException, Request, status

from app.config import get_settings

settings = get_settings()

class TokenBucket:
    """Per-key token bucket rate limiter (in-memory fallback)."""

    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # tokens added per second
        self.capacity = capacity  # max burst size
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        """Check if a request is allowed for the given key."""
        now = time.monotonic()

        if key in self._buckets:
            tokens, last_check = self._buckets[key]
            elapsed = now - last_check
            tokens = min(self.capacity, tokens + elapsed * self.rate)
        else:
            tokens = float(self.capacity)

        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True

        self._buckets[key] = (tokens, now)
        return False

    def cleanup(self, max_age: float = 300.0) -> None:
        """Remove stale entries (call periodically)."""
        now = time.monotonic()
        stale = [k for k, (_, t) in self._buckets.items() if now - t > max_age]
        for k in stale:
            del self._buckets[k]

# Global in-memory rate limiter instances (fallback)
_rate_limiter = TokenBucket(
    rate=float(settings.rate_limit_per_second),
    capacity=settings.rate_limit_per_second * 2,  # Allow brief bursts
)

# Stricter limiter for auth endpoints (prevent brute force)
_auth_rate_limiter = TokenBucket(rate=5.0, capacity=10)

# SSO endpoints: 10 requests/min per IP (0.167/sec, burst 5) — M-4 hardening
_sso_rate_limiter = TokenBucket(rate=10.0 / 60.0, capacity=5)

# Redis rate limiter (initialized lazily in app lifespan)
_redis_rate_limiter = None
_redis_auth_rate_limiter = None
_redis_sso_rate_limiter = None

def set_redis_rate_limiters(general, auth, sso=None) -> None:
    """Set Redis-backed rate limiters. Called from main.py lifespan."""
    global _redis_rate_limiter, _redis_auth_rate_limiter, _redis_sso_rate_limiter
    _redis_rate_limiter = general
    _redis_auth_rate_limiter = auth
    _redis_sso_rate_limiter = sso

def _get_client_key(request: Request) -> str:
    """
    Extract a rate-limit key from the request (IP-based).

    We use request.client.host which is set correctly by uvicorn when
    --proxy-headers and --forwarded-allow-ips are configured. Reading
    X-Forwarded-For directly is unsafe because any client can spoof it
    to get a fresh rate-limit bucket on every request.
    """
    return request.client.host if request.client else "unknown"

async def rate_limit(request: Request) -> None:
    """
    FastAPI dependency for general rate limiting.
    Uses Redis sliding window when available, falls back to in-memory.
    Raises 429 if the client exceeds the rate limit.
    """
    key = _get_client_key(request)

    # Try Redis first
    if _redis_rate_limiter is not None:
        allowed = await _redis_rate_limiter.allow(key)
    else:
        allowed = _rate_limiter.allow(key)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
            headers={"Retry-After": "1"},
        )

async def auth_rate_limit(request: Request) -> None:
    """
    Stricter rate limiter for authentication endpoints.
    5 requests/sec per IP to prevent credential stuffing.
    """
    key = f"auth:{_get_client_key(request)}"

    # Try Redis first
    if _redis_auth_rate_limiter is not None:
        allowed = await _redis_auth_rate_limiter.allow(key)
    else:
        allowed = _auth_rate_limiter.allow(key)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Try again later.",
            headers={"Retry-After": "10"},
        )

async def sso_rate_limit(request: Request) -> None:
    """
    Rate limiter for SSO login/callback endpoints (M-4 hardening).
    10 requests/min per IP — prevents brute-force SSO token abuse.
    """
    key = f"sso:{_get_client_key(request)}"

    # Try Redis first
    if _redis_sso_rate_limiter is not None:
        allowed = await _redis_sso_rate_limiter.allow(key)
    else:
        allowed = _sso_rate_limiter.allow(key)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many SSO requests. Try again later.",
            headers={"Retry-After": "30"},
        )

# ── Periodic Cleanup ─────────────────────────────────────────────────────────

def cleanup_all(max_age: float = 300.0) -> int:
    """
    Remove stale entries from all rate limiters.

    Call this periodically (e.g. every 60s) from the app lifespan
    to prevent unbounded memory growth from abandoned client IPs.

    Returns the total number of entries removed.
    """
    before = len(_rate_limiter._buckets) + len(_auth_rate_limiter._buckets) + len(_sso_rate_limiter._buckets)
    _rate_limiter.cleanup(max_age)
    _auth_rate_limiter.cleanup(max_age)
    _sso_rate_limiter.cleanup(max_age)
    after = len(_rate_limiter._buckets) + len(_auth_rate_limiter._buckets) + len(_sso_rate_limiter._buckets)
    return before - after
