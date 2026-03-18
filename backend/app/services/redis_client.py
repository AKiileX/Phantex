# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Redis Client & Utilities.

Provides:
  - Async Redis connection pool (via redis-py with asyncio)
  - Health check
  - Graceful shutdown

Configuration:
    PHANTEX_REDIS_URL=redis://localhost:6379/0
    PHANTEX_REDIS_TLS_ENABLED=false
    PHANTEX_REDIS_TLS_CERT_FILE=
    PHANTEX_REDIS_TLS_KEY_FILE=
    PHANTEX_REDIS_TLS_CA_FILE=
"""

from __future__ import annotations

import ssl

import structlog

logger = structlog.get_logger("phantex.services.redis")

# Lazy-init Redis instance
_redis_client = None

async def get_redis():
    """Get the shared async Redis client. Creates on first call."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.warning("redis_not_installed", msg="redis[asyncio] not installed. Redis features disabled.")
        return None

    from app.config import get_settings

    settings = get_settings()

    ssl_ctx: ssl.SSLContext | None = None
    if settings.redis_tls_enabled:
        ssl_ctx = ssl.create_default_context()
        if settings.redis_tls_ca_file:
            ssl_ctx.load_verify_locations(settings.redis_tls_ca_file)
        if settings.redis_tls_cert_file and settings.redis_tls_key_file:
            ssl_ctx.load_cert_chain(settings.redis_tls_cert_file, settings.redis_tls_key_file)

    kwargs = {
        "decode_responses": True,
        "max_connections": 20,
        "socket_timeout": 5.0,
        "socket_connect_timeout": 5.0,
        "retry_on_timeout": True,
    }
    if ssl_ctx:
        kwargs["ssl"] = ssl_ctx

    _redis_client = aioredis.from_url(
        settings.redis_url,
        **kwargs,
    )

    logger.info("redis_connected", url=_mask_url(settings.redis_url))
    return _redis_client

async def close_redis() -> None:
    """Close the Redis connection pool. Call during app shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
        logger.info("redis_closed")

async def check_redis_health() -> bool:
    """Quick health check — can we PING Redis?"""
    try:
        client = await get_redis()
        if client is None:
            return False
        return await client.ping()
    except Exception:
        return False

def _mask_url(url: str) -> str:
    """Mask password in Redis URL for logging."""
    if "@" in url:
        # redis://:password@host:port/db → redis://***@host:port/db
        parts = url.split("@", 1)
        return f"redis://***@{parts[1]}"
    return url
