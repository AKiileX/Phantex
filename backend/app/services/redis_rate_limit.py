# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Redis-backed Sliding Window Rate Limiter.

Replaces the in-memory TokenBucket with a Redis-backed sliding window
counter. Benefits:
  - Survives process restarts
  - Shared across multiple backend workers
  - Accurate sliding window (not fixed window)

If Redis is unavailable, falls back to the in-memory TokenBucket.
"""

from __future__ import annotations

import time

import structlog

logger = structlog.get_logger("phantex.services.redis_rate_limit")

# Lua script for atomic sliding window rate limiting
# KEYS[1] = rate limit key
# ARGV[1] = window size in seconds
# ARGV[2] = max requests in window
# ARGV[3] = current timestamp (seconds, float)
# Returns: 1 if allowed, 0 if rejected
_SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Remove entries outside the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add this request
    redis.call('ZADD', key, now, now .. ':' .. redis.call('INCR', KEYS[1] .. ':seq'))
    -- Set TTL to window + 1 for auto-cleanup
    redis.call('EXPIRE', key, math.ceil(window) + 1)
    return 1
else
    return 0
end
"""

class RedisSlidingWindowLimiter:
    """
    Redis-backed sliding window rate limiter.

    Uses a sorted set per key with timestamps as scores.
    Atomic via Lua script.
    """

    def __init__(
        self,
        redis_client,
        *,
        rate: float = 100.0,
        window_seconds: float = 1.0,
        key_prefix: str = "rl:",
    ) -> None:
        self._redis = redis_client
        self._rate = rate  # max requests per window
        self._window = window_seconds
        self._key_prefix = key_prefix
        self._script_sha: str | None = None

    async def _ensure_script(self) -> str:
        """Load the Lua script into Redis (cached via SHA)."""
        if self._script_sha is None:
            self._script_sha = await self._redis.script_load(_SLIDING_WINDOW_SCRIPT)
        return self._script_sha

    async def allow(self, key: str) -> bool:
        """
        Check if a request is allowed.

        Args:
            key: Rate limit key (e.g., IP address, user ID)

        Returns:
            True if allowed, False if rate limited
        """
        try:
            sha = await self._ensure_script()
            result = await self._redis.evalsha(
                sha,
                1,
                f"{self._key_prefix}{key}",
                str(self._window),
                str(int(self._rate)),
                str(time.time()),
            )
            return result == 1
        except Exception as e:
            # Redis failure — allow the request (fail-open)
            logger.warning("redis_rate_limit_error", error=str(e), key=key)
            return True

    async def get_remaining(self, key: str) -> int:
        """Get remaining requests in current window."""
        try:
            full_key = f"{self._key_prefix}{key}"
            now = time.time()
            await self._redis.zremrangebyscore(full_key, "-inf", now - self._window)
            count = await self._redis.zcard(full_key)
            return max(0, int(self._rate) - count)
        except Exception:
            return int(self._rate)

class RedisWSTicketStore:
    """
    Redis-backed WebSocket ticket store.

    Replaces the in-memory WSTicketStore for multi-worker deployments.
    Tickets are stored as Redis keys with TTL for auto-expiry.
    """

    def __init__(
        self,
        redis_client,
        *,
        ttl_seconds: int = 30,
        key_prefix: str = "ws_ticket:",
        max_pending: int = 10_000,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._key_prefix = key_prefix
        self._max_pending = max_pending

    async def create_ticket(
        self,
        ticket: str,
        tenant_id: str,
        user_id: str,
        role: str,
    ) -> bool:
        """
        Store a ticket in Redis with TTL.

        Returns True if stored, False if too many pending.
        """
        import json

        key = f"{self._key_prefix}{ticket}"

        try:
            # Enforce max pending tickets via atomic counter
            counter_key = f"{self._key_prefix}_count"
            count = await self._redis.incr(counter_key)
            if count == 1:
                # First ticket — set counter TTL to match ticket TTL
                await self._redis.expire(counter_key, self._ttl + 5)
            if count > self._max_pending:
                await self._redis.decr(counter_key)
                logger.warning("redis_ticket_max_pending", count=count, max=self._max_pending)
                return False

            data = json.dumps(
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "role": role,
                }
            )
            # SET with NX (only if not exists) + EX (TTL)
            result = await self._redis.set(key, data, ex=self._ttl, nx=True)
            if result is None:
                # Ticket already exists (collision) — decrement counter
                await self._redis.decr(counter_key)
            return result is not None
        except Exception as e:
            logger.warning("redis_ticket_create_error", error=str(e))
            return False

    async def consume_ticket(self, ticket: str) -> dict | None:
        """
        Consume a ticket (single-use). Returns ticket data or None.
        Uses GETDEL for atomicity. Decrements pending counter on success.
        """
        import json

        key = f"{self._key_prefix}{ticket}"
        try:
            # GETDEL: get and delete atomically (Redis 6.2+)
            data = await self._redis.getdel(key)
            if data is None:
                return None
            # Decrement pending counter so create_ticket() stays accurate
            counter_key = f"{self._key_prefix}_count"
            await self._redis.decr(counter_key)
            try:
                return json.loads(data)
            except (json.JSONDecodeError, TypeError):
                logger.warning("redis_ticket_corrupt_data", ticket=ticket[:8])
                return None
        except Exception as e:
            logger.warning("redis_ticket_consume_error", error=str(e))
            return None
