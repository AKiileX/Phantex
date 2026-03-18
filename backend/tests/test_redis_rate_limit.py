# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for backend/app/services/redis_rate_limit.py

Covers:
  - RedisSlidingWindowLimiter: allow, get_remaining, script caching,
    fail-open on Redis error
  - RedisWSTicketStore: create_ticket, consume_ticket (single-use),
    max_pending enforcement, counter decrement, collision handling,
    Redis error handling
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from app.services.redis_rate_limit import (
    _SLIDING_WINDOW_SCRIPT,
    RedisSlidingWindowLimiter,
    RedisWSTicketStore,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_redis() -> AsyncMock:
    """Create a mock async Redis client."""
    r = AsyncMock()
    r.script_load = AsyncMock(return_value="fake-sha-256")
    r.evalsha = AsyncMock(return_value=1)
    r.zremrangebyscore = AsyncMock()
    r.zcard = AsyncMock(return_value=0)
    r.incr = AsyncMock(return_value=1)
    r.decr = AsyncMock()
    r.expire = AsyncMock()
    r.set = AsyncMock(return_value=True)
    r.getdel = AsyncMock(return_value=None)
    return r

# ── RedisSlidingWindowLimiter ────────────────────────────────────────────────

class TestRedisSlidingWindowLimiter:
    @pytest.mark.asyncio
    async def test_allow_loads_script_once(self):
        redis = _mock_redis()
        limiter = RedisSlidingWindowLimiter(redis, rate=100, window_seconds=1.0)

        await limiter.allow("key1")
        await limiter.allow("key2")

        # Script should be loaded only once
        redis.script_load.assert_called_once_with(_SLIDING_WINDOW_SCRIPT)
        # evalsha called twice
        assert redis.evalsha.call_count == 2

    @pytest.mark.asyncio
    async def test_allow_returns_true_when_allowed(self):
        redis = _mock_redis()
        redis.evalsha = AsyncMock(return_value=1)
        limiter = RedisSlidingWindowLimiter(redis, rate=10, window_seconds=1.0)

        assert await limiter.allow("192.168.1.1") is True

    @pytest.mark.asyncio
    async def test_allow_returns_false_when_rejected(self):
        redis = _mock_redis()
        redis.evalsha = AsyncMock(return_value=0)
        limiter = RedisSlidingWindowLimiter(redis, rate=10, window_seconds=1.0)

        assert await limiter.allow("192.168.1.1") is False

    @pytest.mark.asyncio
    async def test_allow_fail_open_on_redis_error(self):
        redis = _mock_redis()
        redis.evalsha = AsyncMock(side_effect=ConnectionError("Redis down"))
        # script_load also needed for first call
        limiter = RedisSlidingWindowLimiter(redis, rate=10, window_seconds=1.0)
        limiter._script_sha = "fake-sha"  # pretend script already loaded

        # Should return True (fail-open)
        assert await limiter.allow("key") is True

    @pytest.mark.asyncio
    async def test_allow_passes_correct_args(self):
        redis = _mock_redis()
        limiter = RedisSlidingWindowLimiter(redis, rate=50.0, window_seconds=10.0, key_prefix="rl:")

        await limiter.allow("test-key")

        call_args = redis.evalsha.call_args
        # evalsha(sha, numkeys, key, window, limit, now)
        assert call_args[0][0] == "fake-sha-256"  # SHA
        assert call_args[0][1] == 1  # numkeys
        assert call_args[0][2] == "rl:test-key"  # full key
        assert call_args[0][3] == "10.0"  # window
        assert call_args[0][4] == "50"  # limit (int)

    @pytest.mark.asyncio
    async def test_get_remaining_full_capacity(self):
        redis = _mock_redis()
        redis.zcard = AsyncMock(return_value=0)
        limiter = RedisSlidingWindowLimiter(redis, rate=100, window_seconds=1.0)

        remaining = await limiter.get_remaining("key")
        assert remaining == 100

    @pytest.mark.asyncio
    async def test_get_remaining_partial(self):
        redis = _mock_redis()
        redis.zcard = AsyncMock(return_value=30)
        limiter = RedisSlidingWindowLimiter(redis, rate=100, window_seconds=1.0)

        remaining = await limiter.get_remaining("key")
        assert remaining == 70

    @pytest.mark.asyncio
    async def test_get_remaining_exhausted(self):
        redis = _mock_redis()
        redis.zcard = AsyncMock(return_value=150)
        limiter = RedisSlidingWindowLimiter(redis, rate=100, window_seconds=1.0)

        remaining = await limiter.get_remaining("key")
        assert remaining == 0  # clamped to 0

    @pytest.mark.asyncio
    async def test_get_remaining_redis_error_returns_full(self):
        redis = _mock_redis()
        redis.zremrangebyscore = AsyncMock(side_effect=ConnectionError("down"))
        limiter = RedisSlidingWindowLimiter(redis, rate=100, window_seconds=1.0)

        remaining = await limiter.get_remaining("key")
        assert remaining == 100

# ── Lua Script Validation ────────────────────────────────────────────────────

class TestLuaScript:
    def test_script_uses_incr_not_random(self):
        """Ensure collision-resistant INCR is used, not math.random"""
        assert "math.random" not in _SLIDING_WINDOW_SCRIPT
        assert "INCR" in _SLIDING_WINDOW_SCRIPT

    def test_script_has_zremrangebyscore(self):
        """Sliding window must prune old entries"""
        assert "ZREMRANGEBYSCORE" in _SLIDING_WINDOW_SCRIPT

    def test_script_sets_expire(self):
        """Auto-cleanup TTL on sorted set"""
        assert "EXPIRE" in _SLIDING_WINDOW_SCRIPT

# ── RedisWSTicketStore ───────────────────────────────────────────────────────

class TestRedisWSTicketStore:
    @pytest.mark.asyncio
    async def test_create_ticket_success(self):
        redis = _mock_redis()
        redis.incr = AsyncMock(return_value=1)
        redis.set = AsyncMock(return_value=True)
        store = RedisWSTicketStore(redis, ttl_seconds=30, max_pending=100)

        result = await store.create_ticket("ticket-abc", "tenant-1", "user-1", "admin")

        assert result is True
        redis.set.assert_called_once()
        call_args = redis.set.call_args
        assert call_args[0][0] == "ws_ticket:ticket-abc"
        # Verify data structure
        data = json.loads(call_args[0][1])
        assert data == {"tenant_id": "tenant-1", "user_id": "user-1", "role": "admin"}

    @pytest.mark.asyncio
    async def test_create_ticket_max_pending_rejected(self):
        redis = _mock_redis()
        redis.incr = AsyncMock(return_value=10001)
        store = RedisWSTicketStore(redis, ttl_seconds=30, max_pending=10_000)

        result = await store.create_ticket("ticket-xyz", "tenant-1", "user-1", "admin")

        assert result is False
        redis.decr.assert_called_once()  # counter decremented
        redis.set.assert_not_called()  # ticket not stored

    @pytest.mark.asyncio
    async def test_create_ticket_collision_decrements_counter(self):
        redis = _mock_redis()
        redis.incr = AsyncMock(return_value=5)
        redis.set = AsyncMock(return_value=None)  # NX failed — collision
        store = RedisWSTicketStore(redis, ttl_seconds=30, max_pending=100)

        result = await store.create_ticket("ticket-dup", "tenant-1", "user-1", "admin")

        assert result is False
        redis.decr.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_ticket_first_sets_counter_ttl(self):
        redis = _mock_redis()
        redis.incr = AsyncMock(return_value=1)  # First ticket
        redis.set = AsyncMock(return_value=True)
        store = RedisWSTicketStore(redis, ttl_seconds=30, max_pending=100)

        await store.create_ticket("ticket-first", "tenant-1", "user-1", "admin")

        # Counter TTL should be set (ttl + 5)
        redis.expire.assert_called_once()
        ttl_arg = redis.expire.call_args[0][1]
        assert ttl_arg == 35  # 30 + 5

    @pytest.mark.asyncio
    async def test_create_ticket_redis_error_returns_false(self):
        redis = _mock_redis()
        redis.incr = AsyncMock(side_effect=ConnectionError("Redis down"))
        store = RedisWSTicketStore(redis, ttl_seconds=30, max_pending=100)

        result = await store.create_ticket("ticket-err", "tenant-1", "user-1", "admin")
        assert result is False

    @pytest.mark.asyncio
    async def test_consume_ticket_success(self):
        redis = _mock_redis()
        ticket_data = json.dumps({"tenant_id": "t-1", "user_id": "u-1", "role": "admin"})
        redis.getdel = AsyncMock(return_value=ticket_data)
        store = RedisWSTicketStore(redis, ttl_seconds=30)

        result = await store.consume_ticket("ticket-valid")

        assert result == {"tenant_id": "t-1", "user_id": "u-1", "role": "admin"}
        redis.getdel.assert_called_once_with("ws_ticket:ticket-valid")
        # Counter should be decremented
        redis.decr.assert_called_once()

    @pytest.mark.asyncio
    async def test_consume_ticket_not_found(self):
        redis = _mock_redis()
        redis.getdel = AsyncMock(return_value=None)
        store = RedisWSTicketStore(redis, ttl_seconds=30)

        result = await store.consume_ticket("ticket-missing")

        assert result is None
        redis.decr.assert_not_called()  # No decrement for missing ticket

    @pytest.mark.asyncio
    async def test_consume_ticket_single_use(self):
        """Second consume of same ticket returns None (GETDEL atomicity)."""
        redis = _mock_redis()
        ticket_data = json.dumps({"tenant_id": "t-1", "user_id": "u-1", "role": "admin"})
        redis.getdel = AsyncMock(side_effect=[ticket_data, None])
        store = RedisWSTicketStore(redis, ttl_seconds=30)

        first = await store.consume_ticket("ticket-once")
        second = await store.consume_ticket("ticket-once")

        assert first is not None
        assert second is None

    @pytest.mark.asyncio
    async def test_consume_ticket_redis_error_returns_none(self):
        redis = _mock_redis()
        redis.getdel = AsyncMock(side_effect=ConnectionError("Redis down"))
        store = RedisWSTicketStore(redis, ttl_seconds=30)

        result = await store.consume_ticket("ticket-err")
        assert result is None
