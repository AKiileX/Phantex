# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Rate Limiter (JB6 Hardening).

In-memory, per-tenant sliding-window rate limiter that caps how many
content-analysis events are processed per second.

Design choices:
  - Token-bucket algorithm (simple, well-understood)
  - Per-tenant isolation — one noisy tenant cannot starve others
  - Bounded memory — evicts LRU tenants when limit is reached
  - Thread-safe (stdlib Lock)
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

@dataclass
class _Bucket:
    """Token-bucket state for one tenant."""

    tokens: float
    last_refill: float  # monotonic timestamp
    capacity: float
    rate: float  # tokens per second

class ContentRateLimiter:
    """Per-tenant token-bucket rate limiter.

    Parameters
    ----------
    rate:
        Maximum events per second per tenant (default 10 000).
    burst:
        Maximum burst capacity (default = rate, so 1 second burst).
    max_tenants:
        Maximum tracked tenants before LRU eviction (default 10 000).
    """

    def __init__(
        self,
        rate: float = 10_000,
        burst: float | None = None,
        max_tenants: int = 10_000,
    ):
        self._rate = rate
        self._burst = burst if burst is not None else rate
        self._max_tenants = max_tenants
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def allow(self, tenant_id: str, tokens: int = 1) -> bool:
        """Return True if the request is within the rate limit.

        Consumes ``tokens`` from the tenant's bucket on success.
        """
        with self._lock:
            bucket = self._get_or_create(tenant_id)
            self._refill(bucket)

            if bucket.tokens >= tokens:
                bucket.tokens -= tokens
                # Move to end (most recently used)
                self._buckets.move_to_end(tenant_id)
                return True

            return False

    def remaining(self, tenant_id: str) -> float:
        """Return approximate remaining tokens for a tenant."""
        with self._lock:
            bucket = self._buckets.get(tenant_id)
            if bucket is None:
                return self._burst
            self._refill(bucket)
            return bucket.tokens

    def reset(self, tenant_id: str | None = None) -> None:
        """Reset rate limiter state.

        If ``tenant_id`` is provided, reset only that tenant.
        Otherwise reset all tenants.
        """
        with self._lock:
            if tenant_id is None:
                self._buckets.clear()
            else:
                self._buckets.pop(tenant_id, None)

    @property
    def tenant_count(self) -> int:
        """Number of currently tracked tenants."""
        return len(self._buckets)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_or_create(self, tenant_id: str) -> _Bucket:
        bucket = self._buckets.get(tenant_id)
        if bucket is not None:
            return bucket

        # Evict LRU if at capacity
        while len(self._buckets) >= self._max_tenants:
            self._buckets.popitem(last=False)

        bucket = _Bucket(
            tokens=self._burst,
            last_refill=time.monotonic(),
            capacity=self._burst,
            rate=self._rate,
        )
        self._buckets[tenant_id] = bucket
        return bucket

    def _refill(self, bucket: _Bucket) -> None:
        now = time.monotonic()
        elapsed = now - bucket.last_refill
        if elapsed > 0:
            bucket.tokens = min(
                bucket.capacity,
                bucket.tokens + elapsed * bucket.rate,
            )
            bucket.last_refill = now
