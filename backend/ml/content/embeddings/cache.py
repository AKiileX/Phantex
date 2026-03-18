# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8a — Embedding Cache.

LRU cache for embedding vectors to avoid re-encoding identical or
near-identical text.  Keyed by SHA-256 hash of the (truncated) text.

Hardening:
- Bounded size (default 50 000 entries ≈ ~75 MB at 384-dim float32).
- Not persistent — cache is ephemeral per process lifetime.
- Thread-safe via threading.Lock.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict

import numpy as np
from numpy.typing import NDArray

class EmbeddingCache:
    """LRU cache for embedding vectors.

    Parameters
    ----------
    max_size:
        Maximum number of cached embeddings.
    """

    def __init__(self, max_size: int = 50_000) -> None:
        self._max_size = max(1, max_size)
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, NDArray[np.floating]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, text: str) -> NDArray[np.floating] | None:
        """Return cached embedding or None."""
        key = self._key(text)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return None

    def put(self, text: str, embedding: NDArray[np.floating]) -> None:
        """Store an embedding in the cache."""
        key = self._key(text)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = embedding
                return

            self._cache[key] = embedding

            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached embeddings."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """Cache hit rate as a float in [0, 1]."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict[str, int | float]:
        return {
            "size": self.size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 4),
            "max_size": self._max_size,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _key(text: str) -> str:
        """SHA-256 hash of the text (deterministic, collision-resistant)."""
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
