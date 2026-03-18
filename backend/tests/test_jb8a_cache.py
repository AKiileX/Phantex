# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB8a — Embedding Cache."""

import numpy as np
import pytest

from ml.content.embeddings.cache import EmbeddingCache

@pytest.fixture
def cache():
    return EmbeddingCache(max_size=100)

class TestCacheBasics:
    def test_empty_cache(self, cache):
        assert cache.size == 0

    def test_put_and_get(self, cache):
        vec = np.random.rand(384).astype(np.float32)
        cache.put("test text", vec)
        result = cache.get("test text")
        assert result is not None
        assert np.allclose(result, vec)

    def test_miss_returns_none(self, cache):
        assert cache.get("nonexistent") is None

    def test_size_increases(self, cache):
        cache.put("a", np.zeros(384, dtype=np.float32))
        cache.put("b", np.zeros(384, dtype=np.float32))
        assert cache.size == 2

    def test_overwrite_same_key(self, cache):
        v1 = np.ones(384, dtype=np.float32)
        v2 = np.ones(384, dtype=np.float32) * 2
        cache.put("key", v1)
        cache.put("key", v2)
        assert cache.size == 1
        assert np.allclose(cache.get("key"), v2)

class TestCacheLRU:
    def test_evicts_oldest(self):
        cache = EmbeddingCache(max_size=3)
        cache.put("a", np.zeros(384, dtype=np.float32))
        cache.put("b", np.zeros(384, dtype=np.float32))
        cache.put("c", np.zeros(384, dtype=np.float32))
        cache.put("d", np.zeros(384, dtype=np.float32))
        # "a" should be evicted
        assert cache.get("a") is None
        assert cache.get("d") is not None
        assert cache.size == 3

    def test_access_refreshes_lru(self):
        cache = EmbeddingCache(max_size=3)
        cache.put("a", np.zeros(384, dtype=np.float32))
        cache.put("b", np.zeros(384, dtype=np.float32))
        cache.put("c", np.zeros(384, dtype=np.float32))
        cache.get("a")  # refresh "a"
        cache.put("d", np.zeros(384, dtype=np.float32))
        # "b" should be evicted (oldest untouched)
        assert cache.get("b") is None
        assert cache.get("a") is not None

class TestCacheStats:
    def test_hit_rate_zero_when_empty(self, cache):
        assert cache.hit_rate == 0.0

    def test_hit_rate_tracks(self, cache):
        cache.put("key", np.zeros(384, dtype=np.float32))
        cache.get("key")  # hit
        cache.get("missing")  # miss
        assert cache.hit_rate == 0.5

    def test_stats_dict(self, cache):
        s = cache.stats
        assert "size" in s
        assert "hits" in s
        assert "misses" in s
        assert "hit_rate" in s

    def test_clear(self, cache):
        cache.put("a", np.zeros(384, dtype=np.float32))
        cache.clear()
        assert cache.size == 0
        assert cache.get("a") is None

class TestCacheHardening:
    def test_unicode_keys(self, cache):
        vec = np.zeros(384, dtype=np.float32)
        cache.put("こんにちは", vec)
        assert cache.get("こんにちは") is not None

    def test_empty_key(self, cache):
        vec = np.zeros(384, dtype=np.float32)
        cache.put("", vec)
        assert cache.get("") is not None

    def test_max_size_one(self):
        cache = EmbeddingCache(max_size=1)
        cache.put("a", np.zeros(384, dtype=np.float32))
        cache.put("b", np.zeros(384, dtype=np.float32))
        assert cache.size == 1
        assert cache.get("b") is not None
