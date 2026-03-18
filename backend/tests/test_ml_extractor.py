# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for ML Feature Extractor (J1).

Tests the FeatureExtractor class including event processing,
Redis interaction (mocked), and the full feature computation pipeline.
"""

import json
import math
import time
from unittest.mock import AsyncMock

import pytest

from ml.features.extractor import FeatureExtractor
from ml.features.registry import feature_defaults, feature_names

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_event(event_type="TOOL_CALL", ts=None, **extra):
    """Create a minimal event dict."""
    return {
        "tenant_id": "t1",
        "agent_id": "a1",
        "event_type": event_type,
        "timestamp_epoch": ts or time.time(),
        "dest_ip": extra.get("dest_ip", ""),
        "dest_port": extra.get("dest_port", 0),
        "bytes_out": extra.get("bytes_out", 0),
        "bytes_in": extra.get("bytes_in", 0),
        "file_path": extra.get("file_path", ""),
        "tool_name": extra.get("tool_name", "read_file"),
        "tool_duration_ms": extra.get("tool_duration_ms"),
        "token_count": extra.get("token_count"),
        "prompt_length": extra.get("prompt_length"),
    }

def _make_redis_mock(stored_events=None):
    """Create a mock Redis client."""
    redis = AsyncMock()
    redis.zadd = AsyncMock()
    redis.zcard = AsyncMock(return_value=1)
    redis.zremrangebyrank = AsyncMock()
    redis.expire = AsyncMock()
    redis.hset = AsyncMock()
    redis.hgetall = AsyncMock(return_value={})

    # zrangebyscore returns stored events as JSON bytes
    events = stored_events or []
    redis.zrangebyscore = AsyncMock(return_value=[json.dumps(e).encode() for e in events])
    return redis

# ── Tests ────────────────────────────────────────────────────────────────────

class TestFeatureExtractor:
    """Tests for the FeatureExtractor class."""

    @pytest.mark.asyncio
    async def test_process_event_returns_features(self):
        """process_event returns a dict of features."""
        events_in_redis = [_make_event(ts=time.time())]
        redis = _make_redis_mock(events_in_redis)
        extractor = FeatureExtractor(redis)

        result = await extractor.process_event(_make_event())
        assert result is not None
        assert isinstance(result, dict)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_process_event_missing_tenant(self):
        """process_event returns None for events without tenant_id."""
        redis = _make_redis_mock()
        extractor = FeatureExtractor(redis)

        event = _make_event()
        event.pop("tenant_id")
        result = await extractor.process_event(event)
        assert result is None

    @pytest.mark.asyncio
    async def test_process_event_missing_agent(self):
        """process_event returns None for events without agent_id."""
        redis = _make_redis_mock()
        extractor = FeatureExtractor(redis)

        event = _make_event()
        event.pop("agent_id")
        result = await extractor.process_event(event)
        assert result is None

    @pytest.mark.asyncio
    async def test_process_event_writes_to_redis(self):
        """process_event calls zadd and hset on Redis."""
        redis = _make_redis_mock([_make_event()])
        extractor = FeatureExtractor(redis)

        await extractor.process_event(_make_event())
        redis.zadd.assert_called()
        redis.hset.assert_called()

    @pytest.mark.asyncio
    async def test_features_contain_all_registered(self):
        """Returned features include all registered feature names."""
        events_list = [_make_event(ts=time.time())]
        redis = _make_redis_mock(events_list)
        extractor = FeatureExtractor(redis)

        result = await extractor.process_event(_make_event())
        assert result is not None
        expected_names = feature_names()
        for name in expected_names:
            assert name in result, f"Missing feature: {name}"

    @pytest.mark.asyncio
    async def test_nan_inf_guarded(self):
        """Features should never contain NaN or Inf values."""
        redis = _make_redis_mock([_make_event()])
        extractor = FeatureExtractor(redis)

        result = await extractor.process_event(_make_event())
        assert result is not None
        for k, v in result.items():
            assert not math.isnan(v), f"{k} is NaN"
            assert not math.isinf(v), f"{k} is Inf"

    @pytest.mark.asyncio
    async def test_process_batch_groups_by_agent(self):
        """process_batch processes events grouped by agent."""
        redis = _make_redis_mock([_make_event()])
        extractor = FeatureExtractor(redis)

        events = [
            _make_event(event_type="TOOL_CALL"),
            _make_event(event_type="FILE_READ"),
        ]
        count = await extractor.process_batch(events)
        assert count == 2

    @pytest.mark.asyncio
    async def test_process_batch_skips_incomplete(self):
        """process_batch skips events without tenant/agent."""
        redis = _make_redis_mock([_make_event()])
        extractor = FeatureExtractor(redis)

        events = [
            _make_event(),
            {"event_type": "TOOL_CALL"},  # Missing tenant + agent
        ]
        count = await extractor.process_batch(events)
        assert count == 1

    @pytest.mark.asyncio
    async def test_get_features_returns_defaults_when_empty(self):
        """get_features returns defaults when Redis has no data."""
        redis = _make_redis_mock()
        extractor = FeatureExtractor(redis)

        result = await extractor.get_features("t1", "a1")
        defaults = feature_defaults()
        assert result == defaults

    @pytest.mark.asyncio
    async def test_get_features_merges_redis_data(self):
        """get_features merges Redis data over defaults."""
        redis = _make_redis_mock()
        redis.hgetall = AsyncMock(
            return_value={
                b"event_count_1h": b"42.0",
            }
        )
        extractor = FeatureExtractor(redis)

        result = await extractor.get_features("t1", "a1")
        assert result["event_count_1h"] == 42.0

class TestVolumeFeatures:
    """Tests for volume feature computation."""

    def test_event_count_windows(self):
        """Volume features count events within each time window."""
        from ml.features.volume import compute_volume_features

        now = time.time()
        events = [
            {"event_type": "TOOL_CALL", "timestamp_epoch": now - 30},  # In 1m, 5m, 1h, 24h
            {"event_type": "TOOL_CALL", "timestamp_epoch": now - 120},  # In 5m, 1h, 24h
            {"event_type": "FILE_READ", "timestamp_epoch": now - 30},  # In 1m, 5m, 1h, 24h
        ]

        result = compute_volume_features(events, now)
        assert result["event_count_1m"] == 2  # Two within 60s
        assert result["event_count_5m"] == 3  # All within 300s
        assert result["tool_call_count_1m"] == 1
        assert result["tool_call_count_5m"] == 2
        assert result["file_read_count_1m"] == 1

    def test_empty_events(self):
        """All volume features are 0 for empty event list."""
        from ml.features.volume import compute_volume_features

        result = compute_volume_features([], time.time())
        for v in result.values():
            assert v == 0

class TestVelocityFeatures:
    """Tests for velocity feature computation."""

    def test_events_per_second(self):
        """events_per_second computed as count/window_seconds."""
        from ml.features.velocity import compute_velocity_features

        now = time.time()
        events = [{"event_type": "TOOL_CALL", "timestamp_epoch": now - i} for i in range(30)]
        result = compute_velocity_features(events, now)
        assert result["events_per_second_1m"] == pytest.approx(30 / 60, rel=0.1)

    def test_tool_calls_per_minute(self):
        """tool_calls_per_minute counts only TOOL_CALL events."""
        from ml.features.velocity import compute_velocity_features

        now = time.time()
        events = [
            {"event_type": "TOOL_CALL", "timestamp_epoch": now - 10},
            {"event_type": "FILE_READ", "timestamp_epoch": now - 10},
            {"event_type": "TOOL_CALL", "timestamp_epoch": now - 20},
        ]
        result = compute_velocity_features(events, now)
        assert result["tool_calls_per_minute_1m"] == pytest.approx(2.0, rel=0.1)

class TestTemporalFeatures:
    """Tests for temporal feature computation."""

    def test_hour_of_day_range(self):
        """hour_of_day is in [0, 23]."""
        from ml.features.temporal import compute_temporal_features

        result = compute_temporal_features([_make_event(ts=time.time())], time.time())
        assert 0 <= result["hour_of_day"] <= 23

    def test_day_of_week_range(self):
        """day_of_week is in [0, 6]."""
        from ml.features.temporal import compute_temporal_features

        result = compute_temporal_features([_make_event(ts=time.time())], time.time())
        assert 0 <= result["day_of_week"] <= 6

    def test_burst_duration_zero_for_single(self):
        """burst_duration is 0 for a single event."""
        from ml.features.temporal import compute_temporal_features

        result = compute_temporal_features([_make_event(ts=time.time())], time.time())
        assert result["burst_duration"] == 0

class TestSequenceFeatures:
    """Tests for sequence feature computation."""

    def test_empty_events(self):
        """Sequence features are 0 for empty event list."""
        from ml.features.sequence import compute_sequence_features

        result = compute_sequence_features([], time.time())
        for v in result.values():
            assert v == 0

    def test_bigram_entropy_positive(self):
        """Bigram entropy is positive for varied event types."""
        from ml.features.sequence import compute_sequence_features

        now = time.time()
        events = [{"event_type": t, "timestamp_epoch": now - i} for i, t in enumerate(["A", "B", "C", "A", "B", "D"])]
        result = compute_sequence_features(events, now)
        assert result["bigram_entropy"] >= 0

class TestDiversityFeatures:
    """Tests for diversity feature computation."""

    def test_unique_tools(self):
        """unique_tools_used counts distinct tool_name values."""
        from ml.features.diversity import compute_diversity_features

        now = time.time()
        events = [
            {"tool_name": "read_file", "timestamp_epoch": now - 10},
            {"tool_name": "write_file", "timestamp_epoch": now - 20},
            {"tool_name": "read_file", "timestamp_epoch": now - 30},
        ]
        result = compute_diversity_features(events, now)
        assert result["unique_tools_used_1h"] == 2

    def test_empty_events(self):
        """All diversity features are 0 for empty event list."""
        from ml.features.diversity import compute_diversity_features

        result = compute_diversity_features([], time.time())
        for v in result.values():
            assert v == 0

# ── Sprint 3 Audit: Security Hardening Tests ────────────────────────────────

class TestBehavioralFeatureBounds:
    """Verify behavioral features are clamped to prevent overflow."""

    def test_extreme_response_time_clamped(self):
        """Extremely large response time is bounded at 1M."""
        from ml.features.behavioral import compute_behavioral_features

        now = time.time()
        events = [
            {"tool_duration_ms": 1e18, "timestamp_epoch": now - 10},
        ]
        result = compute_behavioral_features(events, now)
        assert result["avg_response_time_1h"] <= 1_000_000.0

    def test_extreme_token_count_clamped(self):
        """Extremely large token count is bounded at 1M."""
        from ml.features.behavioral import compute_behavioral_features

        now = time.time()
        events = [
            {"token_count": 1e18, "timestamp_epoch": now - 10},
        ]
        result = compute_behavioral_features(events, now)
        assert result["avg_token_count_1h"] <= 1_000_000.0

class TestPayloadTruncation:
    """Verify string fields are truncated in event storage."""

    @pytest.mark.asyncio
    async def test_long_file_path_truncated(self):
        """file_path longer than 256 chars is truncated before storage."""
        import json

        stored_members = []
        redis = AsyncMock()
        redis.zadd = AsyncMock(side_effect=lambda k, m: stored_members.extend(m.keys()))
        redis.zcard = AsyncMock(return_value=1)
        redis.expire = AsyncMock()

        from ml.features.extractor import FeatureExtractor

        extractor = FeatureExtractor(redis)
        long_path = "A" * 1000
        event = {
            "tenant_id": "t1",
            "agent_id": "a1",
            "event_type": "FILE_READ",
            "file_path": long_path,
            "timestamp_epoch": time.time(),
        }
        await extractor._append_event("key", event)
        assert len(stored_members) == 1
        parsed = json.loads(stored_members[0])
        assert len(parsed["file_path"]) == 256
