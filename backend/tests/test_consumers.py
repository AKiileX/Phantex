# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Kafka Consumer base class (I4).

Covers:
  - BaseStorageConsumer configuration
  - Buffer and flush logic
  - DLQ routing
  - Metrics tracking
  - Tenant ID extraction from topic name
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.consumers.base_consumer import _TOPIC_TENANT_RE, BaseStorageConsumer

# ── Topic Regex ──────────────────────────────────────────────────────────────

class TestTopicTenantRegex:
    def test_matches_valid_topic(self):
        m = _TOPIC_TENANT_RE.match("phantex.events.tenant-abc-123")
        assert m is not None
        assert m.group(1) == "tenant-abc-123"

    def test_matches_uuid_tenant(self):
        m = _TOPIC_TENANT_RE.match("phantex.events.550e8400-e29b-41d4-a716-446655440000")
        assert m is not None
        assert m.group(1) == "550e8400-e29b-41d4-a716-446655440000"

    def test_no_match_wrong_prefix(self):
        m = _TOPIC_TENANT_RE.match("other.events.tenant-1")
        assert m is None

    def test_no_match_empty_tenant(self):
        m = _TOPIC_TENANT_RE.match("phantex.events.")
        # .+ requires at least 1 char after the last dot — no match
        assert m is None

    def test_no_match_base_topic(self):
        m = _TOPIC_TENANT_RE.match("phantex.events")
        assert m is None

# ── Consumer Configuration ───────────────────────────────────────────────────

class ConcreteConsumer(BaseStorageConsumer):
    """Minimal concrete implementation for testing."""

    def __init__(self, **kwargs):
        super().__init__(name="test-consumer", consumer_group="test-group", **kwargs)
        self.processed_batches: list[list] = []

    async def process_batch(self, events):
        self.processed_batches.append(events)

class TestConsumerConfig:
    def test_default_config(self):
        c = ConcreteConsumer()
        assert c.name == "test-consumer"
        assert c._consumer_group == "test-group"
        assert c._batch_size == 500
        assert c._flush_interval == 2.0
        assert c._max_retries == 3
        assert c._dlq_topic == "phantex.dlq"

    def test_custom_config(self):
        c = ConcreteConsumer(
            batch_size=100,
            flush_interval_seconds=5.0,
            max_retries=5,
            dlq_topic="custom.dlq",
        )
        assert c._batch_size == 100
        assert c._flush_interval == 5.0
        assert c._max_retries == 5
        assert c._dlq_topic == "custom.dlq"

    def test_initial_metrics(self):
        c = ConcreteConsumer()
        assert c.events_consumed == 0
        assert c.events_written == 0
        assert c.events_dlq == 0
        assert c.batches_written == 0
        assert c.deserialization_errors == 0

# ── Buffer & Flush ───────────────────────────────────────────────────────────

class TestBufferFlush:
    @pytest.mark.asyncio
    async def test_empty_buffer_no_flush(self):
        c = ConcreteConsumer()
        await c._flush_buffer()
        assert c.processed_batches == []
        assert c.batches_written == 0

    @pytest.mark.asyncio
    async def test_flush_processes_buffer(self):
        c = ConcreteConsumer()
        c._buffer = [{"event": 1}, {"event": 2}]
        await c._flush_buffer()
        assert len(c.processed_batches) == 1
        assert len(c.processed_batches[0]) == 2
        assert c.events_written == 2
        assert c.batches_written == 1
        assert c._buffer == []

    @pytest.mark.asyncio
    async def test_flush_clears_buffer(self):
        c = ConcreteConsumer()
        c._buffer = [{"event": 1}]
        await c._flush_buffer()
        assert c._buffer == []

    @pytest.mark.asyncio
    async def test_flush_retries_on_error(self):
        call_count = 0

        class FlakeyConsumer(BaseStorageConsumer):
            async def process_batch(self, events):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise Exception("transient error")

        c = FlakeyConsumer(
            name="flakey",
            consumer_group="test",
            max_retries=3,
        )
        c._buffer = [{"event": 1}]
        await c._flush_buffer()
        assert call_count == 3  # Retried twice, succeeded on 3rd
        assert c.events_written == 1

    @pytest.mark.asyncio
    async def test_flush_sends_to_dlq_after_max_retries(self):
        class AlwaysFailConsumer(BaseStorageConsumer):
            async def process_batch(self, events):
                raise Exception("permanent error")

        c = AlwaysFailConsumer(
            name="fail",
            consumer_group="test",
            max_retries=2,
        )
        # Mock the DLQ sender
        c._send_to_dlq = AsyncMock()
        c._buffer = [{"event": 1}, {"event": 2}]
        await c._flush_buffer()
        c._send_to_dlq.assert_awaited_once()
        assert len(c._send_to_dlq.call_args[0][0]) == 2

# ── Stop / Cleanup ───────────────────────────────────────────────────────────

class TestConsumerLifecycle:
    @pytest.mark.asyncio
    async def test_stop_flushes_remaining(self):
        c = ConcreteConsumer()
        c._buffer = [{"event": 1}]
        await c.stop()
        assert c.events_written == 1
        assert c._buffer == []

    @pytest.mark.asyncio
    async def test_stop_logs_metrics(self):
        c = ConcreteConsumer()
        c.events_consumed = 100
        c.events_written = 95
        c.events_dlq = 5
        await c.stop()
        # Just ensure stop() doesn't crash
        assert True
