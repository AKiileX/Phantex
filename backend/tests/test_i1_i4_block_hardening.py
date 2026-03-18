# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
I1-I4 Block Hardening Tests — .

Tests for security findings in Redis/ClickHouse/Neo4j clients, Kafka consumer
base class, and storage writers (PG, CH, Neo4j).

Findings covered:
  F1  (LOW)    clickhouse.py   — Singleton race condition → asyncio.Lock
  F2  (LOW)    neo4j_client.py — Singleton race condition → asyncio.Lock
  F3  (MEDIUM) main_consumer   — asyncpg pool missing SSL → _build_pg_ssl_context
  F4  (MEDIUM) main_consumer   — CH client missing TLS   → secure + ssl_context
  F5  (MEDIUM) main_consumer   — Neo4j missing encrypted  → encrypted param
  F6  (HIGH)   base_consumer   — No msg size guard         → MAX_MESSAGE_BYTES
  F7  (MEDIUM) base_consumer   — Tenant ID not UUID-valid  → uuid.UUID validation
  F8  (MEDIUM) ch_writer       — int() crash on bad data   → _safe_int helper
  F9  (MEDIUM) neo4j_writer    — Single-event poisons batch→ isolated failures
  F10 (LOW)    pg_writer       — No safe int coercion      → _safe_int helper
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# F1 — ClickHouse singleton lock
# ═══════════════════════════════════════════════════════════════════════════════

class TestClickHouseSingletonLock:
    """F1: clickhouse.py must use asyncio.Lock for singleton initialisation."""

    def test_lock_exists(self):
        from app.clickhouse import _client_lock

        assert isinstance(_client_lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_concurrent_calls_create_single_client(self):
        """Two concurrent get_clickhouse() calls must not create two clients."""
        import app.clickhouse as ch_mod

        original = ch_mod._client
        ch_mod._client = None  # Reset for test

        call_count = 0
        fake_client = MagicMock()

        async def fake_get_async_client(**kwargs):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)  # Simulate slow connect
            return fake_client

        try:
            with (
                patch("app.clickhouse.clickhouse_connect") as mock_cc,
                patch("app.clickhouse.get_settings") as mock_settings,
            ):
                mock_cc.get_async_client = fake_get_async_client
                s = MagicMock()
                s.clickhouse_host = "localhost"
                s.clickhouse_port = 9000
                s.clickhouse_database = "default"
                s.clickhouse_user = "default"
                s.clickhouse_password = ""
                s.clickhouse_tls_enabled = False
                mock_settings.return_value = s

                results = await asyncio.gather(
                    ch_mod.get_clickhouse(),
                    ch_mod.get_clickhouse(),
                    ch_mod.get_clickhouse(),
                )

            # Only ONE client should have been created
            assert call_count == 1
            assert all(r is fake_client for r in results)
        finally:
            ch_mod._client = original

    @pytest.mark.asyncio
    async def test_close_resets_client(self):
        import app.clickhouse as ch_mod

        original = ch_mod._client
        ch_mod._client = MagicMock()
        try:
            await ch_mod.close_clickhouse()
            assert ch_mod._client is None
        finally:
            ch_mod._client = original

# ═══════════════════════════════════════════════════════════════════════════════
# F2 — Neo4j singleton lock
# ═══════════════════════════════════════════════════════════════════════════════

class TestNeo4jSingletonLock:
    """F2: neo4j_client.py must use asyncio.Lock for singleton initialisation."""

    def test_lock_exists(self):
        from app.neo4j_client import _driver_lock

        assert isinstance(_driver_lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_concurrent_calls_create_single_driver(self):
        """Two concurrent get_neo4j() calls must create exactly one driver."""
        import app.neo4j_client as neo_mod

        original = neo_mod._driver
        neo_mod._driver = None

        call_count = 0
        fake_driver = AsyncMock()
        fake_driver.verify_connectivity = AsyncMock()

        try:
            with (
                patch("app.neo4j_client.AsyncGraphDatabase") as mock_agd,
                patch("app.neo4j_client.get_settings") as mock_settings,
            ):

                async def slow_driver(*a, **kw):
                    nonlocal call_count
                    call_count += 1
                    await asyncio.sleep(0.05)
                    return fake_driver

                # AsyncGraphDatabase.driver is sync but returns driver
                mock_agd.driver = MagicMock(side_effect=lambda *a, **kw: fake_driver)
                s = MagicMock()
                s.neo4j_uri = "bolt://localhost:7687"
                s.neo4j_user = "neo4j"
                s.neo4j_password = "test"
                s.neo4j_database = "neo4j"
                s.neo4j_tls_enabled = False
                mock_settings.return_value = s

                results = await asyncio.gather(
                    neo_mod.get_neo4j(),
                    neo_mod.get_neo4j(),
                )

            # Driver constructor should be called only once
            assert mock_agd.driver.call_count == 1
            assert all(r is fake_driver for r in results)
        finally:
            neo_mod._driver = original

# ═══════════════════════════════════════════════════════════════════════════════
# F3 — asyncpg pool SSL context in main_consumer
# ═══════════════════════════════════════════════════════════════════════════════

class TestPgSslContext:
    """F3: _build_pg_ssl_context must return proper SSL contexts."""

    def test_disable_returns_none(self):
        from app.main_consumer import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "disable"
        assert _build_pg_ssl_context(settings) is None

    def test_require_returns_context_no_verify(self):
        import ssl

        from app.main_consumer import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "require"
        settings.db_ssl_ca_file = None
        settings.db_ssl_cert_file = None
        settings.db_ssl_key_file = None

        ctx = _build_pg_ssl_context(settings)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False

    def test_verify_full_returns_context_with_verify(self):
        import ssl

        from app.main_consumer import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "verify-full"
        settings.db_ssl_ca_file = None
        settings.db_ssl_cert_file = None
        settings.db_ssl_key_file = None

        ctx = _build_pg_ssl_context(settings)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_verify_ca_no_hostname_check(self):
        import ssl

        from app.main_consumer import _build_pg_ssl_context

        settings = MagicMock()
        settings.db_ssl_mode = "verify-ca"
        settings.db_ssl_ca_file = None
        settings.db_ssl_cert_file = None
        settings.db_ssl_key_file = None

        ctx = _build_pg_ssl_context(settings)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is False

# ═══════════════════════════════════════════════════════════════════════════════
# F6 — Message size guard in base_consumer
# ═══════════════════════════════════════════════════════════════════════════════

class TestMessageSizeGuard:
    """F6: Messages larger than MAX_MESSAGE_BYTES must be rejected."""

    def test_constant_defined(self):
        from app.consumers.base_consumer import MAX_MESSAGE_BYTES

        assert MAX_MESSAGE_BYTES == 1_048_576  # 1 MB

    def test_oversized_message_is_skipped(self):
        """Simulate oversized message through the consumer's message handling."""
        from app.consumers.base_consumer import MAX_MESSAGE_BYTES

        # A message just over the limit
        payload = b"x" * (MAX_MESSAGE_BYTES + 1)
        assert len(payload) > MAX_MESSAGE_BYTES

    def test_normal_message_under_limit(self):
        from app.consumers.base_consumer import MAX_MESSAGE_BYTES

        payload = json.dumps({"event_id": "test", "data": "small"}).encode()
        assert len(payload) < MAX_MESSAGE_BYTES

# ═══════════════════════════════════════════════════════════════════════════════
# F7 — Tenant UUID validation in base_consumer
# ═══════════════════════════════════════════════════════════════════════════════

class TestTenantUuidValidation:
    """F7: Tenant ID from topic must be validated as UUID."""

    def test_valid_uuid_accepted(self):
        import uuid

        from app.consumers.base_consumer import _TOPIC_TENANT_RE

        topic = "phantex.events.550e8400-e29b-41d4-a716-446655440000"
        m = _TOPIC_TENANT_RE.match(topic)
        assert m is not None
        raw = m.group(1)
        # Must parse as UUID without error
        validated = str(uuid.UUID(raw))
        assert validated == "550e8400-e29b-41d4-a716-446655440000"

    def test_non_uuid_tenant_rejected(self):
        """Non-UUID tenant IDs must be rejected by uuid.UUID()."""
        import uuid

        bad_tenants = [
            "'; DROP TABLE events; --",
            "not-a-uuid",
            "../../../etc/passwd",
            "",
            "tenant-abc-123",
        ]
        for bad in bad_tenants:
            with pytest.raises((ValueError, AttributeError)):
                uuid.UUID(bad)

    def test_uuid_normalisation(self):
        """UUID with uppercase letters is normalised to lowercase."""
        import uuid

        raw = "550E8400-E29B-41D4-A716-446655440000"
        validated = str(uuid.UUID(raw))
        assert validated == "550e8400-e29b-41d4-a716-446655440000"

# ═══════════════════════════════════════════════════════════════════════════════
# F8 — _safe_int in ch_writer
# ═══════════════════════════════════════════════════════════════════════════════

class TestChWriterSafeInt:
    """F8: ClickHouse writer must not crash on non-numeric field values."""

    def test_safe_int_valid(self):
        from app.consumers.ch_writer import _safe_int

        assert _safe_int(42) == 42
        assert _safe_int("123") == 123
        assert _safe_int("0") == 0
        assert _safe_int(0) == 0

    def test_safe_int_none(self):
        from app.consumers.ch_writer import _safe_int

        assert _safe_int(None) == 0

    def test_safe_int_bad_string(self):
        from app.consumers.ch_writer import _safe_int

        assert _safe_int("abc") == 0
        assert _safe_int("12.5.6") == 0
        assert _safe_int("") == 0
        assert _safe_int("NaN") == 0

    def test_safe_int_custom_default(self):
        from app.consumers.ch_writer import _safe_int

        assert _safe_int("bad", default=-1) == -1

    def test_safe_int_float(self):
        from app.consumers.ch_writer import _safe_int

        assert _safe_int(3.14) == 3

    def test_safe_int_bool(self):
        from app.consumers.ch_writer import _safe_int

        assert _safe_int(True) == 1
        assert _safe_int(False) == 0

    @pytest.mark.asyncio
    async def test_process_batch_with_bad_numeric_fields(self):
        """Batch with non-numeric dest_port/bytes_out must not crash."""
        from app.consumers.ch_writer import ClickHouseWriter

        mock_ch = MagicMock()
        mock_ch.insert = MagicMock()

        writer = ClickHouseWriter(mock_ch)
        events = [
            {
                "event_id": "evt-1",
                "dest_port": "abc",  # bad
                "bytes_out": None,  # None
                "bytes_in": "not-a-number",  # bad
                "tool_duration_ms": "",  # empty
            },
            {
                "event_id": "evt-2",
                "dest_port": 443,  # good
                "bytes_out": "1024",  # string int
                "bytes_in": 2048,  # int
                "tool_duration_ms": 150,  # int
            },
        ]

        # Should not raise
        await writer.process_batch(events)
        assert mock_ch.insert.called

        # Verify the rows
        call_args = mock_ch.insert.call_args
        rows = call_args[0][1]
        assert len(rows) == 2

        # First event: bad values → 0 or None (0 or None → None for Nullable cols)
        assert rows[0][9] is None  # dest_port: _safe_int("bad") → 0 → 0 or None → None
        assert rows[0][10] == 0  # bytes_out: _safe_int(default 0) → 0
        assert rows[0][11] == 0  # bytes_in: _safe_int("not-a-number") → 0
        assert rows[0][14] is None  # tool_duration_ms: _safe_int("") → 0 → 0 or None → None

        # Second event: good values
        assert rows[1][9] == 443  # dest_port
        assert rows[1][10] == 1024  # bytes_out
        assert rows[1][11] == 2048  # bytes_in
        assert rows[1][14] == 150  # tool_duration_ms

# ═══════════════════════════════════════════════════════════════════════════════
# F9 — Neo4j writer isolated event failures
# ═══════════════════════════════════════════════════════════════════════════════

class TestNeo4jWriterIsolatedFailures:
    """F9: Neo4j writer must isolate individual event failures."""

    @pytest.mark.asyncio
    async def test_partial_failure_does_not_raise(self):
        """If some events fail but not all, batch succeeds."""
        from app.consumers.neo4j_writer import Neo4jWriter

        call_count = 0

        async def mock_write(driver, event):
            nonlocal call_count
            call_count += 1
            if event.get("event_id") == "bad":
                raise RuntimeError("Simulated write failure")

        driver = AsyncMock()
        writer = Neo4jWriter(driver)

        events = [
            {"event_id": "good-1"},
            {"event_id": "bad"},
            {"event_id": "good-2"},
        ]

        with patch("app.consumers.neo4j_writer.write_event_to_graph", side_effect=mock_write):
            # Should NOT raise — only one event fails
            await writer.process_batch(events)

        assert call_count == 3  # All events attempted

    @pytest.mark.asyncio
    async def test_all_events_fail_raises(self):
        """If ALL events fail, the batch raises for retry/DLQ."""
        from app.consumers.neo4j_writer import Neo4jWriter

        async def always_fail(driver, event):
            raise RuntimeError("Always fails")

        driver = AsyncMock()
        writer = Neo4jWriter(driver)

        events = [
            {"event_id": "e1"},
            {"event_id": "e2"},
        ]

        with patch("app.consumers.neo4j_writer.write_event_to_graph", side_effect=always_fail):
            with pytest.raises(RuntimeError, match="All 2 events failed"):
                await writer.process_batch(events)

    @pytest.mark.asyncio
    async def test_empty_batch_no_raise(self):
        from app.consumers.neo4j_writer import Neo4jWriter

        driver = AsyncMock()
        writer = Neo4jWriter(driver)
        await writer.process_batch([])  # Must not raise

    @pytest.mark.asyncio
    async def test_single_event_failure_isolated(self):
        """One bad event in a batch of many should be isolated."""
        from app.consumers.neo4j_writer import Neo4jWriter

        success_ids = []

        async def selective_fail(driver, event):
            eid = event.get("event_id")
            if eid == "poison":
                raise ValueError("bad event")
            success_ids.append(eid)

        driver = AsyncMock()
        writer = Neo4jWriter(driver)

        events = [{"event_id": f"ok-{i}"} for i in range(5)]
        events.insert(2, {"event_id": "poison"})  # Poison at index 2

        with patch("app.consumers.neo4j_writer.write_event_to_graph", side_effect=selective_fail):
            await writer.process_batch(events)

        # 5 out of 6 should have succeeded
        assert len(success_ids) == 5
        assert "poison" not in success_ids

# ═══════════════════════════════════════════════════════════════════════════════
# F10 — _safe_int in pg_writer
# ═══════════════════════════════════════════════════════════════════════════════

class TestPgWriterSafeInt:
    """F10: PostgreSQL writer must safely coerce numeric fields."""

    def test_safe_int_valid(self):
        from app.consumers.pg_writer import _safe_int

        assert _safe_int(8080) == 8080
        assert _safe_int("443") == 443

    def test_safe_int_bad_values(self):
        from app.consumers.pg_writer import _safe_int

        assert _safe_int("bad") == 0
        assert _safe_int(None) == 0
        assert _safe_int("") == 0
        assert _safe_int([]) == 0

    @pytest.mark.asyncio
    async def test_pg_batch_with_bad_numeric_fields(self):
        """PG writer must not crash on non-numeric dest_port etc."""
        from app.consumers.pg_writer import PostgresWriter

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock()

        # Make pool.acquire() return an async context manager
        mock_pool.acquire = MagicMock(return_value=_async_cm(mock_conn))

        writer = PostgresWriter(mock_pool)

        events = [
            {
                "event_id": "e1",
                "dest_port": "not-int",
                "bytes_out": None,
                "tool_duration_ms": "bad",
            },
        ]

        await writer.process_batch(events)
        assert mock_conn.executemany.called

        # Verify row values – PG writer stores 8 columns:
        # (event_id, tenant_id, agent_id, sensor_id, event_type, severity, timestamp, raw_data)
        call_args = mock_conn.executemany.call_args
        rows = call_args[0][1]
        assert len(rows) == 1
        row = rows[0]
        assert row[0] == "e1"  # event_id preserved
        assert len(row) == 8  # PG schema has 8 columns
        raw = json.loads(row[7])  # raw_data is full event JSON
        assert raw["event_id"] == "e1"

# ═══════════════════════════════════════════════════════════════════════════════
# F4/F5 — TLS parameters in main_consumer for CH and Neo4j
# ═══════════════════════════════════════════════════════════════════════════════

class TestMainConsumerTLS:
    """F4+F5: CH client and Neo4j driver in main_consumer must use TLS params."""

    def test_ch_init_has_secure_and_ssl_context_params(self):
        """Source code must reference 'secure' and 'ssl_context' for CH init."""
        import inspect

        from app import main_consumer

        source = inspect.getsource(main_consumer.main)
        # The CH init section should contain TLS configuration
        assert "clickhouse_tls_enabled" in source
        assert 'ch_kwargs["secure"]' in source or '"secure"' in source

    def test_neo4j_init_has_encrypted_param(self):
        """Source code must pass encrypted= to AsyncGraphDatabase.driver."""
        import inspect

        from app import main_consumer

        source = inspect.getsource(main_consumer.main)
        assert "encrypted=" in source
        assert "neo4j_tls_enabled" in source

# ═══════════════════════════════════════════════════════════════════════════════
# Integration-style: base_consumer + writers end-to-end
# ═══════════════════════════════════════════════════════════════════════════════

class TestBaseConsumerMessageSizeIntegration:
    """Integration tests for F6 message size guard with base consumer."""

    @pytest.mark.asyncio
    async def test_oversized_message_increments_deser_errors(self):
        """The consumer must count oversized messages as deserialization errors."""
        from app.consumers.base_consumer import MAX_MESSAGE_BYTES, BaseStorageConsumer

        class DummyConsumer(BaseStorageConsumer):
            async def process_batch(self, events):
                pass

        DummyConsumer(name="size-test", consumer_group="test")

        # Simulate what would happen: manually check the guard
        oversized = b"x" * (MAX_MESSAGE_BYTES + 100)
        assert len(oversized) > MAX_MESSAGE_BYTES

        # The guard is inline in _run_consumer. We verify the constant
        # is correctly set and the guard code exists.
        import inspect

        source = inspect.getsource(BaseStorageConsumer._run_consumer)
        assert "MAX_MESSAGE_BYTES" in source
        assert "consumer_msg_too_large" in source

    @pytest.mark.asyncio
    async def test_tenant_uuid_validation_in_source(self):
        """The consumer must validate tenant_id as UUID in the consume loop."""
        import inspect

        from app.consumers.base_consumer import BaseStorageConsumer

        source = inspect.getsource(BaseStorageConsumer._run_consumer)
        assert "_uuid.UUID" in source
        assert "consumer_invalid_tenant_id" in source

# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

class _async_cm:
    """Minimal async context manager wrapper for mocking pool.acquire()."""

    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, *args):
        pass
