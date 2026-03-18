# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Analytics Service (I2).

Covers:
  - Interval/range parsing and validation
  - Query function parameter handling
  - Edge cases (invalid ranges, limit clamping)

Note: We test the pure-logic helpers. Query execution against ClickHouse
is integration-tested via docker-compose; unit tests mock the CH client.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.analytics_service import (
    _INTERVAL_MAP,
    _RANGE_MAP,
    _parse_range,
    attack_breakdown,
    event_volume,
    network_destinations,
    tool_usage,
    top_agents,
)

# ── Range / Interval Parsing ─────────────────────────────────────────────────

class TestParseRange:
    def test_valid_ranges(self):
        for key in _RANGE_MAP:
            result = _parse_range(key)
            assert isinstance(result, datetime)
            assert result.tzinfo is not None

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError, match="Invalid range"):
            _parse_range("999y")

    def test_range_is_past(self):
        result = _parse_range("1h")
        now = datetime.now(UTC)
        assert result < now

    def test_longer_range_is_further_past(self):
        h1 = _parse_range("1h")
        d30 = _parse_range("30d")
        assert d30 < h1

class TestIntervalMap:
    def test_all_intervals_present(self):
        expected = {"1m", "5m", "15m", "1h", "1d"}
        assert set(_INTERVAL_MAP.keys()) == expected

    def test_interval_values_are_ch_functions(self):
        for fn in _INTERVAL_MAP.values():
            assert fn.startswith("toStartOf")

# ── Mock ClickHouse Client ───────────────────────────────────────────────────

def _mock_ch(rows: list[tuple] | None = None):
    """Create a mock ClickHouse AsyncClient."""
    mock = AsyncMock()
    result = MagicMock()
    result.result_rows = rows or []
    mock.query.return_value = result
    return mock

# ── Event Volume ─────────────────────────────────────────────────────────────

class TestEventVolume:
    @pytest.mark.asyncio
    async def test_empty_result(self):
        ch = _mock_ch([])
        tid = uuid.uuid4()
        result = await event_volume(ch, tid)
        assert result == []
        ch.query.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_structured_rows(self):
        ch = _mock_ch(
            [
                ("2025-01-15 10:00:00", "TOOL_CALL", 42),
                ("2025-01-15 11:00:00", "NETWORK_CONNECT", 7),
            ]
        )
        tid = uuid.uuid4()
        result = await event_volume(ch, tid, interval="1h", range_str="24h")
        assert len(result) == 2
        assert result[0]["event_type"] == "TOOL_CALL"
        assert result[0]["count"] == 42
        assert "bucket" in result[0]

    @pytest.mark.asyncio
    async def test_hourly_uses_aggregated_table(self):
        ch = _mock_ch([])
        tid = uuid.uuid4()
        await event_volume(ch, tid, interval="1h")
        query_arg = ch.query.call_args[0][0]
        assert "events_hourly" in query_arg

    @pytest.mark.asyncio
    async def test_minute_uses_raw_table(self):
        ch = _mock_ch([])
        tid = uuid.uuid4()
        await event_volume(ch, tid, interval="5m")
        query_arg = ch.query.call_args[0][0]
        assert "phantex.events" in query_arg
        assert "events_hourly" not in query_arg

    @pytest.mark.asyncio
    async def test_agent_filter(self):
        ch = _mock_ch([])
        tid = uuid.uuid4()
        aid = uuid.uuid4()
        await event_volume(ch, tid, interval="5m", agent_id=aid)
        params = ch.query.call_args[1].get("parameters") or ch.query.call_args[0][1]
        assert "agent_id" in params

    @pytest.mark.asyncio
    async def test_event_type_filter(self):
        ch = _mock_ch([])
        tid = uuid.uuid4()
        await event_volume(ch, tid, interval="5m", event_type="TOOL_CALL")
        params = ch.query.call_args[1].get("parameters") or ch.query.call_args[0][1]
        assert "etype" in params

# ── Top Agents ───────────────────────────────────────────────────────────────

class TestTopAgents:
    @pytest.mark.asyncio
    async def test_empty_result(self):
        ch = _mock_ch([])
        result = await top_agents(ch, uuid.uuid4())
        assert result == []

    @pytest.mark.asyncio
    async def test_structured_result(self):
        ch = _mock_ch(
            [
                (uuid.uuid4(), 100, 5, "2025-01-15 10:00:00"),
            ]
        )
        result = await top_agents(ch, uuid.uuid4())
        assert len(result) == 1
        assert result[0]["event_count"] == 100
        assert result[0]["unique_types"] == 5

    @pytest.mark.asyncio
    async def test_limit_clamped_min(self):
        ch = _mock_ch([])
        await top_agents(ch, uuid.uuid4(), limit=-5)
        params = ch.query.call_args[1].get("parameters") or ch.query.call_args[0][1]
        assert params["lim"] == 1

    @pytest.mark.asyncio
    async def test_limit_clamped_max(self):
        ch = _mock_ch([])
        await top_agents(ch, uuid.uuid4(), limit=9999)
        params = ch.query.call_args[1].get("parameters") or ch.query.call_args[0][1]
        assert params["lim"] == 100

# ── Attack Breakdown ─────────────────────────────────────────────────────────

class TestAttackBreakdown:
    @pytest.mark.asyncio
    async def test_empty_result(self):
        ch = _mock_ch([])
        result = await attack_breakdown(ch, uuid.uuid4())
        assert result == []

    @pytest.mark.asyncio
    async def test_structured_result(self):
        ch = _mock_ch(
            [
                ("credential_theft", "high", 12),
                ("data_exfiltration", "critical", 3),
            ]
        )
        result = await attack_breakdown(ch, uuid.uuid4())
        assert len(result) == 2
        assert result[0]["attack_class"] == "credential_theft"
        assert result[1]["count"] == 3

# ── Network Destinations ─────────────────────────────────────────────────────

class TestNetworkDestinations:
    @pytest.mark.asyncio
    async def test_empty_result(self):
        ch = _mock_ch([])
        result = await network_destinations(ch, uuid.uuid4(), agent_id=uuid.uuid4())
        assert result == []

    @pytest.mark.asyncio
    async def test_structured_result(self):
        ch = _mock_ch(
            [
                ("10.0.0.1", 443, 10, 5000, 3000, "2025-01-14", "2025-01-15"),
            ]
        )
        result = await network_destinations(ch, uuid.uuid4(), agent_id=uuid.uuid4())
        assert len(result) == 1
        assert result[0]["dest_ip"] == "10.0.0.1"
        assert result[0]["connection_count"] == 10

    @pytest.mark.asyncio
    async def test_limit_clamped(self):
        ch = _mock_ch([])
        await network_destinations(ch, uuid.uuid4(), agent_id=uuid.uuid4(), limit=500)
        params = ch.query.call_args[1].get("parameters") or ch.query.call_args[0][1]
        assert params["lim"] == 200

# ── Tool Usage ───────────────────────────────────────────────────────────────

class TestToolUsage:
    @pytest.mark.asyncio
    async def test_empty_result(self):
        ch = _mock_ch([])
        result = await tool_usage(ch, uuid.uuid4(), agent_id=uuid.uuid4())
        assert result == []

    @pytest.mark.asyncio
    async def test_structured_result(self):
        ch = _mock_ch(
            [
                ("exec_shell", 50, 123.456, 999, "2025-01-10", "2025-01-15"),
            ]
        )
        result = await tool_usage(ch, uuid.uuid4(), agent_id=uuid.uuid4())
        assert len(result) == 1
        assert result[0]["tool_name"] == "exec_shell"
        assert result[0]["call_count"] == 50
        assert result[0]["avg_duration_ms"] == 123.5  # rounded

    @pytest.mark.asyncio
    async def test_limit_clamped(self):
        ch = _mock_ch([])
        await tool_usage(ch, uuid.uuid4(), agent_id=uuid.uuid4(), limit=-1)
        params = ch.query.call_args[1].get("parameters") or ch.query.call_args[0][1]
        assert params["lim"] == 1
