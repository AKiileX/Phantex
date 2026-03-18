# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for Phase 4, Block AQ — FinOps Cost & Token Monitoring.

Covers:
- TokenTracker record and flush
- Cost aggregator estimate_cost()
- Budget manager evaluate()
- Cost anomaly detection helpers
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.finops.budget_manager import (
    BudgetConfig,
    BudgetManager,
    BudgetScope,
)
from app.services.finops.cost_aggregator import _PRICING, estimate_cost
from app.services.finops.cost_anomaly import _make_anomaly, detect_anomalies
from app.services.finops.token_tracker import TokenRecord, TokenTracker

# ── Fixtures ──────────────────────────────────────────────────────────────────

TENANT = uuid.uuid4()
AGENT = uuid.uuid4()

def _make_record(**overrides) -> TokenRecord:
    defaults = dict(
        tenant_id=TENANT,
        agent_id=AGENT,
        request_id="req-001",
        provider="openai",
        model="gpt-4o-mini",
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        estimated_cost_usd=0.045,
        latency_ms=320.0,
        source="copilot",
    )
    defaults.update(overrides)
    return TokenRecord(**defaults)

# ── TokenTracker ──────────────────────────────────────────────────────────────

class TestTokenTracker:
    def test_record_buffers(self):
        tracker = TokenTracker()
        assert tracker.pending == 0

    @pytest.mark.asyncio
    async def test_record_increments_buffer(self):
        tracker = TokenTracker()
        rec = _make_record()
        # Patch flush to avoid ClickHouse
        tracker.flush = AsyncMock(return_value=0)
        await tracker.record(rec)
        assert tracker.pending == 1

    @pytest.mark.asyncio
    async def test_auto_flush_at_threshold(self):
        tracker = TokenTracker()
        tracker._FLUSH_SIZE = 3
        flush_mock = AsyncMock(return_value=3)
        tracker.flush = flush_mock

        for i in range(3):
            await tracker.record(_make_record(request_id=f"req-{i}"))

        flush_mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_flush_when_empty(self):
        tracker = TokenTracker()
        count = await tracker.flush()
        assert count == 0

    @pytest.mark.asyncio
    async def test_flush_logs_when_no_clickhouse(self):
        tracker = TokenTracker()
        tracker._buffer = [_make_record()]

        with patch("app.clickhouse.get_clickhouse", new_callable=AsyncMock, return_value=None):
            count = await tracker.flush()

        assert count == 0
        assert tracker.pending == 0  # buffer was drained to logs

    @pytest.mark.asyncio
    async def test_flush_success(self):
        tracker = TokenTracker()
        tracker._buffer = [_make_record(), _make_record(request_id="req-002")]

        mock_ch = AsyncMock()
        mock_ch.insert = AsyncMock()

        with patch("app.clickhouse.get_clickhouse", new_callable=AsyncMock, return_value=mock_ch):
            count = await tracker.flush()

        assert count == 2
        assert tracker.pending == 0
        mock_ch.insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_flush_rebuffers_on_failure(self):
        tracker = TokenTracker()
        records = [_make_record(), _make_record(request_id="req-002")]
        tracker._buffer = list(records)

        mock_ch = AsyncMock()
        mock_ch.insert = AsyncMock(side_effect=Exception("connection lost"))

        with patch("app.clickhouse.get_clickhouse", new_callable=AsyncMock, return_value=mock_ch):
            count = await tracker.flush()

        assert count == 0
        assert tracker.pending == 2  # re-buffered

    def test_from_usage_stats(self):
        usage = MagicMock()
        usage.provider = "anthropic"
        usage.model = "claude-3-5-sonnet"
        usage.prompt_tokens = 200
        usage.completion_tokens = 100
        usage.total_tokens = 300
        usage.estimated_cost_usd = 0.21
        usage.latency_ms = 450.0

        rec = TokenTracker.from_usage_stats(TENANT, AGENT, usage, source="copilot")
        assert rec.provider == "anthropic"
        assert rec.total_tokens == 300
        assert rec.source == "copilot"

    def test_from_sdk_event(self):
        event = {
            "provider": "openai",
            "model": "gpt-4o",
            "input_tokens": 500,
            "output_tokens": 200,
            "latency_ms": 800,
        }
        rec = TokenTracker.from_sdk_event(TENANT, AGENT, event)
        assert rec.total_tokens == 700
        assert rec.source == "sdk"
        assert rec.estimated_cost_usd == 0.0  # SDK events costed by aggregator

# ── Cost Aggregator ───────────────────────────────────────────────────────────

class TestCostAggregator:
    def test_estimate_cost_gpt4o(self):
        cost = estimate_cost("gpt-4o", 1000, 1000)
        assert cost == pytest.approx(0.005 + 0.015)

    def test_estimate_cost_gpt4o_mini(self):
        cost = estimate_cost("gpt-4o-mini", 1000, 1000)
        assert cost == pytest.approx(0.00015 + 0.0006)

    def test_estimate_cost_claude(self):
        cost = estimate_cost("claude-3-5-sonnet", 1000, 1000)
        assert cost == pytest.approx(0.003 + 0.015)

    def test_estimate_cost_local_free(self):
        cost = estimate_cost("mistral-local", 1000, 1000)
        assert cost == 0.0

    def test_estimate_cost_unknown_model(self):
        cost = estimate_cost("some-unknown-model", 1000, 1000)
        assert cost == 0.0

    def test_pricing_table_has_entries(self):
        assert len(_PRICING) >= 5

# ── Budget Manager ────────────────────────────────────────────────────────────

class TestBudgetManager:
    @pytest.mark.asyncio
    async def test_evaluate_under_budget(self):
        mgr = BudgetManager()
        cfg = BudgetConfig(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            scope=BudgetScope.TENANT,
            scope_id=str(TENANT),
            budget_usd=100.0,
        )

        mock_ch = AsyncMock()
        # Return $25 spent
        mock_result = MagicMock()
        mock_result.first_row = [25.0]
        mock_ch.query = AsyncMock(return_value=mock_result)
        mock_ch.insert = AsyncMock()

        status = await mgr.evaluate(mock_ch, cfg)
        assert status.spent_usd == 25.0
        assert status.pct_used == 25.0
        assert status.remaining_usd == 75.0
        assert not status.capped
        assert status.breached_thresholds == []

    @pytest.mark.asyncio
    async def test_evaluate_over_budget_hard_cap(self):
        mgr = BudgetManager()
        cfg = BudgetConfig(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            scope=BudgetScope.AGENT,
            scope_id=str(AGENT),
            budget_usd=50.0,
            hard_cap=True,
        )

        mock_ch = AsyncMock()
        mock_result = MagicMock()
        mock_result.first_row = [55.0]
        mock_ch.query = AsyncMock(return_value=mock_result)
        mock_ch.insert = AsyncMock()

        status = await mgr.evaluate(mock_ch, cfg)
        assert status.pct_used == 110.0
        assert status.capped is True
        assert 100 in status.breached_thresholds

    @pytest.mark.asyncio
    async def test_alert_dedup(self):
        mgr = BudgetManager()
        cfg = BudgetConfig(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            scope=BudgetScope.TENANT,
            scope_id=str(TENANT),
            budget_usd=100.0,
        )

        mock_ch = AsyncMock()
        mock_result = MagicMock()
        mock_result.first_row = [95.0]
        mock_ch.query = AsyncMock(return_value=mock_result)
        mock_ch.insert = AsyncMock()

        # First evaluation fires alerts
        await mgr.evaluate(mock_ch, cfg)
        call_count_1 = mock_ch.insert.call_count

        # Second evaluation — already fired, should not call insert again
        await mgr.evaluate(mock_ch, cfg)
        assert mock_ch.insert.call_count == call_count_1

    def test_reset_period(self):
        mgr = BudgetManager()
        mgr._fired.add((uuid.uuid4(), 80))
        mgr.reset_period()
        assert len(mgr._fired) == 0

# ── Cost Anomaly ──────────────────────────────────────────────────────────────

class TestCostAnomaly:
    def test_make_anomaly(self):
        a = _make_anomaly(
            TENANT,
            AGENT,
            "spike",
            "high",
            "cost too high",
            1.5,
            0.3,
            5.0,
        )
        assert a["anomaly_type"] == "spike"
        assert a["severity"] == "high"
        assert a["cost_usd"] == 1.5
        assert a["baseline_usd"] == 0.3
        assert a["deviation_factor"] == 5.0
        assert a["correlated_alert_id"] is None
        assert a["tenant_id"] == TENANT
        assert a["agent_id"] == AGENT

    def test_make_anomaly_rounding(self):
        a = _make_anomaly(
            TENANT,
            AGENT,
            "sustained_high",
            "medium",
            "desc",
            1.23456789,
            0.12345678,
            10.00001,
        )
        assert a["cost_usd"] == 1.2346
        assert a["baseline_usd"] == 0.1235
        assert a["deviation_factor"] == 10.0

    @pytest.mark.asyncio
    async def test_detect_anomalies_populates_correlation(self):
        mock_ch = AsyncMock()

        baseline_result = MagicMock()
        baseline_result.result_rows = [(str(AGENT), 1.0)]

        recent_result = MagicMock()
        recent_result.result_rows = [
            (str(AGENT), datetime(2026, 1, 1, 10, 0, tzinfo=UTC), 4.2),
        ]

        async def _query_side_effect(sql, *args, **kwargs):
            if "avg_hourly" in sql:
                return baseline_result
            return recent_result

        mock_ch.query = AsyncMock(side_effect=_query_side_effect)
        mock_ch.insert = AsyncMock()

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [(uuid.uuid4(), str(AGENT))]
        mock_db.execute = AsyncMock(return_value=mock_result)

        anomalies = await detect_anomalies(mock_ch, TENANT, db=mock_db)

        assert len(anomalies) == 1
        assert anomalies[0]["correlated_alert_id"] is not None
        assert anomalies[0]["severity"] == "critical"
        mock_ch.insert.assert_called_once()
