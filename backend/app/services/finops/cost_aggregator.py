# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Cost Aggregator.

Price lookup per model per provider (OpenAI, Anthropic, Google, local).
Queries ClickHouse ``cost_hourly`` MV to serve per-agent, per-team,
and per-tenant cost rollups over configurable time ranges.

All queries enforce tenant_id isolation via parameterised queries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from app.utils.logging import get_logger

logger = get_logger("phantex.finops.cost_aggregator")

# ── Model pricing (per 1K tokens) ────────────────────────────────────────────
# Updated periodically; local/Ollama = $0.

_PRICING: dict[str, tuple[float, float]] = {
    # (input_per_1k, output_per_1k)
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "claude-3-5-sonnet": (0.003, 0.015),
    "claude-3-opus": (0.015, 0.075),
    "claude-3-haiku": (0.00025, 0.00125),
    "gemini-1.5-pro": (0.00125, 0.005),
    "gemini-1.5-flash": (0.000075, 0.0003),
    "command-r-plus": (0.003, 0.015),
    "mistral-large": (0.002, 0.006),
}

ValidRange = Literal["1h", "6h", "24h", "7d", "30d", "90d"]

_RANGE_MAP: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}

def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Return estimated USD cost for a single request."""
    for prefix, (in_rate, out_rate) in sorted(_PRICING.items(), key=lambda x: -len(x[0])):
        if prefix in model:
            return prompt_tokens / 1000 * in_rate + completion_tokens / 1000 * out_rate
    return 0.0

# ── Aggregation queries ──────────────────────────────────────────────────────

async def cost_summary(
    ch: Any,
    tenant_id: uuid.UUID,
    range_str: ValidRange = "24h",
) -> dict[str, Any]:
    """Top-level cost summary for a tenant over the given range."""
    cutoff = datetime.now(UTC) - _RANGE_MAP[range_str]
    result = await ch.query(
        """
        SELECT
            sum(total_cost_usd)       AS total_cost,
            sum(total_tokens)         AS total_tokens,
            sum(request_count)        AS total_requests,
            uniqExact(agent_id)       AS unique_agents
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff},
    )
    row = result.first_row
    return {
        "total_cost_usd": round(float(row[0] or 0), 4),
        "total_tokens": int(row[1] or 0),
        "total_requests": int(row[2] or 0),
        "unique_agents": int(row[3] or 0),
        "range": range_str,
    }

async def cost_by_agent(
    ch: Any,
    tenant_id: uuid.UUID,
    range_str: ValidRange = "24h",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Per-agent cost breakdown, sorted by spend descending."""
    cutoff = datetime.now(UTC) - _RANGE_MAP[range_str]
    result = await ch.query(
        """
        SELECT
            agent_id,
            sum(total_cost_usd)       AS cost,
            sum(total_tokens)         AS tokens,
            sum(request_count)        AS requests
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        GROUP BY agent_id
        ORDER BY cost DESC
        LIMIT {lim:UInt32}
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff, "lim": limit},
    )
    return [
        {
            "agent_id": str(r[0]),
            "cost_usd": round(float(r[1] or 0), 4),
            "total_tokens": int(r[2] or 0),
            "requests": int(r[3] or 0),
        }
        for r in result.result_rows
    ]

async def cost_by_model(
    ch: Any,
    tenant_id: uuid.UUID,
    range_str: ValidRange = "24h",
) -> list[dict[str, Any]]:
    """Per-model cost breakdown."""
    cutoff = datetime.now(UTC) - _RANGE_MAP[range_str]
    result = await ch.query(
        """
        SELECT
            provider,
            model,
            sum(total_cost_usd)       AS cost,
            sum(total_tokens)         AS tokens,
            sum(request_count)        AS requests
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        GROUP BY provider, model
        ORDER BY cost DESC
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff},
    )
    return [
        {
            "provider": r[0],
            "model": r[1],
            "cost_usd": round(float(r[2] or 0), 4),
            "total_tokens": int(r[3] or 0),
            "requests": int(r[4] or 0),
        }
        for r in result.result_rows
    ]

async def cost_trend(
    ch: Any,
    tenant_id: uuid.UUID,
    range_str: ValidRange = "7d",
) -> list[dict[str, Any]]:
    """Hourly cost trend for charting."""
    cutoff = datetime.now(UTC) - _RANGE_MAP[range_str]
    result = await ch.query(
        """
        SELECT
            hour,
            sum(total_cost_usd)  AS cost,
            sum(total_tokens)    AS tokens,
            sum(request_count)   AS requests
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        GROUP BY hour
        ORDER BY hour
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff},
    )
    return [
        {
            "hour": r[0].isoformat() if hasattr(r[0], "isoformat") else str(r[0]),
            "cost_usd": round(float(r[1] or 0), 4),
            "total_tokens": int(r[2] or 0),
            "requests": int(r[3] or 0),
        }
        for r in result.result_rows
    ]

async def projected_spend(
    ch: Any,
    tenant_id: uuid.UUID,
) -> dict[str, Any]:
    """Project monthly spend using recent 7-day average."""
    cutoff = datetime.now(UTC) - timedelta(days=7)
    result = await ch.query(
        """
        SELECT sum(total_cost_usd) AS week_cost
        FROM phantex.cost_hourly
        WHERE tenant_id = {tid:UUID}
          AND hour >= {cutoff:DateTime}
        """,
        parameters={"tid": tenant_id, "cutoff": cutoff},
    )
    week_cost = float(result.first_row[0] or 0)
    monthly = week_cost / 7.0 * 30.0
    return {
        "last_7d_usd": round(week_cost, 4),
        "projected_monthly_usd": round(monthly, 2),
    }
