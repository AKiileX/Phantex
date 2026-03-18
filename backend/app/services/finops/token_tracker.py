# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Token Usage Tracker.

Intercepts LLM API call results, extracts token counts, and persists
them to ClickHouse for cost aggregation.  Works with:
  - Backend Copilot calls (UsageStats from llm_provider.py)
  - SDK telemetry events (input_tokens / output_tokens from gateway)

All writes are tenant-scoped.  When ClickHouse is unavailable the
record is logged so it can be recovered from structured log replay.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.finops.token_tracker")

@dataclass(frozen=True)
class TokenRecord:
    """A single LLM request's token usage."""

    tenant_id: uuid.UUID
    agent_id: str
    request_id: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    latency_ms: float = 0.0
    source: str = "backend"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

class TokenTracker:
    """Accumulates and flushes token-usage records to ClickHouse."""

    _FLUSH_SIZE = 50
    _TABLE = "phantex.token_usage"
    _COLUMNS = [
        "tenant_id",
        "agent_id",
        "request_id",
        "provider",
        "model",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "estimated_cost_usd",
        "latency_ms",
        "source",
        "timestamp",
    ]

    def __init__(self) -> None:
        self._buffer: list[TokenRecord] = []

    # ── Public API ────────────────────────────────────────────────────

    async def record(self, rec: TokenRecord) -> None:
        """Buffer a token-usage record and flush if threshold reached."""
        self._buffer.append(rec)
        logger.debug(
            "token_recorded",
            tenant_id=str(rec.tenant_id),
            agent_id=str(rec.agent_id),
            model=rec.model,
            total_tokens=rec.total_tokens,
            cost=rec.estimated_cost_usd,
        )
        if len(self._buffer) >= self._FLUSH_SIZE:
            await self.flush()

    async def flush(self) -> int:
        """Flush buffered records to ClickHouse.  Returns count written."""
        if not self._buffer:
            return 0

        batch = list(self._buffer)
        self._buffer.clear()

        from app.clickhouse import get_clickhouse

        ch = await get_clickhouse()
        if ch is None:
            # Log each record so ops can replay from structured logs
            for rec in batch:
                logger.warning("token_record_orphaned", **_rec_to_dict(rec))
            return 0

        rows = [_rec_to_row(r) for r in batch]
        try:
            await ch.insert(
                self._TABLE,
                rows,
                column_names=self._COLUMNS,
            )
            logger.info("token_flush", count=len(rows))
            return len(rows)
        except Exception:
            logger.exception("token_flush_failed", count=len(rows))
            # Re-buffer for next attempt
            self._buffer.extend(batch)
            return 0

    @property
    def pending(self) -> int:
        return len(self._buffer)

    # ── Convenience: build TokenRecord from UsageStats ────────────────

    @staticmethod
    def from_usage_stats(
        tenant_id: uuid.UUID,
        agent_id: str,
        usage: Any,
        *,
        source: str = "copilot",
    ) -> TokenRecord:
        """Convert a ``UsageStats`` dataclass to a ``TokenRecord``."""
        return TokenRecord(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=uuid.uuid4().hex,
            provider=getattr(usage, "provider", "unknown"),
            model=getattr(usage, "model", "unknown"),
            prompt_tokens=getattr(usage, "prompt_tokens", 0),
            completion_tokens=getattr(usage, "completion_tokens", 0),
            total_tokens=getattr(usage, "total_tokens", 0),
            estimated_cost_usd=getattr(usage, "estimated_cost_usd", 0.0),
            latency_ms=getattr(usage, "latency_ms", 0.0),
            source=source,
        )

    @staticmethod
    def from_sdk_event(
        tenant_id: uuid.UUID,
        agent_id: str,
        event: dict[str, Any],
    ) -> TokenRecord:
        """Convert an SDK telemetry event dict to a ``TokenRecord``."""
        return TokenRecord(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=event.get("request_id", uuid.uuid4().hex),
            provider=event.get("provider", "unknown"),
            model=event.get("model", "unknown"),
            prompt_tokens=int(event.get("input_tokens", 0)),
            completion_tokens=int(event.get("output_tokens", 0)),
            total_tokens=int(event.get("input_tokens", 0)) + int(event.get("output_tokens", 0)),
            estimated_cost_usd=0.0,  # SDK events get costed by the aggregator
            latency_ms=float(event.get("latency_ms", 0)),
            source="sdk",
        )

# ── Internal helpers ──────────────────────────────────────────────────────────

def _rec_to_row(rec: TokenRecord) -> list[Any]:
    return [
        rec.tenant_id,
        rec.agent_id,
        rec.request_id,
        rec.provider,
        rec.model,
        rec.prompt_tokens,
        rec.completion_tokens,
        rec.total_tokens,
        rec.estimated_cost_usd,
        rec.latency_ms,
        rec.source,
        rec.timestamp,
    ]

def _rec_to_dict(rec: TokenRecord) -> dict[str, Any]:
    return {
        "tenant_id": str(rec.tenant_id),
        "agent_id": str(rec.agent_id),
        "request_id": rec.request_id,
        "provider": rec.provider,
        "model": rec.model,
        "prompt_tokens": rec.prompt_tokens,
        "completion_tokens": rec.completion_tokens,
        "total_tokens": rec.total_tokens,
        "estimated_cost_usd": rec.estimated_cost_usd,
        "source": rec.source,
    }
