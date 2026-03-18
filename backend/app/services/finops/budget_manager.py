# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Budget Manager.

Configurable spending budgets per agent / team / tenant with
80% / 90% / 100% threshold alerts and optional hard-cap (auto-pause).

Budget configuration is stored in PostgreSQL; spent amounts are
queried from ClickHouse ``cost_hourly`` MV in real time.

Alert records are written to ClickHouse ``budget_alerts`` table.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.finops.budget_manager")

class BudgetScope(StrEnum):
    AGENT = "agent"
    TEAM = "team"
    TENANT = "tenant"

@dataclass
class BudgetConfig:
    """A budget rule — stored in PostgreSQL ``finops_budgets`` table."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    scope: BudgetScope
    scope_id: str  # agent_id / team_id / tenant_id
    budget_usd: float  # Monthly budget in USD
    hard_cap: bool = False  # If True, auto-pause when 100% reached
    enabled: bool = True

    # Thresholds (percent) at which to generate alert records
    thresholds: tuple[int, ...] = (80, 90, 100)

@dataclass
class BudgetStatus:
    """Current spending status against a budget."""

    config: BudgetConfig
    spent_usd: float
    pct_used: float
    remaining_usd: float
    breached_thresholds: list[int]
    capped: bool

class BudgetManager:
    """Evaluate budgets and fire threshold alerts."""

    _PERIOD_DAYS = 30  # rolling 30-day budget window

    def __init__(self) -> None:
        # In-memory set of (budget_id, threshold) already fired this period
        # Prevents duplicate alerts within the same budget window.
        self._fired: set[tuple[uuid.UUID, int]] = set()

    # ── Evaluate a single budget ──────────────────────────────────────

    async def evaluate(
        self,
        ch: Any,
        config: BudgetConfig,
    ) -> BudgetStatus:
        """Check current spend against a budget config."""
        spent = await self._get_spend(ch, config)
        pct = (spent / config.budget_usd * 100) if config.budget_usd > 0 else 0.0
        remaining = max(0.0, config.budget_usd - spent)

        breached: list[int] = []
        for threshold in config.thresholds:
            if pct >= threshold:
                breached.append(threshold)
                await self._fire_alert(ch, config, threshold, spent)

        capped = config.hard_cap and pct >= 100

        if capped:
            logger.warning(
                "budget_hard_cap_triggered",
                tenant_id=str(config.tenant_id),
                scope=config.scope.value,
                scope_id=config.scope_id,
                spent=round(spent, 4),
                budget=config.budget_usd,
            )

        return BudgetStatus(
            config=config,
            spent_usd=round(spent, 4),
            pct_used=round(pct, 2),
            remaining_usd=round(remaining, 4),
            breached_thresholds=breached,
            capped=capped,
        )

    # ── Evaluate all budgets for a tenant ─────────────────────────────

    async def evaluate_all(
        self,
        ch: Any,
        budgets: list[BudgetConfig],
    ) -> list[BudgetStatus]:
        """Evaluate all budget configs (typically called on a schedule)."""
        results = []
        for cfg in budgets:
            if cfg.enabled:
                results.append(await self.evaluate(ch, cfg))
        return results

    def reset_period(self) -> None:
        """Clear fired-alert dedup set (call on budget period rollover)."""
        self._fired.clear()

    # ── Private helpers ───────────────────────────────────────────────

    async def _get_spend(self, ch: Any, config: BudgetConfig) -> float:
        """Query actual spend from ClickHouse for this budget scope."""
        cutoff = datetime.now(UTC) - timedelta(days=self._PERIOD_DAYS)

        if config.scope == BudgetScope.AGENT:
            query = """
                SELECT sum(total_cost_usd) FROM phantex.cost_hourly
                WHERE tenant_id = {tid:UUID}
                  AND agent_id = {sid:UUID}
                  AND hour >= {cutoff:DateTime}
            """
        elif config.scope == BudgetScope.TENANT:
            query = """
                SELECT sum(total_cost_usd) FROM phantex.cost_hourly
                WHERE tenant_id = {tid:UUID}
                  AND hour >= {cutoff:DateTime}
            """
        else:
            # Team scope — requires an agent→team mapping join in production.
            # For now aggregate at tenant level as team support is deferred.
            query = """
                SELECT sum(total_cost_usd) FROM phantex.cost_hourly
                WHERE tenant_id = {tid:UUID}
                  AND hour >= {cutoff:DateTime}
            """

        result = await ch.query(
            query,
            parameters={
                "tid": config.tenant_id,
                "sid": config.scope_id,
                "cutoff": cutoff,
            },
        )
        return float(result.first_row[0] or 0)

    async def _fire_alert(
        self,
        ch: Any,
        config: BudgetConfig,
        threshold: int,
        spent: float,
    ) -> None:
        """Write a budget alert record (deduped per period)."""
        key = (config.id, threshold)
        if key in self._fired:
            return
        self._fired.add(key)

        action = "hard_cap" if config.hard_cap and threshold >= 100 else "warn"
        logger.info(
            "budget_threshold_breached",
            tenant_id=str(config.tenant_id),
            scope=config.scope.value,
            scope_id=config.scope_id,
            threshold=threshold,
            spent=round(spent, 4),
            budget=config.budget_usd,
            action=action,
        )

        try:
            await ch.insert(
                "phantex.budget_alerts",
                [
                    [
                        config.tenant_id,
                        config.scope.value,
                        config.scope_id,
                        threshold,
                        config.budget_usd,
                        spent,
                        action,
                        datetime.now(UTC),
                    ]
                ],
                column_names=[
                    "tenant_id",
                    "scope",
                    "scope_id",
                    "threshold_pct",
                    "budget_usd",
                    "spent_usd",
                    "alert_action",
                    "timestamp",
                ],
            )
        except Exception:
            logger.exception("budget_alert_write_failed")
