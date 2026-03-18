# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Baseline Updater (J4).

Continuous baseline update using exponential moving average (EMA).
Manages the baseline store (PostgreSQL) and handles LEARNING → ACTIVE → STALE
lifecycle transitions.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from ml.baseline.builder import BaselineBuilder
from ml.baseline.comparator import BaselineComparator
from ml.baseline.models import BaselineProfile

logger = structlog.get_logger("phantex.ml.baseline.updater")

class BaselineUpdater:
    """Manages baseline profiles with PostgreSQL persistence.

    Lifecycle:
      1. New agent → create LEARNING profile
      2. 7 days of learning → transition to ACTIVE
      3. ACTIVE: compare features, update via EMA, generate alerts
      4. 30 days inactive → mark STALE
      5. STALE + new event → reset to LEARNING
    """

    def __init__(self, pg_pool=None) -> None:
        self._pool = pg_pool
        self._builder = BaselineBuilder()
        self._comparator = BaselineComparator()
        # In-memory cache of loaded profiles
        self._profiles: dict[str, BaselineProfile] = {}

    async def process_event(
        self,
        event: dict[str, Any],
        features: dict[str, float],
    ) -> list[dict[str, Any]]:
        """Process a single event: update baseline and return any alerts.

        Returns list of baseline deviation alert dicts.
        """
        tenant_id = event.get("tenant_id", "")
        agent_id = event.get("agent_id", "")
        if not tenant_id or not agent_id:
            return []

        cache_key = f"{tenant_id}:{agent_id}"

        # Load or create profile
        profile = self._profiles.get(cache_key)
        if profile is None:
            profile = await self._load_profile(tenant_id, agent_id)
        if profile is None:
            profile = self._builder.create_profile(tenant_id, agent_id)
            logger.info(
                "baseline_created",
                tenant_id=tenant_id,
                agent_id=agent_id,
            )

        # Compare BEFORE updating (so we compare against the old baseline)
        alerts = self._comparator.compare(profile, features, event)

        # Update profile with new data
        profile = self._builder.update_profile(profile, features, event)

        # Cache and persist
        self._profiles[cache_key] = profile
        await self._save_profile(profile)

        # Annotate alerts with agent info
        for alert in alerts:
            alert["tenant_id"] = tenant_id
            alert["agent_id"] = agent_id
            alert["baseline_mode"] = profile.mode
            alert["event_id"] = event.get("event_id")

        return alerts

    async def get_baseline_mode(self, tenant_id: str, agent_id: str) -> str:
        """Return the current baseline mode for an agent."""
        cache_key = f"{tenant_id}:{agent_id}"
        profile = self._profiles.get(cache_key)
        if profile is None:
            profile = await self._load_profile(tenant_id, agent_id)
        if profile is None:
            return "LEARNING"  # New agent → implicitly LEARNING
        return profile.mode

    async def get_profile(self, tenant_id: str, agent_id: str) -> BaselineProfile | None:
        """Get the full baseline profile for an agent."""
        cache_key = f"{tenant_id}:{agent_id}"
        profile = self._profiles.get(cache_key)
        if profile is None:
            profile = await self._load_profile(tenant_id, agent_id)
        return profile

    async def _load_profile(self, tenant_id: str, agent_id: str) -> BaselineProfile | None:
        """Load a baseline profile from PostgreSQL."""
        if self._pool is None:
            return None

        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT profile_data
                    FROM agent_baselines
                    WHERE tenant_id = $1 AND agent_id = $2
                    """,
                    tenant_id,
                    agent_id,
                )
                if row:
                    data = json.loads(row["profile_data"])
                    profile = BaselineProfile.from_dict(data)
                    cache_key = f"{tenant_id}:{agent_id}"
                    self._profiles[cache_key] = profile
                    return profile
        except Exception:
            logger.exception(
                "baseline_load_error",
                tenant_id=tenant_id,
                agent_id=agent_id,
            )
        return None

    async def _save_profile(self, profile: BaselineProfile) -> None:
        """Save a baseline profile to PostgreSQL."""
        if self._pool is None:
            return

        try:
            data = json.dumps(profile.to_dict())
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO agent_baselines (tenant_id, agent_id, mode, profile_data, updated_at)
                    VALUES ($1, $2, $3, $4, NOW())
                    ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
                        mode = EXCLUDED.mode,
                        profile_data = EXCLUDED.profile_data,
                        updated_at = NOW()
                    """,
                    profile.tenant_id,
                    profile.agent_id,
                    profile.mode,
                    data,
                )
        except Exception:
            logger.exception(
                "baseline_save_error",
                tenant_id=profile.tenant_id,
                agent_id=profile.agent_id,
            )
