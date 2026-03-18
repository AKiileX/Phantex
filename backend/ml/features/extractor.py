# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Feature Extractor (J1).

Main feature extraction pipeline. Consumes events from Kafka, computes
the full feature vector per agent, and writes to Redis (hot) and
optionally ClickHouse (cold) for model training.

All features are float values. Missing data → 0.0 (safe default).
"""

from __future__ import annotations

import contextlib
import time
from typing import Any

import structlog

from ml.config import (
    REDIS_EVENT_STREAM_MAXLEN,
    REDIS_EVENT_STREAM_PREFIX,
    REDIS_FEATURE_PREFIX,
    REDIS_FEATURE_TTL,
    get_ml_config,
)
from ml.features.behavioral import compute_behavioral_features
from ml.features.diversity import compute_diversity_features
from ml.features.mcp import compute_mcp_features
from ml.features.network import compute_network_features
from ml.features.registry import feature_defaults
from ml.features.sequence import compute_sequence_features
from ml.features.temporal import compute_temporal_features
from ml.features.trust import compute_trust_features
from ml.features.velocity import compute_velocity_features
from ml.features.volume import compute_volume_features

logger = structlog.get_logger("phantex.ml.features")

class FeatureExtractor:
    """
    Stateless feature extraction engine.

    Given a Redis client and an event, compute the full feature vector
    for the agent and persist it.

    Redis data model:
        - ml:events:{tenant}:{agent} — sorted set of recent event JSON
          (score = timestamp, limited to MAXLEN most recent)
        - ml:features:{tenant}:{agent} — HASH of feature_name → value
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client
        self._config = get_ml_config().features

    async def process_event(self, event: dict[str, Any]) -> dict[str, float] | None:
        """Process a single event: append to stream and recompute features.

        Returns the computed feature vector, or None if event lacks required
        fields (tenant_id, agent_id).
        """
        tenant_id = event.get("tenant_id")
        agent_id = event.get("agent_id")
        if not tenant_id or not agent_id:
            return None

        now = time.time()

        # Add timestamp_epoch if not present
        event.setdefault("timestamp_epoch", now)

        # ── Append event to the agent's recent-event list in Redis ───
        stream_key = f"{REDIS_EVENT_STREAM_PREFIX}:{tenant_id}:{agent_id}"
        await self._append_event(stream_key, event)

        # ── Retrieve recent events for feature computation ───────────
        recent_events = await self._get_recent_events(stream_key)

        # ── Compute all feature categories ───────────────────────────
        features = self._compute_features(recent_events, now)

        # ── Write features to Redis ──────────────────────────────────
        feature_key = f"{REDIS_FEATURE_PREFIX}:{tenant_id}:{agent_id}"
        await self._write_features(feature_key, features)

        return features

    async def process_batch(self, events: list[dict[str, Any]]) -> int:
        """Process a batch of events. Returns count of successfully processed."""
        count = 0
        # Group by agent to minimize Redis round-trips
        agent_events: dict[tuple[str, str], list[dict]] = {}
        for e in events:
            tid = e.get("tenant_id")
            aid = e.get("agent_id")
            if tid and aid:
                agent_events.setdefault((tid, aid), []).append(e)

        for (tenant_id, agent_id), agent_evts in agent_events.items():
            try:
                now = time.time()
                stream_key = f"{REDIS_EVENT_STREAM_PREFIX}:{tenant_id}:{agent_id}"

                # Append all events for this agent
                for e in agent_evts:
                    e.setdefault("timestamp_epoch", now)
                    await self._append_event(stream_key, e)

                # Recompute features once (from full recent history)
                recent_events = await self._get_recent_events(stream_key)
                features = self._compute_features(recent_events, now)

                feature_key = f"{REDIS_FEATURE_PREFIX}:{tenant_id}:{agent_id}"
                await self._write_features(feature_key, features)
                count += len(agent_evts)
            except Exception:
                logger.exception(
                    "feature_extraction_error",
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                )

        return count

    def _compute_features(self, events: list[dict], now: float) -> dict[str, float]:
        """Compute the full feature vector from recent events."""
        # Start with defaults (all zeros for missing features)
        features = feature_defaults()

        # Compute each feature category and merge
        features.update(compute_volume_features(events, now))
        features.update(compute_velocity_features(events, now))
        features.update(compute_diversity_features(events, now))
        features.update(compute_behavioral_features(events, now))
        features.update(compute_network_features(events, now))
        features.update(compute_temporal_features(events, now))
        features.update(compute_sequence_features(events, now))
        features.update(compute_mcp_features(events, now))
        features.update(compute_trust_features(events, now))

        # Validate: reject NaN/Inf (model poisoning guard)
        import math

        for k, v in features.items():
            if not isinstance(v, int | float) or math.isnan(v) or math.isinf(v):
                features[k] = 0.0

        return features

    async def _append_event(self, stream_key: str, event: dict) -> None:
        """Append an event to the agent's sorted set in Redis.

        Uses ZADD with score = timestamp_epoch. Trims to MAXLEN.
        We store a minimal JSON payload (only fields needed for features).
        """
        import json

        ts = event.get("timestamp_epoch", time.time())
        # Store only feature-relevant fields to save memory
        # Truncate string fields to prevent Redis memory abuse
        _MAX_STR = 256
        mini = {
            "event_type": str(event.get("event_type", ""))[:_MAX_STR],
            "timestamp_epoch": ts,
            "dest_ip": str(event.get("dest_ip", ""))[:_MAX_STR],
            "dest_port": event.get("dest_port", 0),
            "bytes_out": min(int(event.get("bytes_out", 0)), 10_000_000_000),
            "bytes_in": min(int(event.get("bytes_in", 0)), 10_000_000_000),
            "file_path": str(event.get("file_path", ""))[:_MAX_STR],
            "tool_name": str(event.get("tool_name", ""))[:_MAX_STR],
            "tool_duration_ms": event.get("tool_duration_ms"),
            "token_count": event.get("token_count"),
            "prompt_length": event.get("prompt_length"),
        }
        member = json.dumps(mini, separators=(",", ":"))
        await self._redis.zadd(stream_key, {member: ts})

        # Trim to keep only recent events (remove oldest beyond MAXLEN)
        count = await self._redis.zcard(stream_key)
        if count > REDIS_EVENT_STREAM_MAXLEN:
            await self._redis.zremrangebyrank(stream_key, 0, count - REDIS_EVENT_STREAM_MAXLEN - 1)

        # Set TTL for auto-cleanup
        await self._redis.expire(stream_key, REDIS_FEATURE_TTL)

    async def _get_recent_events(self, stream_key: str) -> list[dict]:
        """Retrieve all recent events for an agent from Redis."""
        import json

        # Get all members with scores (timestamps)
        raw = await self._redis.zrangebyscore(stream_key, "-inf", "+inf", withscores=False)
        events = []
        for member in raw:
            try:
                if isinstance(member, bytes):
                    member = member.decode("utf-8")
                events.append(json.loads(member))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
        return events

    async def _write_features(self, feature_key: str, features: dict[str, float]) -> None:
        """Write computed features to Redis HASH."""
        if not features:
            return
        # Convert all values to strings for Redis HASH
        str_features = {k: str(v) for k, v in features.items()}
        await self._redis.hset(feature_key, mapping=str_features)
        await self._redis.expire(feature_key, REDIS_FEATURE_TTL)

    async def get_features(self, tenant_id: str, agent_id: str) -> dict[str, float]:
        """Read the current feature vector for an agent.

        Returns feature_defaults() merged with whatever is in Redis.
        Used by the inference pipeline (J3) to score an agent.
        """
        feature_key = f"{REDIS_FEATURE_PREFIX}:{tenant_id}:{agent_id}"
        raw = await self._redis.hgetall(feature_key)
        defaults = feature_defaults()
        if not raw:
            return defaults
        for k, v in raw.items():
            key = k.decode("utf-8") if isinstance(k, bytes) else k
            val = v.decode("utf-8") if isinstance(v, bytes) else v
            with contextlib.suppress(ValueError, TypeError):
                defaults[key] = float(val)
        return defaults
