# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Block V1 — MCP Server Behavioral Profiler.

Builds and maintains behavioral baselines for each MCP server:
  - Response-time distribution (mean, stddev, p95, p99)
  - Content pattern signatures (response structure fingerprint)
  - Capability manifest (declared tools vs actually-used tools)
  - Activity rate (calls per hour, calls per day)

Detects anomalies when behavior deviates from the server's own baseline.
Thread-safe, tenant-isolated, time-windowed.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

# ── Anomaly severity ────────────────────────────────────────────────────────

class AnomalyType(StrEnum):
    LATENCY_SPIKE = "latency_spike"
    LATENCY_DROP = "latency_drop"
    CONTENT_DRIFT = "content_drift"
    CAPABILITY_CHANGE = "capability_change"
    RATE_SPIKE = "rate_spike"
    NEW_TOOL_ADDED = "new_tool_added"
    TOOL_REMOVED = "tool_removed"
    RESPONSE_SIZE_ANOMALY = "response_size_anomaly"

@dataclass(frozen=True)
class BehavioralAnomaly:
    """Single detected anomaly event."""

    anomaly_type: AnomalyType
    server_id: str
    tenant_id: str
    severity: float  # 0.0–1.0
    detail: str
    expected_value: float | str | None = None
    actual_value: float | str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

@dataclass
class ResponseSample:
    """Single MCP call observation."""

    timestamp: datetime
    tool_name: str
    latency_ms: float
    response_size: int
    status: str  # "ok" | "error"
    content_hash: str = ""  # SHA-256 of response structure

@dataclass
class ServerProfile:
    """Behavioral baseline for one MCP server."""

    server_id: str
    tenant_id: str
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Rolling window of observations (max 1000)
    samples: deque = field(default_factory=lambda: deque(maxlen=1000))

    # Capability manifest
    declared_tools: set[str] = field(default_factory=set)
    observed_tools: set[str] = field(default_factory=set)
    previous_tools: set[str] = field(default_factory=set)

    # Fingerprint of server capabilities (hash of sorted tool list)
    capability_hash: str = ""

    # Aggregated stats (computed from samples)
    latency_mean: float = 0.0
    latency_stddev: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0
    avg_response_size: float = 0.0
    error_rate: float = 0.0
    calls_per_hour: float = 0.0

    # Anomalies detected on this server
    anomaly_history: deque = field(default_factory=lambda: deque(maxlen=100))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to API-friendly dict."""
        return {
            "server_id": self.server_id,
            "tenant_id": self.tenant_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sample_count": len(self.samples),
            "declared_tools": sorted(self.declared_tools),
            "observed_tools": sorted(self.observed_tools),
            "capability_hash": self.capability_hash,
            "stats": {
                "latency_mean_ms": round(self.latency_mean, 2),
                "latency_stddev_ms": round(self.latency_stddev, 2),
                "latency_p95_ms": round(self.latency_p95, 2),
                "latency_p99_ms": round(self.latency_p99, 2),
                "avg_response_size": round(self.avg_response_size, 1),
                "error_rate": round(self.error_rate, 4),
                "calls_per_hour": round(self.calls_per_hour, 2),
            },
            "anomaly_count": len(self.anomaly_history),
            "recent_anomalies": [
                {
                    "type": a.anomaly_type.value,
                    "severity": round(a.severity, 3),
                    "detail": a.detail,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in list(self.anomaly_history)[-10:]
            ],
        }

# ── Profiler ────────────────────────────────────────────────────────────────

# Thresholds for anomaly detection (configurable)
DEFAULT_CONFIG = {
    "latency_z_threshold": 3.0,  # Z-score for latency anomaly
    "rate_spike_factor": 5.0,  # N× above avg → rate spike
    "response_size_z_threshold": 3.0,  # Z-score for response size
    "min_samples_for_baseline": 10,  # Min samples before anomaly detection
    "window_hours": 24,  # Rolling window for baseline
}

class MCPBehavioralProfiler:
    """Thread-safe behavioral profiler for MCP servers."""

    __slots__ = ("_lock", "_profiles", "_config", "_max_profiles")

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        max_profiles: int = 10_000,
    ) -> None:
        self._lock = threading.Lock()
        self._profiles: dict[tuple[str, str], ServerProfile] = {}
        self._config = {**DEFAULT_CONFIG, **(config or {})}
        self._max_profiles = max_profiles

    # ── Core API ────────────────────────────────────────────────────

    def record_call(
        self,
        tenant_id: str,
        server_id: str,
        tool_name: str,
        latency_ms: float,
        response_size: int,
        status: str = "ok",
        response_body: str | bytes | None = None,
    ) -> list[BehavioralAnomaly]:
        """Record an MCP call and return any anomalies detected."""
        now = datetime.now(UTC)
        content_hash = ""
        if response_body:
            raw = response_body if isinstance(response_body, bytes) else response_body.encode()
            content_hash = hashlib.sha256(raw).hexdigest()[:16]

        sample = ResponseSample(
            timestamp=now,
            tool_name=tool_name,
            latency_ms=latency_ms,
            response_size=response_size,
            status=status,
            content_hash=content_hash,
        )

        with self._lock:
            profile = self._get_or_create(tenant_id, server_id)
            profile.samples.append(sample)
            profile.last_seen = now
            profile.observed_tools.add(tool_name)

            # Recompute stats
            self._recompute_stats(profile)

            # Detect anomalies
            anomalies = self._detect_anomalies(profile, sample)
            for a in anomalies:
                profile.anomaly_history.append(a)

            return anomalies

    def update_capabilities(
        self,
        tenant_id: str,
        server_id: str,
        tools: list[str],
    ) -> list[BehavioralAnomaly]:
        """Update declared tool list. Detect capability changes."""
        now = datetime.now(UTC)
        new_tools = set(tools)

        with self._lock:
            profile = self._get_or_create(tenant_id, server_id)
            old_tools = profile.declared_tools.copy()
            old_hash = profile.capability_hash

            profile.declared_tools = new_tools
            new_hash = hashlib.sha256(json.dumps(sorted(new_tools)).encode()).hexdigest()[:16]
            profile.capability_hash = new_hash
            profile.previous_tools = old_tools
            profile.last_seen = now

            anomalies: list[BehavioralAnomaly] = []

            # If hash changed and we had a previous baseline, flag it
            if old_hash and old_hash != new_hash and old_tools:
                added = new_tools - old_tools
                removed = old_tools - new_tools

                for tool in added:
                    a = BehavioralAnomaly(
                        anomaly_type=AnomalyType.NEW_TOOL_ADDED,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        severity=0.7,
                        detail=f"New tool declared: {tool}",
                        expected_value=str(sorted(old_tools)),
                        actual_value=tool,
                        timestamp=now,
                    )
                    anomalies.append(a)
                    profile.anomaly_history.append(a)

                for tool in removed:
                    a = BehavioralAnomaly(
                        anomaly_type=AnomalyType.TOOL_REMOVED,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        severity=0.5,
                        detail=f"Tool removed from manifest: {tool}",
                        expected_value=tool,
                        actual_value=str(sorted(new_tools)),
                        timestamp=now,
                    )
                    anomalies.append(a)
                    profile.anomaly_history.append(a)

                # Overall capability change
                if added or removed:
                    a = BehavioralAnomaly(
                        anomaly_type=AnomalyType.CAPABILITY_CHANGE,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        severity=0.8 if added and removed else 0.6,
                        detail=f"Capability manifest changed: +{len(added)} -{len(removed)} tools",
                        expected_value=old_hash,
                        actual_value=new_hash,
                        timestamp=now,
                    )
                    anomalies.append(a)
                    profile.anomaly_history.append(a)

            return anomalies

    def get_profile(self, tenant_id: str, server_id: str) -> ServerProfile | None:
        """Return the behavioral profile for a server, or None."""
        with self._lock:
            return self._profiles.get((tenant_id, server_id))

    def list_profiles(self, tenant_id: str) -> list[ServerProfile]:
        """Return all profiles for a tenant."""
        with self._lock:
            return [p for k, p in self._profiles.items() if k[0] == tenant_id]

    def get_anomalies(self, tenant_id: str, server_id: str | None = None, limit: int = 50) -> list[BehavioralAnomaly]:
        """Return recent anomalies, optionally filtered by server."""
        with self._lock:
            all_anomalies: list[BehavioralAnomaly] = []
            for key, profile in self._profiles.items():
                if key[0] != tenant_id:
                    continue
                if server_id and key[1] != server_id:
                    continue
                all_anomalies.extend(profile.anomaly_history)

        # Sort by timestamp descending
        all_anomalies.sort(key=lambda a: a.timestamp, reverse=True)
        return all_anomalies[:limit]

    # ── Private ─────────────────────────────────────────────────────

    def _get_or_create(self, tenant_id: str, server_id: str) -> ServerProfile:
        """Get or create a profile. Must be called under lock."""
        key = (tenant_id, server_id)
        if key not in self._profiles:
            if len(self._profiles) >= self._max_profiles:
                # Evict oldest
                oldest_key = min(
                    self._profiles,
                    key=lambda k: self._profiles[k].last_seen,
                )
                del self._profiles[oldest_key]
            self._profiles[key] = ServerProfile(server_id=server_id, tenant_id=tenant_id)
        return self._profiles[key]

    def _recompute_stats(self, profile: ServerProfile) -> None:
        """Recompute aggregate statistics from the sample window."""
        window_cutoff = datetime.now(UTC) - timedelta(hours=self._config["window_hours"])
        recent = [s for s in profile.samples if s.timestamp >= window_cutoff]
        if not recent:
            return

        latencies = [s.latency_ms for s in recent]
        sizes = [s.response_size for s in recent]
        errors = sum(1 for s in recent if s.status == "error")

        profile.latency_mean = statistics.mean(latencies)
        profile.latency_stddev = statistics.stdev(latencies) if len(latencies) > 1 else 0
        sorted_lat = sorted(latencies)
        profile.latency_p95 = sorted_lat[int(len(sorted_lat) * 0.95)] if len(sorted_lat) > 1 else sorted_lat[0]
        profile.latency_p99 = sorted_lat[int(len(sorted_lat) * 0.99)] if len(sorted_lat) > 1 else sorted_lat[0]
        profile.avg_response_size = statistics.mean(sizes) if sizes else 0
        profile.error_rate = errors / len(recent) if recent else 0

        # Calls per hour
        if len(recent) > 1:
            span = (recent[-1].timestamp - recent[0].timestamp).total_seconds()
            if span > 0:
                profile.calls_per_hour = len(recent) / (span / 3600)

    def _detect_anomalies(self, profile: ServerProfile, sample: ResponseSample) -> list[BehavioralAnomaly]:
        """Check the latest sample against the profile baseline."""
        min_samples = self._config["min_samples_for_baseline"]
        if len(profile.samples) < min_samples:
            return []

        anomalies: list[BehavioralAnomaly] = []

        # ── Latency anomaly ──
        if profile.latency_stddev > 0:
            z = (sample.latency_ms - profile.latency_mean) / profile.latency_stddev
            threshold = self._config["latency_z_threshold"]

            if z > threshold:
                anomalies.append(
                    BehavioralAnomaly(
                        anomaly_type=AnomalyType.LATENCY_SPIKE,
                        server_id=profile.server_id,
                        tenant_id=profile.tenant_id,
                        severity=min(1.0, z / (threshold * 2)),
                        detail=f"Response latency {sample.latency_ms:.0f}ms is {z:.1f}σ above mean ({profile.latency_mean:.0f}ms)",
                        expected_value=profile.latency_mean,
                        actual_value=sample.latency_ms,
                    )
                )
            elif z < -threshold and sample.latency_ms < profile.latency_mean * 0.1:
                anomalies.append(
                    BehavioralAnomaly(
                        anomaly_type=AnomalyType.LATENCY_DROP,
                        server_id=profile.server_id,
                        tenant_id=profile.tenant_id,
                        severity=0.4,
                        detail=f"Suspiciously fast response {sample.latency_ms:.0f}ms vs mean {profile.latency_mean:.0f}ms (possible pre-cached/proxy)",
                        expected_value=profile.latency_mean,
                        actual_value=sample.latency_ms,
                    )
                )

        # ── Response size anomaly ──
        if profile.avg_response_size > 0 and len(profile.samples) > min_samples:
            sizes = [s.response_size for s in profile.samples]
            size_stddev = statistics.stdev(sizes) if len(sizes) > 1 else 0
            if size_stddev > 0:
                z = (sample.response_size - profile.avg_response_size) / size_stddev
                if abs(z) > self._config["response_size_z_threshold"]:
                    anomalies.append(
                        BehavioralAnomaly(
                            anomaly_type=AnomalyType.RESPONSE_SIZE_ANOMALY,
                            server_id=profile.server_id,
                            tenant_id=profile.tenant_id,
                            severity=min(1.0, abs(z) / 6.0),
                            detail=f"Response size {sample.response_size}B is {z:.1f}σ from mean ({profile.avg_response_size:.0f}B)",
                            expected_value=profile.avg_response_size,
                            actual_value=sample.response_size,
                        )
                    )

        return anomalies

    # ── Introspection ───────────────────────────────────────────────

    def __len__(self) -> int:
        with self._lock:
            return len(self._profiles)
