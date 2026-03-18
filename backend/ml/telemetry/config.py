# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Telemetry Export Configuration (Q3).

Centralized settings for anonymized telemetry export.
Kill switch: PHANTEX_TELEMETRY_EXPORT=false overrides everything.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

def _default_hmac_key() -> str:
    """Read HMAC key from env, fall back to dev marker."""
    return os.environ.get(
        "PHANTEX_TELEMETRY_HMAC_KEY",
        "phantex-telemetry-hash-key-change-in-production",
    )

@dataclass(frozen=True)
class TelemetryExportConfig:
    """Configuration for anonymized telemetry export (Q3).

    Privacy guarantees:
    - Only feature vectors (statistical summaries) — never raw data
    - Differential privacy noise on every exported vector
    - Tenant ID hashed (HMAC-SHA256, not reversible)
    - Opt-in only, default OFF
    """

    # ── Kill Switch ──────────────────────────────────────────────────
    # PHANTEX_TELEMETRY_EXPORT=false env var overrides everything.
    # Checked at runtime, not just at config load.
    kill_switch_env: str = "PHANTEX_TELEMETRY_EXPORT"

    # ── Differential Privacy ─────────────────────────────────────────
    # Epsilon for Laplacian noise on feature vectors.
    # Lower ε = more privacy, more noise. Default 2.0 is moderate.
    dp_epsilon: float = 2.0
    # L1 sensitivity of individual feature values (max single-user impact)
    dp_sensitivity: float = 1.0

    # ── Export Batching ──────────────────────────────────────────────
    # Buffer exports and upload every N seconds (default: 15 min)
    batch_interval_seconds: int = 900  # 15 minutes
    # Maximum records per batch upload
    max_batch_size: int = 10_000
    # Maximum age of a record in the buffer before forced flush (1h)
    max_record_age_seconds: int = 3600

    # ── Tenant Anonymization ─────────────────────────────────────────
    # HMAC key for tenant ID hashing — MUST be overridden in production.
    # Set PHANTEX_TELEMETRY_HMAC_KEY env var (from Vault).
    tenant_hash_key: str = field(default_factory=_default_hmac_key)
    _DEV_HMAC_KEY: str = "phantex-telemetry-hash-key-change-in-production"

    # ── Feature Vector ───────────────────────────────────────────────
    # Number of features expected (must match ML pipeline)
    n_features: int = 62

    # ── Export Endpoint ──────────────────────────────────────────────
    # Where to send telemetry (Phantex Cloud ingestion URL)
    cloud_endpoint: str = ""  # Empty = disabled (no cloud yet)
    # Request timeout for uploads
    upload_timeout_seconds: int = 30
    # Retry count for failed uploads
    upload_retries: int = 3

    # ── Viewer Buffer ────────────────────────────────────────────────
    # How many recent export payloads to keep for admin review
    viewer_buffer_size: int = 500

@dataclass(frozen=True)
class CloudIngestionConfig:
    """Configuration for the cloud-side ingestion service (Q4).

    Receives anonymized telemetry from participating deployments.
    """

    # ── Rate Limiting ────────────────────────────────────────────────
    # Max batches per anonymized tenant per hour
    max_batches_per_tenant_hour: int = 60
    # Max records per single batch
    max_records_per_batch: int = 10_000
    # Max body size (bytes) for a single ingestion request
    max_body_bytes: int = 10 * 1024 * 1024  # 10 MB

    # ── Validation ───────────────────────────────────────────────────
    n_features: int = 62
    # Tenant hash format: hex-encoded HMAC-SHA256 (64 chars)
    tenant_hash_length: int = 64

    # ── Storage ──────────────────────────────────────────────────────
    # ClickHouse table for telemetry storage
    clickhouse_table: str = "telemetry_vectors"
    # Data retention (days)
    retention_days: int = 90

    # ── Deduplication ────────────────────────────────────────────────
    # Window for record dedup (same tenant_hash + timestamp)
    dedup_window_seconds: int = 60

def is_telemetry_kill_switch_active() -> bool:
    """Check if the global kill switch is active.

    Returns True if telemetry should be BLOCKED (kill switch ON).
    The env var PHANTEX_TELEMETRY_EXPORT defaults to "true" (allowed).
    Set to "false" to kill all telemetry export globally.
    """
    val = os.environ.get("PHANTEX_TELEMETRY_EXPORT", "true").lower().strip()
    # If explicitly set to false/0/no → kill switch is active (block export)
    return val in ("false", "0", "no", "off")
