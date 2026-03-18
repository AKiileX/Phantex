# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Cloud Telemetry Ingestion Service (Q4).

Cloud-side service that receives anonymized telemetry from participating
customer deployments. Responsibilities:
1. Validate payload format and DP noise signature
2. Rate limit per anonymized tenant
3. Deduplicate records
4. Store in ClickHouse (cloud-side, separate from customer data)
5. Audit log all ingestion events

This code runs on the PHANTEX CLOUD side (not customer premises).
All data is anonymized — no PII, no raw prompts, GDPR/CCPA compliant.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from ml.telemetry.anonymizer import verify_dp_noise_signature
from ml.telemetry.config import CloudIngestionConfig

logger = structlog.get_logger("phantex.ml.telemetry.ingestion")

# ── Rate Limiter ─────────────────────────────────────────────────────────────

class TenantRateLimiter:
    """In-memory sliding window rate limiter per anonymized tenant.

    Limits the number of ingestion batches per tenant per hour.
    In production, this would be Redis-backed for multi-instance support.
    """

    _MAX_TRACKED_TENANTS = 100_000  # Cap to prevent memory exhaustion

    def __init__(self, max_per_hour: int = 60) -> None:
        self._max_per_hour = max_per_hour
        self._windows: dict[str, list[float]] = {}

    def is_allowed(self, tenant_hash: str) -> bool:
        """Check if a tenant is allowed to ingest (not rate-limited)."""
        now = time.time()
        window_start = now - 3600  # 1-hour window

        # Clean up old entries
        if tenant_hash in self._windows:
            self._windows[tenant_hash] = [ts for ts in self._windows[tenant_hash] if ts > window_start]

        timestamps = self._windows.get(tenant_hash, [])
        return not len(timestamps) >= self._max_per_hour

    def record(self, tenant_hash: str) -> None:
        """Record a successful ingestion for rate limiting."""
        # Evict oldest tenant if at capacity (prevent memory exhaustion)
        if tenant_hash not in self._windows and len(self._windows) >= self._MAX_TRACKED_TENANTS:
            # Evict the tenant with the oldest last-access
            oldest = min(self._windows, key=lambda k: self._windows[k][-1] if self._windows[k] else 0)
            del self._windows[oldest]
        if tenant_hash not in self._windows:
            self._windows[tenant_hash] = []
        self._windows[tenant_hash].append(time.time())

    def get_remaining(self, tenant_hash: str) -> int:
        """Get remaining quota for a tenant in the current window."""
        now = time.time()
        window_start = now - 3600
        timestamps = self._windows.get(tenant_hash, [])
        recent = [ts for ts in timestamps if ts > window_start]
        return max(0, self._max_per_hour - len(recent))

    def cleanup(self) -> int:
        """Remove expired entries. Returns count of tenants cleaned."""
        now = time.time()
        window_start = now - 3600
        cleaned = 0
        empty_keys = []
        for tenant_hash, timestamps in self._windows.items():
            before = len(timestamps)
            self._windows[tenant_hash] = [ts for ts in timestamps if ts > window_start]
            if len(self._windows[tenant_hash]) < before:
                cleaned += 1
            if not self._windows[tenant_hash]:
                empty_keys.append(tenant_hash)
        for key in empty_keys:
            del self._windows[key]
        return cleaned

# ── Deduplicator ─────────────────────────────────────────────────────────────

class RecordDeduplicator:
    """Deduplicates telemetry records within a time window.

    Uses a rolling set of record fingerprints (hash of tenant + timestamp + first 4 features).
    """

    _MAX_SEEN = 500_000  # Cap to prevent unbounded memory growth

    def __init__(self, window_seconds: int = 60) -> None:
        self._window_seconds = window_seconds
        self._seen: dict[str, float] = {}  # fingerprint → timestamp

    def _fingerprint(self, record: dict[str, Any]) -> str:
        """Compute a dedup fingerprint for a record."""
        key = (
            f"{record.get('anonymized_tenant_hash', '')}:{record.get('timestamp', 0)}:{record.get('attack_class', '')}"
        )
        # Include first 4 feature values for tighter dedup
        fv = record.get("feature_vector", [])
        for i in range(min(4, len(fv))):
            key += f":{round(fv[i], 4)}"

        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

    def is_duplicate(self, record: dict[str, Any]) -> bool:
        """Check if a record is a duplicate within the dedup window."""
        fp = self._fingerprint(record)
        now = time.time()

        if fp in self._seen and (now - self._seen[fp]) < self._window_seconds:
            return True

        # Evict oldest if at capacity
        if len(self._seen) >= self._MAX_SEEN:
            self.cleanup()

        self._seen[fp] = now
        return False

    def cleanup(self) -> int:
        """Remove expired fingerprints. Returns count removed."""
        now = time.time()
        expired = [fp for fp, ts in self._seen.items() if (now - ts) >= self._window_seconds]
        for fp in expired:
            del self._seen[fp]
        return len(expired)

# ── Ingestion Result ─────────────────────────────────────────────────────────

@dataclass
class IngestionOutcome:
    """Result of processing a single ingestion batch."""

    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.accepted + self.rejected + self.duplicates

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
        }

# ── Cloud Ingestion Service ──────────────────────────────────────────────────

class CloudIngestionService:
    """Receives, validates, deduplicates, and stores anonymized telemetry.

    Usage:
        service = CloudIngestionService(config, clickhouse_client)
        result = await service.ingest(batch_records, tenant_hash)
    """

    def __init__(
        self,
        config: CloudIngestionConfig | None = None,
        clickhouse_client=None,
    ) -> None:
        self._config = config or CloudIngestionConfig()
        self._ch = clickhouse_client
        self._rate_limiter = TenantRateLimiter(
            max_per_hour=self._config.max_batches_per_tenant_hour,
        )
        self._deduplicator = RecordDeduplicator(
            window_seconds=self._config.dedup_window_seconds,
        )
        self._total_ingested = 0
        self._total_batches = 0
        self._tenant_hashes_seen: set[str] = set()

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_records_ingested": self._total_ingested,
            "total_batches_received": self._total_batches,
            "unique_tenant_hashes": len(self._tenant_hashes_seen),
        }

    # ── Validate ─────────────────────────────────────────────────────

    _SAFE_TABLE_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$")

    def validate_record(self, record: dict[str, Any]) -> str | None:
        """Validate a single telemetry record.

        Returns None if valid, or an error message string.
        """
        # Check tenant hash format
        tenant_hash = record.get("anonymized_tenant_hash", "")
        if not isinstance(tenant_hash, str) or len(tenant_hash) != self._config.tenant_hash_length:
            return f"Invalid tenant hash length: {len(tenant_hash)}"

        # Check hex format
        try:
            int(tenant_hash, 16)
        except (ValueError, TypeError):
            return "Tenant hash is not valid hex"

        # Check feature vector
        fv = record.get("feature_vector")
        if not isinstance(fv, list) or len(fv) != self._config.n_features:
            expected = self._config.n_features
            actual = len(fv) if isinstance(fv, list) else "not a list"
            return f"Feature vector: expected {expected} dims, got {actual}"

        # Check for NaN/Inf in feature vector
        for i, val in enumerate(fv):
            if not isinstance(val, int | float):
                return f"Feature vector[{i}] is not numeric"
            if math.isnan(val) or math.isinf(val):
                return f"Feature vector[{i}] contains NaN/Inf"

        # Verify DP noise signature
        if not verify_dp_noise_signature(fv, self._config.n_features):
            return "Feature vector fails DP noise signature check"

        # Check confidence range
        confidence = record.get("confidence")
        if not isinstance(confidence, int | float) or confidence < 0 or confidence > 1:
            return f"Invalid confidence: {confidence}"

        # Check timestamp
        timestamp = record.get("timestamp")
        if not isinstance(timestamp, int | float):
            return f"Invalid timestamp type: {type(timestamp).__name__}"
        min_ts = 1577836800  # 2020-01-01
        max_ts = time.time() + 86400
        if timestamp < min_ts or timestamp > max_ts:
            return f"Timestamp out of range: {timestamp}"

        # Check attack_class
        attack_class = record.get("attack_class", "")
        if not isinstance(attack_class, str) or len(attack_class) > 100:
            return "Invalid attack_class"

        return None  # Valid

    # ── Rate Check ───────────────────────────────────────────────────

    def check_rate_limit(self, tenant_hash: str) -> bool:
        """Check if the tenant is within rate limits."""
        return self._rate_limiter.is_allowed(tenant_hash)

    # ── Ingest ───────────────────────────────────────────────────────

    async def ingest(
        self,
        records: list[dict[str, Any]],
        source_tenant_hash: str | None = None,
    ) -> IngestionOutcome:
        """Ingest a batch of anonymized telemetry records.

        Steps:
        1. Rate limit check (per anonymized tenant)
        2. Validate each record
        3. Deduplicate
        4. Store valid records

        Args:
            records: List of telemetry vector dicts.
            source_tenant_hash: Primary tenant hash for the batch (rate limiting).

        Returns:
            IngestionOutcome with counts.
        """
        outcome = IngestionOutcome()

        # Determine primary tenant hash from batch
        if source_tenant_hash is None and records:
            source_tenant_hash = records[0].get("anonymized_tenant_hash", "unknown")

        if source_tenant_hash:
            # Rate limit check
            if not self.check_rate_limit(source_tenant_hash):
                outcome.rejected = len(records)
                outcome.errors.append("Rate limit exceeded")
                logger.warning(
                    "telemetry_rate_limited",
                    tenant_hash=source_tenant_hash[:16] + "...",
                    remaining=self._rate_limiter.get_remaining(source_tenant_hash),
                )
                return outcome

            self._rate_limiter.record(source_tenant_hash)

        # Process each record
        valid_records = []
        for record in records:
            # Validate
            error = self.validate_record(record)
            if error:
                outcome.rejected += 1
                if len(outcome.errors) < 10:  # Cap error details
                    outcome.errors.append(error)
                continue

            # Dedup
            if self._deduplicator.is_duplicate(record):
                outcome.duplicates += 1
                continue

            valid_records.append(record)
            outcome.accepted += 1

        # Track tenant
        if source_tenant_hash:
            self._tenant_hashes_seen.add(source_tenant_hash)

        # Store valid records
        if valid_records:
            await self._store(valid_records)
            self._total_ingested += len(valid_records)

        self._total_batches += 1

        logger.info(
            "telemetry_batch_ingested",
            accepted=outcome.accepted,
            rejected=outcome.rejected,
            duplicates=outcome.duplicates,
            source_hash=source_tenant_hash[:16] + "..." if source_tenant_hash else None,
        )

        return outcome

    async def _store(self, records: list[dict[str, Any]]) -> None:
        """Store validated records in ClickHouse.

        In production, this inserts into the telemetry_vectors table.
        Without ClickHouse configured, records are just acknowledged
        (metrics are still tracked).
        """
        if self._ch is None:
            # No ClickHouse — metrics-only mode
            logger.debug(
                "telemetry_store_noop",
                records=len(records),
                reason="no_clickhouse_client",
            )
            return

        try:
            # Validate table name against allowlist
            table = self._config.clickhouse_table
            if not self._SAFE_TABLE_RE.match(table):
                raise ValueError(f"Invalid ClickHouse table name: {table!r}")

            # Build ClickHouse insert
            table = self._config.clickhouse_table
            rows = []
            for r in records:
                rows.append(
                    {
                        "tenant_hash": r["anonymized_tenant_hash"],
                        "feature_vector": r["feature_vector"],
                        "attack_class": r["attack_class"],
                        "confidence": r["confidence"],
                        "event_timestamp": r["timestamp"],
                        "ingested_at": time.time(),
                    }
                )

            await self._ch.insert(table, rows)
            logger.debug("telemetry_stored", table=table, rows=len(rows))

        except Exception:
            logger.exception(
                "telemetry_store_error",
                records=len(records),
            )
            # Don't re-raise — records are already accepted/acknowledged
            # ClickHouse storage is best-effort

    # ── Cleanup ──────────────────────────────────────────────────────

    def cleanup(self) -> dict[str, int]:
        """Run periodic cleanup on rate limiter and deduplicator."""
        rate_cleaned = self._rate_limiter.cleanup()
        dedup_cleaned = self._deduplicator.cleanup()
        return {
            "rate_limiter_tenants_cleaned": rate_cleaned,
            "dedup_fingerprints_cleaned": dedup_cleaned,
        }

    # ── Query ────────────────────────────────────────────────────────

    async def get_stats(self) -> dict[str, Any]:
        """Get ingestion statistics."""
        base = self.stats.copy()

        if self._ch is not None:
            try:
                # Query ClickHouse for storage stats
                table = self._config.clickhouse_table
                if not self._SAFE_TABLE_RE.match(table):
                    raise ValueError(f"Invalid ClickHouse table name: {table!r}")
                row = await self._ch.fetchrow(
                    f"""
                    SELECT
                        count() as total,
                        countDistinct(tenant_hash) as unique_tenants,
                        min(event_timestamp) as oldest,
                        max(event_timestamp) as newest
                    FROM {table}
                    """
                )
                if row:
                    base.update(
                        {
                            "records_in_storage": row["total"],
                            "unique_tenants_in_storage": row["unique_tenants"],
                            "oldest_record": row["oldest"],
                            "newest_record": row["newest"],
                        }
                    )
            except Exception:
                pass

        return base
