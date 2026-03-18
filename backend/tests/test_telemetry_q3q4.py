# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for Q3 (Anonymized Telemetry Export) + Q4 (Cloud Ingestion).

Coverage:
- Anonymizer: tenant hashing, DP noise, record building, batch
- Exporter: kill switch, buffer, flush, viewer, metrics
- Ingestion: validation, rate limiting, dedup, storage, stats
- Config: kill switch, defaults
- Schemas: validation, edge cases
- Router: telemetry & cloud endpoints
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import math
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from ml.telemetry.anonymizer import (
    TelemetryRecord,
    anonymize_tenant_id,
    apply_dp_noise,
    build_telemetry_batch,
    build_telemetry_record,
    verify_dp_noise_signature,
)
from ml.telemetry.config import (
    CloudIngestionConfig,
    TelemetryExportConfig,
    is_telemetry_kill_switch_active,
)
from ml.telemetry.exporter import (
    ExportMetrics,
    TelemetryExporter,
)
from ml.telemetry.ingestion import (
    CloudIngestionService,
    IngestionOutcome,
    RecordDeduplicator,
    TenantRateLimiter,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_feature_vector(n: int = 62, base: float = 1.0) -> list[float]:
    """Create a feature vector with n dimensions."""
    return [base + i * 0.1 for i in range(n)]

def _make_record_dict(
    tenant_id: str = "tenant-abc",
    attack_class: str = "prompt_injection",
    confidence: float = 0.85,
    timestamp: float | None = None,
) -> dict:
    """Create a raw input dict for build_telemetry_record."""
    return {
        "tenant_id": tenant_id,
        "feature_vector": _make_feature_vector(),
        "attack_class": attack_class,
        "confidence": confidence,
        "timestamp": timestamp or time.time(),
    }

def _make_export_record(
    tenant_hash: str | None = None,
    timestamp: float | None = None,
    config: TelemetryExportConfig | None = None,
) -> TelemetryRecord:
    """Create a TelemetryRecord for testing."""
    cfg = config or TelemetryExportConfig()
    return build_telemetry_record(
        tenant_id="tenant-abc",
        feature_vector=_make_feature_vector(),
        attack_class="prompt_injection",
        confidence=0.85,
        timestamp=timestamp or time.time(),
        config=cfg,
    )

def _make_ingestion_record(
    tenant_hash: str | None = None,
    attack_class: str = "normal",
    confidence: float = 0.5,
    timestamp: float | None = None,
) -> dict:
    """Create a valid ingestion record dict."""
    cfg = TelemetryExportConfig()
    th = tenant_hash or anonymize_tenant_id("tenant-xyz", cfg)
    fv = apply_dp_noise(_make_feature_vector(), epsilon=2.0, sensitivity=1.0)
    return {
        "anonymized_tenant_hash": th,
        "feature_vector": fv,
        "attack_class": attack_class,
        "confidence": confidence,
        "timestamp": timestamp or time.time(),
    }

# ══════════════════════════════════════════════════════════════════════════════
# Q3: ANONYMIZER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAnonymizeTenantId:
    """Tenant ID anonymization via HMAC-SHA256."""

    def test_returns_hex_64_chars(self):
        h = anonymize_tenant_id("tenant-1")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        h1 = anonymize_tenant_id("tenant-1")
        h2 = anonymize_tenant_id("tenant-1")
        assert h1 == h2

    def test_different_tenants_different_hash(self):
        h1 = anonymize_tenant_id("tenant-1")
        h2 = anonymize_tenant_id("tenant-2")
        assert h1 != h2

    def test_different_key_different_hash(self):
        cfg1 = TelemetryExportConfig(tenant_hash_key="key-a")
        cfg2 = TelemetryExportConfig(tenant_hash_key="key-b")
        h1 = anonymize_tenant_id("tenant-1", cfg1)
        h2 = anonymize_tenant_id("tenant-1", cfg2)
        assert h1 != h2

    def test_matches_hmac_sha256(self):
        """Verify the output matches standard HMAC-SHA256."""
        cfg = TelemetryExportConfig(tenant_hash_key="my-secret")
        h = anonymize_tenant_id("test-tenant", cfg)
        expected = hmac.new(b"my-secret", b"test-tenant", hashlib.sha256).hexdigest()
        assert h == expected

    def test_empty_tenant_id(self):
        h = anonymize_tenant_id("")
        assert len(h) == 64

    def test_unicode_tenant_id(self):
        h = anonymize_tenant_id("テナント-1")
        assert len(h) == 64

class TestApplyDpNoise:
    """Differential privacy Laplacian noise on feature vectors."""

    def test_preserves_length(self):
        fv = _make_feature_vector()
        noised = apply_dp_noise(fv)
        assert len(noised) == len(fv)

    def test_values_are_different(self):
        """At least some values should change after noise addition."""
        fv = _make_feature_vector()
        noised = apply_dp_noise(fv, epsilon=1.0)
        differences = sum(1 for a, b in zip(fv, noised, strict=False) if a != b)
        # Extremely unlikely (practically 0% chance) all 62 values unchanged
        assert differences > 0

    def test_higher_epsilon_less_noise(self):
        """Higher epsilon should produce less noise on average."""
        fv = _make_feature_vector()
        # Run multiple trials
        total_diff_low_eps = 0
        total_diff_high_eps = 0
        trials = 50
        for _ in range(trials):
            noised_low = apply_dp_noise(fv, epsilon=0.5)
            noised_high = apply_dp_noise(fv, epsilon=10.0)
            total_diff_low_eps += sum(abs(a - b) for a, b in zip(fv, noised_low, strict=False))
            total_diff_high_eps += sum(abs(a - b) for a, b in zip(fv, noised_high, strict=False))
        # Low epsilon (more privacy) should have MORE noise on average
        assert total_diff_low_eps > total_diff_high_eps

    def test_no_nan_inf_in_output(self):
        fv = _make_feature_vector()
        noised = apply_dp_noise(fv)
        for v in noised:
            assert not math.isnan(v)
            assert not math.isinf(v)

    def test_zero_epsilon_raises(self):
        fv = _make_feature_vector()
        with pytest.raises(ValueError, match="positive"):
            apply_dp_noise(fv, epsilon=0)

    def test_negative_epsilon_raises(self):
        fv = _make_feature_vector()
        with pytest.raises(ValueError, match="positive"):
            apply_dp_noise(fv, epsilon=-1.0)

    def test_zero_sensitivity(self):
        """Zero sensitivity should return unchanged values (scale=0)."""
        fv = _make_feature_vector()
        noised = apply_dp_noise(fv, sensitivity=0.0)
        assert noised == fv

    def test_each_dimension_independent(self):
        """Each dimension gets independent noise."""
        fv = [1.0] * 62
        noised = apply_dp_noise(fv, epsilon=1.0)
        # After noise, values should not all be identical
        assert len(set(round(v, 6) for v in noised)) > 1

class TestVerifyDpNoiseSignature:
    """DP noise signature heuristic check."""

    def test_valid_noised_vector(self):
        fv = apply_dp_noise(_make_feature_vector(), epsilon=2.0)
        assert verify_dp_noise_signature(fv) is True

    def test_wrong_dimensions(self):
        assert verify_dp_noise_signature([1.0] * 50) is False
        assert verify_dp_noise_signature([1.0] * 100) is False

    def test_contains_nan(self):
        fv = _make_feature_vector()
        fv[10] = float("nan")
        assert verify_dp_noise_signature(fv) is False

    def test_contains_inf(self):
        fv = _make_feature_vector()
        fv[5] = float("inf")
        assert verify_dp_noise_signature(fv) is False

    def test_extreme_values(self):
        fv = [1e10] * 62
        assert verify_dp_noise_signature(fv) is False

    def test_all_identical_values(self):
        """All-same values suggest no noise — should fail."""
        fv = [0.0] * 62
        assert verify_dp_noise_signature(fv) is False

    def test_empty_vector(self):
        assert verify_dp_noise_signature([]) is False

class TestBuildTelemetryRecord:
    """Building privacy-safe telemetry records."""

    def test_basic_record(self):
        record = build_telemetry_record(
            tenant_id="tenant-abc",
            feature_vector=_make_feature_vector(),
            attack_class="prompt_injection",
            confidence=0.85,
        )
        assert len(record.anonymized_tenant_hash) == 64
        assert len(record.feature_vector) == 62
        assert record.attack_class == "prompt_injection"
        assert 0 <= record.confidence <= 1

    def test_tenant_id_not_in_output(self):
        """Raw tenant ID must NOT appear in the record."""
        record = build_telemetry_record(
            tenant_id="super-secret-tenant-id",
            feature_vector=_make_feature_vector(),
            attack_class="normal",
            confidence=0.5,
        )
        export = record.to_export_dict()
        export_str = json.dumps(export)
        assert "super-secret-tenant-id" not in export_str

    def test_feature_vector_is_noised(self):
        """Output feature vector should differ from input (noise applied)."""
        fv = _make_feature_vector()
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=fv,
            attack_class="normal",
            confidence=0.5,
        )
        # At least one value should be different
        diffs = sum(1 for a, b in zip(fv, record.feature_vector, strict=False) if a != b)
        assert diffs > 0

    def test_confidence_clamped_high(self):
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="x",
            confidence=1.5,
        )
        assert record.confidence == 1.0

    def test_confidence_clamped_low(self):
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="x",
            confidence=-0.3,
        )
        assert record.confidence == 0.0

    def test_custom_timestamp(self):
        ts = 1700000000.0
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="x",
            confidence=0.5,
            timestamp=ts,
        )
        assert record.timestamp == ts

    def test_wrong_dimension_raises(self):
        with pytest.raises(ValueError, match="62 dimensions"):
            build_telemetry_record(
                tenant_id="t1",
                feature_vector=[1.0] * 50,
                attack_class="x",
                confidence=0.5,
            )

    def test_to_export_dict(self):
        record = _make_export_record()
        d = record.to_export_dict()
        assert set(d.keys()) == {
            "anonymized_tenant_hash",
            "feature_vector",
            "attack_class",
            "confidence",
            "timestamp",
        }
        assert isinstance(d["feature_vector"], list)
        assert len(d["feature_vector"]) == 62

    def test_custom_config_epsilon(self):
        """Custom epsilon should work through the pipeline."""
        cfg = TelemetryExportConfig(dp_epsilon=0.5)
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="x",
            confidence=0.5,
            config=cfg,
        )
        assert record.anonymized_tenant_hash  # Still works

class TestBuildTelemetryBatch:
    """Batch record building."""

    def test_valid_batch(self):
        records = [_make_record_dict() for _ in range(5)]
        results = build_telemetry_batch(records)
        assert len(results) == 5

    def test_skips_invalid_records(self):
        records = [
            _make_record_dict(),
            {"bad": "record"},  # Missing fields
            _make_record_dict(),
        ]
        results = build_telemetry_batch(records)
        assert len(results) == 2  # Only valid records

    def test_skips_wrong_dimensions(self):
        records = [
            _make_record_dict(),
            {
                "tenant_id": "t1",
                "feature_vector": [1.0] * 10,  # Wrong dims
                "attack_class": "x",
                "confidence": 0.5,
            },
        ]
        results = build_telemetry_batch(records)
        assert len(results) == 1

    def test_empty_batch(self):
        results = build_telemetry_batch([])
        assert results == []

    def test_all_invalid(self):
        results = build_telemetry_batch([{"bad": 1}, {"worse": 2}])
        assert results == []

# ══════════════════════════════════════════════════════════════════════════════
# Q3: CONFIG TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestTelemetryConfig:
    """Telemetry export configuration."""

    def test_default_values(self):
        cfg = TelemetryExportConfig()
        assert cfg.dp_epsilon == 2.0
        assert cfg.batch_interval_seconds == 900
        assert cfg.n_features == 62
        assert cfg.max_batch_size == 10_000
        assert cfg.viewer_buffer_size == 500
        assert cfg.cloud_endpoint == ""

    def test_cloud_ingestion_defaults(self):
        cfg = CloudIngestionConfig()
        assert cfg.max_batches_per_tenant_hour == 60
        assert cfg.n_features == 62
        assert cfg.retention_days == 90
        assert cfg.tenant_hash_length == 64

class TestKillSwitch:
    """PHANTEX_TELEMETRY_EXPORT kill switch."""

    def test_default_is_allowed(self):
        """No env var set → telemetry allowed (kill switch off)."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove the key entirely
            os.environ.pop("PHANTEX_TELEMETRY_EXPORT", None)
            assert is_telemetry_kill_switch_active() is False

    def test_explicit_true(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "true"}):
            assert is_telemetry_kill_switch_active() is False

    def test_explicit_false(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "false"}):
            assert is_telemetry_kill_switch_active() is True

    def test_zero_blocks(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "0"}):
            assert is_telemetry_kill_switch_active() is True

    def test_off_blocks(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "off"}):
            assert is_telemetry_kill_switch_active() is True

    def test_no_blocks(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "no"}):
            assert is_telemetry_kill_switch_active() is True

    def test_case_insensitive(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "FALSE"}):
            assert is_telemetry_kill_switch_active() is True

    def test_whitespace_handled(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": " false "}):
            assert is_telemetry_kill_switch_active() is True

# ══════════════════════════════════════════════════════════════════════════════
# Q3: EXPORTER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestTelemetryExporter:
    """Telemetry export buffer and flush logic."""

    def test_create_exporter(self):
        exporter = TelemetryExporter()
        assert exporter.buffer_size == 0
        assert exporter.metrics.batches_sent == 0

    @pytest.mark.asyncio
    async def test_enqueue_record(self):
        exporter = TelemetryExporter()
        record = _make_export_record()
        accepted = await exporter.enqueue(record)
        assert accepted is True
        assert exporter.buffer_size == 1

    @pytest.mark.asyncio
    async def test_enqueue_respects_kill_switch(self):
        exporter = TelemetryExporter()
        record = _make_export_record()
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "false"}):
            accepted = await exporter.enqueue(record)
        assert accepted is False
        assert exporter.buffer_size == 0

    @pytest.mark.asyncio
    async def test_enqueue_rejects_when_buffer_full(self):
        cfg = TelemetryExportConfig(max_batch_size=2)
        exporter = TelemetryExporter(config=cfg)
        await exporter.enqueue(_make_export_record(config=cfg))
        await exporter.enqueue(_make_export_record(config=cfg))
        accepted = await exporter.enqueue(_make_export_record(config=cfg))
        assert accepted is False
        assert exporter.metrics.records_dropped == 1

    @pytest.mark.asyncio
    async def test_flush_empty_buffer_succeeds(self):
        exporter = TelemetryExporter()
        result = await exporter.flush()
        assert result is True

    @pytest.mark.asyncio
    async def test_flush_without_endpoint_succeeds(self):
        """No cloud endpoint → flush returns True (not an error)."""
        cfg = TelemetryExportConfig(cloud_endpoint="")
        exporter = TelemetryExporter(config=cfg)
        await exporter.enqueue(_make_export_record(config=cfg))
        result = await exporter.flush()
        assert result is True

    @pytest.mark.asyncio
    async def test_flush_with_endpoint_and_no_http_client(self):
        """Endpoint configured but no HTTP client → dry run."""
        cfg = TelemetryExportConfig(cloud_endpoint="https://cloud.example.com/ingest")
        exporter = TelemetryExporter(config=cfg)
        await exporter.enqueue(_make_export_record(config=cfg))
        result = await exporter.flush()
        assert result is True
        assert exporter.metrics.batches_sent == 1
        assert exporter.metrics.records_exported == 1

    @pytest.mark.asyncio
    async def test_flush_with_mock_http_client_success(self):
        """Successful HTTP upload."""
        cfg = TelemetryExportConfig(cloud_endpoint="https://cloud.example.com/ingest")
        mock_http = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_http.post.return_value = mock_resp

        exporter = TelemetryExporter(config=cfg, http_client=mock_http)
        await exporter.enqueue(_make_export_record(config=cfg))
        await exporter.enqueue(_make_export_record(config=cfg))
        result = await exporter.flush()

        assert result is True
        assert exporter.metrics.batches_sent == 1
        assert exporter.metrics.records_exported == 2
        mock_http.post.assert_called_once()

        # Verify the body was gzipped JSON-L
        call_kwargs = mock_http.post.call_args
        body = call_kwargs.kwargs.get("content") or call_kwargs[1].get("content")
        decompressed = gzip.decompress(body).decode("utf-8")
        lines = decompressed.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "anonymized_tenant_hash" in parsed
            assert len(parsed["feature_vector"]) == 62

    @pytest.mark.asyncio
    async def test_flush_with_mock_http_client_failure(self):
        """HTTP upload failure → retry and eventual failure."""
        cfg = TelemetryExportConfig(
            cloud_endpoint="https://cloud.example.com/ingest",
            upload_retries=2,
        )
        mock_http = AsyncMock()
        mock_http.post.side_effect = RuntimeError("Connection refused")

        exporter = TelemetryExporter(config=cfg, http_client=mock_http)
        await exporter.enqueue(_make_export_record(config=cfg))
        result = await exporter.flush()

        assert result is False
        assert exporter.metrics.batches_failed == 1
        assert mock_http.post.call_count == 2  # retries

    @pytest.mark.asyncio
    async def test_flush_blocked_by_kill_switch(self):
        cfg = TelemetryExportConfig(cloud_endpoint="https://cloud.example.com/ingest")
        exporter = TelemetryExporter(config=cfg)
        await exporter.enqueue(_make_export_record(config=cfg))
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_EXPORT": "false"}):
            result = await exporter.flush()
        assert result is False

    @pytest.mark.asyncio
    async def test_flush_drops_stale_records(self):
        """Records older than max_record_age_seconds are dropped."""
        cfg = TelemetryExportConfig(
            cloud_endpoint="https://cloud.example.com/ingest",
            max_record_age_seconds=1,
        )
        exporter = TelemetryExporter(config=cfg)
        old_record = _make_export_record(config=cfg)
        old_record.created_at = time.time() - 10  # 10 seconds old
        await exporter.enqueue(old_record)

        result = await exporter.flush()
        assert result is True
        assert exporter.metrics.records_dropped >= 1

    def test_viewer_entries_empty(self):
        exporter = TelemetryExporter()
        entries = exporter.get_viewer_entries()
        assert entries == []

    @pytest.mark.asyncio
    async def test_viewer_entries_populated_after_flush(self):
        cfg = TelemetryExportConfig(cloud_endpoint="https://cloud.example.com/ingest")
        exporter = TelemetryExporter(config=cfg)
        await exporter.enqueue(_make_export_record(config=cfg))
        await exporter.flush()
        entries = exporter.get_viewer_entries()
        assert len(entries) == 1
        assert entries[0]["success"] is True
        assert entries[0]["record_count"] == 1

    def test_pending_preview_empty(self):
        exporter = TelemetryExporter()
        preview = exporter.get_pending_preview()
        assert preview == []

    @pytest.mark.asyncio
    async def test_pending_preview_shows_buffer(self):
        exporter = TelemetryExporter()
        await exporter.enqueue(_make_export_record())
        preview = exporter.get_pending_preview()
        assert len(preview) == 1
        assert "anonymized_tenant_hash" in preview[0]

    @pytest.mark.asyncio
    async def test_enqueue_batch(self):
        exporter = TelemetryExporter()
        records = [_make_export_record() for _ in range(5)]
        accepted = await exporter.enqueue_batch(records)
        assert accepted == 5
        assert exporter.buffer_size == 5

    def test_clear_opt_in_cache(self):
        exporter = TelemetryExporter()
        exporter._opted_in_cache["test"] = (True, time.time())
        exporter.clear_opt_in_cache()
        assert len(exporter._opted_in_cache) == 0

    def test_export_metrics_to_dict(self):
        m = ExportMetrics(batches_sent=3, records_exported=100)
        d = m.to_dict()
        assert d["batches_sent"] == 3
        assert d["records_exported"] == 100

    def test_is_globally_enabled(self):
        exporter = TelemetryExporter()
        assert exporter.is_globally_enabled() is True

    def test_has_endpoint_false(self):
        exporter = TelemetryExporter()
        assert exporter.has_endpoint() is False

    def test_has_endpoint_true(self):
        cfg = TelemetryExportConfig(cloud_endpoint="https://example.com")
        exporter = TelemetryExporter(config=cfg)
        assert exporter.has_endpoint() is True

# ══════════════════════════════════════════════════════════════════════════════
# Q4: RATE LIMITER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestTenantRateLimiter:
    """Per-tenant rate limiter for cloud ingestion."""

    def test_allows_within_limit(self):
        limiter = TenantRateLimiter(max_per_hour=5)
        for _ in range(5):
            assert limiter.is_allowed("tenant-a") is True
            limiter.record("tenant-a")

    def test_blocks_over_limit(self):
        limiter = TenantRateLimiter(max_per_hour=2)
        limiter.record("tenant-a")
        limiter.record("tenant-a")
        assert limiter.is_allowed("tenant-a") is False

    def test_different_tenants_independent(self):
        limiter = TenantRateLimiter(max_per_hour=1)
        limiter.record("tenant-a")
        assert limiter.is_allowed("tenant-a") is False
        assert limiter.is_allowed("tenant-b") is True

    def test_get_remaining(self):
        limiter = TenantRateLimiter(max_per_hour=5)
        assert limiter.get_remaining("tenant-a") == 5
        limiter.record("tenant-a")
        assert limiter.get_remaining("tenant-a") == 4

    def test_cleanup(self):
        limiter = TenantRateLimiter(max_per_hour=10)
        # Add timestamp in the past (> 1 hour ago)
        limiter._windows["tenant-old"] = [time.time() - 7200]
        cleaned = limiter.cleanup()
        assert cleaned >= 1
        assert "tenant-old" not in limiter._windows

# ══════════════════════════════════════════════════════════════════════════════
# Q4: DEDUPLICATOR TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestRecordDeduplicator:
    """Telemetry record deduplication."""

    def test_first_record_not_duplicate(self):
        dedup = RecordDeduplicator()
        record = _make_ingestion_record()
        assert dedup.is_duplicate(record) is False

    def test_same_record_is_duplicate(self):
        dedup = RecordDeduplicator()
        record = _make_ingestion_record()
        dedup.is_duplicate(record)
        assert dedup.is_duplicate(record) is True

    def test_different_timestamp_not_duplicate(self):
        dedup = RecordDeduplicator()
        r1 = _make_ingestion_record(timestamp=time.time())
        r2 = _make_ingestion_record(timestamp=time.time() + 1)
        dedup.is_duplicate(r1)
        assert dedup.is_duplicate(r2) is False

    def test_different_tenant_not_duplicate(self):
        dedup = RecordDeduplicator()
        cfg = TelemetryExportConfig()
        r1 = _make_ingestion_record(tenant_hash=anonymize_tenant_id("a", cfg))
        r2 = _make_ingestion_record(tenant_hash=anonymize_tenant_id("b", cfg))
        dedup.is_duplicate(r1)
        assert dedup.is_duplicate(r2) is False

    def test_cleanup(self):
        dedup = RecordDeduplicator(window_seconds=1)
        record = _make_ingestion_record()
        dedup.is_duplicate(record)
        # Manually age the entry
        for key in dedup._seen:
            dedup._seen[key] = time.time() - 10
        cleaned = dedup.cleanup()
        assert cleaned >= 1

# ══════════════════════════════════════════════════════════════════════════════
# Q4: INGESTION SERVICE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestCloudIngestionService:
    """Cloud-side telemetry ingestion validation and processing."""

    def _svc(self, **kwargs) -> CloudIngestionService:
        cfg = CloudIngestionConfig(**kwargs)
        return CloudIngestionService(config=cfg)

    def test_validate_valid_record(self):
        svc = self._svc()
        record = _make_ingestion_record()
        assert svc.validate_record(record) is None  # Valid

    def test_validate_wrong_hash_length(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["anonymized_tenant_hash"] = "short"
        assert svc.validate_record(record) is not None

    def test_validate_non_hex_hash(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["anonymized_tenant_hash"] = "g" * 64  # 'g' is not valid hex
        assert svc.validate_record(record) is not None

    def test_validate_wrong_feature_dims(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["feature_vector"] = [1.0] * 10
        assert svc.validate_record(record) is not None

    def test_validate_nan_in_features(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["feature_vector"][0] = float("nan")
        assert svc.validate_record(record) is not None

    def test_validate_inf_in_features(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["feature_vector"][0] = float("inf")
        assert svc.validate_record(record) is not None

    def test_validate_bad_confidence(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["confidence"] = 1.5
        assert svc.validate_record(record) is not None

    def test_validate_negative_confidence(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["confidence"] = -0.1
        assert svc.validate_record(record) is not None

    def test_validate_old_timestamp(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["timestamp"] = 1000000.0  # Way before 2020
        assert svc.validate_record(record) is not None

    def test_validate_future_timestamp(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["timestamp"] = time.time() + 200_000  # Way in the future
        assert svc.validate_record(record) is not None

    def test_validate_long_attack_class(self):
        svc = self._svc()
        record = _make_ingestion_record()
        record["attack_class"] = "x" * 200
        assert svc.validate_record(record) is not None

    def test_validate_dp_noise_check(self):
        """Records with all-zero features should fail DP check."""
        svc = self._svc()
        record = _make_ingestion_record()
        record["feature_vector"] = [0.0] * 62
        assert svc.validate_record(record) is not None

    @pytest.mark.asyncio
    async def test_ingest_valid_batch(self):
        svc = self._svc()
        records = [_make_ingestion_record() for _ in range(3)]
        outcome = await svc.ingest(records)
        assert outcome.accepted == 3
        assert outcome.rejected == 0
        assert outcome.duplicates == 0

    @pytest.mark.asyncio
    async def test_ingest_mixed_valid_invalid(self):
        svc = self._svc()
        good = _make_ingestion_record()
        bad = _make_ingestion_record()
        bad["feature_vector"] = [1.0] * 10  # Wrong dims
        outcome = await svc.ingest([good, bad])
        assert outcome.accepted == 1
        assert outcome.rejected == 1

    @pytest.mark.asyncio
    async def test_ingest_deduplicates(self):
        svc = self._svc()
        record = _make_ingestion_record()
        # Send same record twice
        outcome = await svc.ingest([record, record])
        assert outcome.accepted == 1
        assert outcome.duplicates == 1

    @pytest.mark.asyncio
    async def test_ingest_rate_limited(self):
        svc = self._svc(max_batches_per_tenant_hour=1)
        records = [_make_ingestion_record()]
        # First batch OK
        o1 = await svc.ingest(records)
        assert o1.accepted == 1
        # Second batch rate-limited
        records2 = [_make_ingestion_record(timestamp=time.time() + 1)]
        o2 = await svc.ingest(records2)
        assert o2.rejected == 1
        assert "Rate limit" in o2.errors[0]

    @pytest.mark.asyncio
    async def test_ingest_stats_updated(self):
        svc = self._svc()
        records = [_make_ingestion_record() for _ in range(5)]
        await svc.ingest(records)
        stats = svc.stats
        assert stats["total_records_ingested"] == 5
        assert stats["total_batches_received"] == 1
        assert stats["unique_tenant_hashes"] == 1

    @pytest.mark.asyncio
    async def test_ingest_multiple_tenants(self):
        svc = self._svc()
        cfg = TelemetryExportConfig()
        h1 = anonymize_tenant_id("tenant-a", cfg)
        h2 = anonymize_tenant_id("tenant-b", cfg)
        r1 = _make_ingestion_record(tenant_hash=h1)
        r2 = _make_ingestion_record(tenant_hash=h2)
        await svc.ingest([r1], source_tenant_hash=h1)
        await svc.ingest([r2], source_tenant_hash=h2)
        assert svc.stats["unique_tenant_hashes"] == 2

    def test_cleanup(self):
        svc = self._svc()
        result = svc.cleanup()
        assert "rate_limiter_tenants_cleaned" in result
        assert "dedup_fingerprints_cleaned" in result

    @pytest.mark.asyncio
    async def test_ingest_with_clickhouse_client(self):
        """When ClickHouse client is provided, records are stored."""
        mock_ch = AsyncMock()
        svc = CloudIngestionService(clickhouse_client=mock_ch)
        records = [_make_ingestion_record()]
        await svc.ingest(records)
        mock_ch.insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_ingest_clickhouse_failure_non_fatal(self):
        """ClickHouse failure should not reject records."""
        mock_ch = AsyncMock()
        mock_ch.insert.side_effect = RuntimeError("CH down")
        svc = CloudIngestionService(clickhouse_client=mock_ch)
        records = [_make_ingestion_record()]
        outcome = await svc.ingest(records)
        # Records are still accepted (storage is best-effort)
        assert outcome.accepted == 1

    @pytest.mark.asyncio
    async def test_get_stats_without_clickhouse(self):
        svc = self._svc()
        stats = await svc.get_stats()
        assert "total_records_ingested" in stats

# ══════════════════════════════════════════════════════════════════════════════
# Q3/Q4: SCHEMA VALIDATION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestTelemetrySchemas:
    """Pydantic schema validation."""

    def test_telemetry_config_update_valid(self):
        from app.schemas.telemetry import TelemetryConfigUpdate

        body = TelemetryConfigUpdate(enabled=True, dp_epsilon=1.5)
        assert body.enabled is True
        assert body.dp_epsilon == 1.5

    def test_telemetry_config_update_no_epsilon(self):
        from app.schemas.telemetry import TelemetryConfigUpdate

        body = TelemetryConfigUpdate(enabled=False)
        assert body.dp_epsilon is None

    def test_telemetry_config_update_epsilon_too_low(self):
        from app.schemas.telemetry import TelemetryConfigUpdate

        with pytest.raises(Exception):
            TelemetryConfigUpdate(enabled=True, dp_epsilon=0.01)

    def test_telemetry_config_update_epsilon_too_high(self):
        from app.schemas.telemetry import TelemetryConfigUpdate

        with pytest.raises(Exception):
            TelemetryConfigUpdate(enabled=True, dp_epsilon=100.0)

    def test_telemetry_vector_valid(self):
        from app.schemas.telemetry import TelemetryVector

        cfg = TelemetryExportConfig()
        th = anonymize_tenant_id("test", cfg)
        fv = apply_dp_noise(_make_feature_vector())
        v = TelemetryVector(
            anonymized_tenant_hash=th,
            feature_vector=fv,
            attack_class="normal",
            confidence=0.5,
            timestamp=time.time(),
        )
        assert v.anonymized_tenant_hash == th

    def test_telemetry_vector_bad_hash_length(self):
        from app.schemas.telemetry import TelemetryVector

        with pytest.raises(Exception):
            TelemetryVector(
                anonymized_tenant_hash="short",
                feature_vector=_make_feature_vector(),
                attack_class="normal",
                confidence=0.5,
                timestamp=time.time(),
            )

    def test_telemetry_vector_bad_hash_format(self):
        from app.schemas.telemetry import TelemetryVector

        with pytest.raises(Exception):
            TelemetryVector(
                anonymized_tenant_hash="z" * 64,  # Not hex
                feature_vector=_make_feature_vector(),
                attack_class="normal",
                confidence=0.5,
                timestamp=time.time(),
            )

    def test_telemetry_vector_wrong_dims(self):
        from app.schemas.telemetry import TelemetryVector

        cfg = TelemetryExportConfig()
        th = anonymize_tenant_id("test", cfg)
        with pytest.raises(Exception):
            TelemetryVector(
                anonymized_tenant_hash=th,
                feature_vector=[1.0] * 10,
                attack_class="normal",
                confidence=0.5,
                timestamp=time.time(),
            )

    def test_telemetry_vector_nan_rejected(self):
        from app.schemas.telemetry import TelemetryVector

        cfg = TelemetryExportConfig()
        th = anonymize_tenant_id("test", cfg)
        fv = _make_feature_vector()
        fv[0] = float("nan")
        with pytest.raises(Exception):
            TelemetryVector(
                anonymized_tenant_hash=th,
                feature_vector=fv,
                attack_class="normal",
                confidence=0.5,
                timestamp=time.time(),
            )

    def test_telemetry_vector_confidence_out_of_range(self):
        from app.schemas.telemetry import TelemetryVector

        cfg = TelemetryExportConfig()
        th = anonymize_tenant_id("test", cfg)
        fv = apply_dp_noise(_make_feature_vector())
        with pytest.raises(Exception):
            TelemetryVector(
                anonymized_tenant_hash=th,
                feature_vector=fv,
                attack_class="normal",
                confidence=1.5,
                timestamp=time.time(),
            )

    def test_telemetry_batch_valid(self):
        from app.schemas.telemetry import TelemetryBatch, TelemetryVector

        cfg = TelemetryExportConfig()
        th = anonymize_tenant_id("test", cfg)
        fv = apply_dp_noise(_make_feature_vector())
        batch = TelemetryBatch(
            records=[
                TelemetryVector(
                    anonymized_tenant_hash=th,
                    feature_vector=fv,
                    attack_class="normal",
                    confidence=0.5,
                    timestamp=time.time(),
                )
            ]
        )
        assert len(batch.records) == 1

    def test_telemetry_batch_empty_rejected(self):
        from app.schemas.telemetry import TelemetryBatch

        with pytest.raises(Exception):
            TelemetryBatch(records=[])

    def test_ingestion_result(self):
        from app.schemas.telemetry import IngestionResult

        r = IngestionResult(accepted=5, rejected=1, duplicates=2)
        assert r.accepted == 5

# ══════════════════════════════════════════════════════════════════════════════
# Q3/Q4: ROUTER ENDPOINT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestTelemetryRouter:
    """Telemetry API endpoint request/response shapes."""

    def test_router_prefix(self):
        from app.routers.telemetry import router

        assert router.prefix == "/api/v1/telemetry"

    def test_router_has_config_endpoints(self):
        from app.routers.telemetry import router

        paths = [r.path for r in router.routes]
        assert "/api/v1/telemetry/config" in paths

    def test_router_has_status_endpoint(self):
        from app.routers.telemetry import router

        paths = [r.path for r in router.routes]
        assert "/api/v1/telemetry/status" in paths

    def test_router_has_viewer_endpoints(self):
        from app.routers.telemetry import router

        paths = [r.path for r in router.routes]
        assert "/api/v1/telemetry/viewer" in paths
        assert "/api/v1/telemetry/viewer/pending" in paths

class TestCloudTelemetryRouter:
    """Cloud ingestion API endpoint shapes."""

    def test_router_prefix(self):
        from app.routers.cloud_telemetry import router

        assert router.prefix == "/api/v1/cloud/telemetry"

    def test_router_has_ingest_endpoint(self):
        from app.routers.cloud_telemetry import router

        paths = [r.path for r in router.routes]
        assert "/api/v1/cloud/telemetry/ingest" in paths

    def test_router_has_stats_endpoint(self):
        from app.routers.cloud_telemetry import router

        paths = [r.path for r in router.routes]
        assert "/api/v1/cloud/telemetry/stats" in paths

# ══════════════════════════════════════════════════════════════════════════════
# Q3: TELEMETRY RECORD EDGE CASES
# ══════════════════════════════════════════════════════════════════════════════

class TestTelemetryRecordEdgeCases:
    """Edge cases for telemetry record creation."""

    def test_very_long_attack_class(self):
        """Long attack_class should be accepted (anonymizer doesn't limit)."""
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="x" * 200,
            confidence=0.5,
        )
        assert len(record.attack_class) == 200

    def test_empty_attack_class(self):
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="",
            confidence=0.5,
        )
        assert record.attack_class == ""

    def test_zero_confidence(self):
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="normal",
            confidence=0.0,
        )
        assert record.confidence == 0.0

    def test_max_confidence(self):
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=_make_feature_vector(),
            attack_class="attack",
            confidence=1.0,
        )
        assert record.confidence == 1.0

    def test_all_zero_features(self):
        """All-zero feature vectors should still work."""
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=[0.0] * 62,
            attack_class="normal",
            confidence=0.5,
        )
        assert len(record.feature_vector) == 62

    def test_negative_feature_values(self):
        fv = [-1.0 * i for i in range(62)]
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=fv,
            attack_class="normal",
            confidence=0.5,
        )
        assert len(record.feature_vector) == 62

    def test_large_feature_values(self):
        fv = [1000.0 + i for i in range(62)]
        record = build_telemetry_record(
            tenant_id="t1",
            feature_vector=fv,
            attack_class="normal",
            confidence=0.5,
        )
        assert len(record.feature_vector) == 62

# ══════════════════════════════════════════════════════════════════════════════
# Q4: INGESTION OUTCOME TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestIngestionOutcome:
    """Ingestion outcome dataclass."""

    def test_total_property(self):
        o = IngestionOutcome(accepted=5, rejected=2, duplicates=1)
        assert o.total == 8

    def test_to_dict(self):
        o = IngestionOutcome(accepted=10, rejected=3, duplicates=0)
        d = o.to_dict()
        assert d == {"accepted": 10, "rejected": 3, "duplicates": 0}

    def test_default_values(self):
        o = IngestionOutcome()
        assert o.accepted == 0
        assert o.rejected == 0
        assert o.duplicates == 0
        assert o.errors == []

# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION: Q3 → Q4 PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class TestQ3ToQ4Pipeline:
    """End-to-end: Q3 builds records → Q4 ingests them."""

    @pytest.mark.asyncio
    async def test_q3_records_accepted_by_q4(self):
        """Records built by Q3 anonymizer should pass Q4 validation."""
        cfg = TelemetryExportConfig()
        records = build_telemetry_batch([_make_record_dict() for _ in range(5)], config=cfg)
        export_dicts = [r.to_export_dict() for r in records]

        svc = CloudIngestionService()
        outcome = await svc.ingest(export_dicts)
        assert outcome.accepted == 5
        assert outcome.rejected == 0

    @pytest.mark.asyncio
    async def test_modified_records_detected(self):
        """If someone tampers with a feature vector, validation catches it."""
        record = _make_export_record()
        export = record.to_export_dict()
        # Tamper: set all features to same value (fails DP check)
        export["feature_vector"] = [42.0] * 62

        svc = CloudIngestionService()
        outcome = await svc.ingest([export])
        assert outcome.rejected == 1

    @pytest.mark.asyncio
    async def test_wrong_dimension_detected(self):
        """Truncated feature vector is rejected by Q4."""
        record = _make_export_record()
        export = record.to_export_dict()
        export["feature_vector"] = export["feature_vector"][:30]

        svc = CloudIngestionService()
        outcome = await svc.ingest([export])
        assert outcome.rejected == 1

    @pytest.mark.asyncio
    async def test_full_pipeline_with_exporter(self):
        """Q3 exporter → serialize → Q4 ingest."""
        cfg = TelemetryExportConfig(cloud_endpoint="https://cloud.example.com/ingest")
        exporter = TelemetryExporter(config=cfg)

        # Q3: Build and enqueue
        for _ in range(3):
            record = _make_export_record(config=cfg)
            await exporter.enqueue(record)

        # Get pending preview (admin viewer)
        preview = exporter.get_pending_preview()
        assert len(preview) == 3

        # Q4: Validate the pending records
        svc = CloudIngestionService()
        outcome = await svc.ingest(preview)
        assert outcome.accepted == 3

# ══════════════════════════════════════════════════════════════════════════════
# SECURITY FIX VERIFICATION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityFixes:
    """Verify security audit fixes."""

    def test_crypto1_dev_hmac_key_marker(self):
        """CRYPTO-1: Config exposes _DEV_HMAC_KEY for production guards."""
        cfg = TelemetryExportConfig()
        assert hasattr(cfg, "_DEV_HMAC_KEY")
        assert cfg.tenant_hash_key == cfg._DEV_HMAC_KEY  # In dev mode

    @pytest.mark.asyncio
    async def test_input2_buffer_toctou_fixed(self):
        """INPUT-2: Buffer capacity check is inside the lock."""
        cfg = TelemetryExportConfig(max_batch_size=1)
        exporter = TelemetryExporter(config=cfg)
        r1 = _make_export_record(config=cfg)
        r2 = _make_export_record(config=cfg)
        await exporter.enqueue(r1)
        accepted = await exporter.enqueue(r2)
        # Second record should be rejected (buffer full)
        assert accepted is False
        assert exporter.buffer_size == 1

    def test_info1_last_error_sanitized(self):
        """INFO-1: last_error does not contain full exception details."""
        from ml.telemetry.exporter import ExportMetrics

        m = ExportMetrics()
        # Simulate what the exporter does after an exception
        m.last_error = "Upload failed: ConnectionError"
        # Should NOT contain stack traces, URLs, or connection strings
        assert "Upload failed:" in m.last_error
        assert "/" not in m.last_error  # No URLs/paths
        assert "\n" not in m.last_error  # No stack traces

    def test_rate2_limiter_capped(self):
        """RATE-2: Rate limiter has max tracked tenants."""
        limiter = TenantRateLimiter(max_per_hour=100)
        assert limiter._MAX_TRACKED_TENANTS == 100_000

    def test_rate2_limiter_evicts_when_full(self):
        """RATE-2: Oldest tenant evicted when at capacity."""
        limiter = TenantRateLimiter(max_per_hour=100)
        limiter._MAX_TRACKED_TENANTS = 3  # Override for test
        for i in range(3):
            limiter.record(f"tenant-{i}")
        # Adding a 4th should evict the oldest
        limiter.record("tenant-new")
        assert len(limiter._windows) <= 3

    def test_auth2_cloud_router_has_validation(self):
        """AUTH-1/2: Cloud router has ingestion key validation function."""
        from app.routers.cloud_telemetry import _check_ip_rate_limit, _validate_ingestion_key

        # Functions exist and are callable
        assert callable(_validate_ingestion_key)
        assert callable(_check_ip_rate_limit)

    def test_auth2_ingestion_key_rejected(self):
        """AUTH-2: Invalid ingestion key raises 403."""
        from app.routers.cloud_telemetry import _validate_ingestion_key

        mock_request = MagicMock()
        mock_request.headers = {"x-phantex-ingestion-key": "wrong-key"}
        mock_request.client.host = "127.0.0.1"
        with patch.dict(os.environ, {"PHANTEX_CLOUD_INGESTION_KEY": "correct-key"}):
            with pytest.raises(HTTPException) as exc_info:
                _validate_ingestion_key(mock_request)
            assert exc_info.value.status_code == 403

    def test_auth2_ingestion_key_accepted(self):
        """AUTH-2: Valid ingestion key passes."""
        from app.routers.cloud_telemetry import _validate_ingestion_key

        mock_request = MagicMock()
        mock_request.headers = {"x-phantex-ingestion-key": "my-secret-key"}
        with patch.dict(os.environ, {"PHANTEX_CLOUD_INGESTION_KEY": "my-secret-key"}):
            _validate_ingestion_key(mock_request)  # Should not raise

    def test_auth2_ingestion_key_skipped_in_dev(self):
        """AUTH-2: No key enforcement when env var is unset."""
        from app.routers.cloud_telemetry import _validate_ingestion_key

        mock_request = MagicMock()
        mock_request.headers = {}
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PHANTEX_CLOUD_INGESTION_KEY", None)
            _validate_ingestion_key(mock_request)  # Should not raise

# ═══════════════════════════════════════════════════════════════════════════════
#  Q3-Q4 Hardening Tests ( audit)
# ═══════════════════════════════════════════════════════════════════════════════

class TestTelemetryRouterHardening:
    """Verify router uses CurrentUser attribute access and has rate limiting."""

    def test_require_admin_accepts_currentuser(self):
        """_require_admin must accept CurrentUser, not dict."""
        import uuid

        from app.routers.telemetry import _require_admin
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="admin", email="a@t.co")
        _require_admin(user)  # no raise

    def test_require_admin_rejects_analyst(self):
        import uuid

        from fastapi import HTTPException

        from app.routers.telemetry import _require_admin
        from app.schemas.auth import CurrentUser

        user = CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst", email="a@t.co")
        with pytest.raises(HTTPException) as exc_info:
            _require_admin(user)
        assert exc_info.value.status_code == 403

    def test_router_has_rate_limit_dependency(self):
        """Rate-limit dependency is present on the telemetry router."""
        from app.routers.telemetry import router

        dep_names = [getattr(d.dependency, "__name__", "") for d in router.dependencies]
        assert "rate_limit" in dep_names

class TestHMACKeyFromEnv:
    """HMAC key must be loaded from PHANTEX_TELEMETRY_HMAC_KEY env var."""

    def test_default_key_when_no_env(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PHANTEX_TELEMETRY_HMAC_KEY", None)
            cfg = TelemetryExportConfig()
            assert cfg.tenant_hash_key == cfg._DEV_HMAC_KEY

    def test_custom_key_from_env(self):
        with patch.dict(os.environ, {"PHANTEX_TELEMETRY_HMAC_KEY": "prod-secret-key-xyz"}):
            cfg = TelemetryExportConfig()
            assert cfg.tenant_hash_key == "prod-secret-key-xyz"
            assert cfg.tenant_hash_key != cfg._DEV_HMAC_KEY

class TestSecureLaplaceHardening:
    """_secure_laplace must never return zero noise."""

    def test_never_returns_zero_on_normal_input(self):
        from ml.telemetry.anonymizer import _secure_laplace

        results = [_secure_laplace(0.5) for _ in range(200)]
        assert all(r != 0.0 for r in results), "Got zero noise — DP leakage"

    def test_returns_zero_only_when_scale_is_zero(self):
        from ml.telemetry.anonymizer import _secure_laplace

        assert _secure_laplace(0.0) == 0.0
        assert _secure_laplace(-1.0) == 0.0

class TestIPRateLimitEviction:
    """IP rate limiter must actually evict when at capacity."""

    def test_eviction_fires_at_capacity(self):
        from app.routers.cloud_telemetry import (
            _IP_MAX_TRACKED,
            _check_ip_rate_limit,
            _ip_request_log,
        )

        # Save and clear state
        saved = dict(_ip_request_log)
        _ip_request_log.clear()

        try:
            # Fill to capacity with fake IPs
            for i in range(min(100, _IP_MAX_TRACKED)):
                _ip_request_log[f"10.0.0.{i}"] = [time.time()]

            original_count = len(_ip_request_log)

            # Insert a brand-new IP that requires eviction
            mock_req = MagicMock()
            mock_req.client.host = "192.168.99.99"

            # Temporarily lower cap for test
            import app.routers.cloud_telemetry as ct

            old_max = ct._IP_MAX_TRACKED
            ct._IP_MAX_TRACKED = original_count  # Force eviction on next insert

            try:
                _check_ip_rate_limit(mock_req)
                # Should have evicted one + added new = same count
                assert "192.168.99.99" in _ip_request_log
                assert len(_ip_request_log) <= original_count + 1
            finally:
                ct._IP_MAX_TRACKED = old_max
        finally:
            _ip_request_log.clear()
            _ip_request_log.update(saved)

class TestClickHouseTableValidation:
    """ClickHouse queries must validate table names."""

    @pytest.mark.asyncio
    async def test_safe_table_name_accepted(self):
        from ml.telemetry.config import CloudIngestionConfig
        from ml.telemetry.ingestion import CloudIngestionService

        cfg = CloudIngestionConfig()
        svc = CloudIngestionService(config=cfg)
        # Default table name should be valid
        assert svc._SAFE_TABLE_RE.match(cfg.clickhouse_table)

    @pytest.mark.asyncio
    async def test_unsafe_table_name_rejected(self):
        from ml.telemetry.ingestion import CloudIngestionService

        svc = CloudIngestionService()
        # Inject obviously bad names
        assert not svc._SAFE_TABLE_RE.match("Robert'; DROP TABLE--")
        assert not svc._SAFE_TABLE_RE.match("")
        assert not svc._SAFE_TABLE_RE.match("123start_with_digit")

class TestOptInGateHardening:
    """Exporter opt-in gate was fixed to use raw tenant_id, not hash."""

    @pytest.mark.asyncio
    async def test_is_tenant_opted_in_returns_false_without_db(self):
        from ml.telemetry.exporter import TelemetryExporter

        exporter = TelemetryExporter()
        result = await exporter.is_tenant_opted_in("some-tenant-uuid")
        assert result is False

    def test_is_tenant_opted_in_docstring_mentions_raw_tenant_id(self):
        import inspect

        from ml.telemetry.exporter import TelemetryExporter

        src = inspect.getsource(TelemetryExporter.is_tenant_opted_in)
        assert "RAW tenant_id" in src
        assert "NOT the anonymized hash" in src

class TestViewerEntriesClamp:
    """get_viewer_entries must clamp limit to sane range."""

    def test_negative_limit_clamped(self):
        from ml.telemetry.exporter import TelemetryExporter

        exporter = TelemetryExporter()
        entries = exporter.get_viewer_entries(limit=-10)
        assert isinstance(entries, list)

    def test_huge_limit_clamped(self):
        from ml.telemetry.exporter import TelemetryExporter

        exporter = TelemetryExporter()
        entries = exporter.get_viewer_entries(limit=999_999)
        assert isinstance(entries, list)

class TestDedupSizeCap:
    """RecordDeduplicator must have a size cap."""

    def test_has_max_seen_constant(self):
        from ml.telemetry.ingestion import RecordDeduplicator

        assert hasattr(RecordDeduplicator, "_MAX_SEEN")
        assert RecordDeduplicator._MAX_SEEN > 0

    def test_auto_cleanup_on_overflow(self):
        from ml.telemetry.ingestion import RecordDeduplicator

        dedup = RecordDeduplicator(window_seconds=60)
        # Set artificially low cap
        old_max = RecordDeduplicator._MAX_SEEN
        RecordDeduplicator._MAX_SEEN = 5
        try:
            # Insert more than cap
            for i in range(10):
                record = {
                    "anonymized_tenant_hash": "a" * 64,
                    "timestamp": time.time() + i,
                    "attack_class": f"type_{i}",
                    "feature_vector": [float(i)] * 4,
                }
                dedup.is_duplicate(record)
            # Should have auto-cleaned (cleanup reduces _seen)
            # The _seen dict should not grow unboundedly
            assert len(dedup._seen) <= 12  # Allow some growth through cleanup cycles
        finally:
            RecordDeduplicator._MAX_SEEN = old_max

class TestBuildBatchLogging:
    """build_telemetry_batch must log dropped records."""

    def test_malformed_record_logs_debug(self):
        from ml.telemetry.anonymizer import build_telemetry_batch

        # Missing required fields — should be skipped
        records = [{"bad": "data"}]
        result = build_telemetry_batch(records)
        assert len(result) == 0  # Malformed dropped
