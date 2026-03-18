# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Cloud Telemetry Ingestion Router (Q4).

Cloud-side API that receives anonymized telemetry batches from
participating customer deployments.

Endpoints:
- POST /ingest     — Submit a batch of anonymized telemetry vectors
- GET  /stats      — Ingestion statistics (admin)

Security:
- mTLS: In production, mTLS is enforced at the gateway/load-balancer level
  (not in FastAPI). The certificate CN is passed as X-Client-CN header.
- API key: Defense-in-depth — validates X-Phantex-Ingestion-Key header.
- Rate limiting: Per source IP + per anonymized tenant, in-memory (Redis in prod).
- No PII: All data is anonymized, GDPR/CCPA compliant.
"""

from __future__ import annotations

import os
import time

from fastapi import APIRouter, HTTPException, Request

from app.schemas.telemetry import (
    IngestionResult,
    IngestionStats,
    TelemetryBatch,
)
from app.utils.logging import get_logger
from ml.telemetry.config import CloudIngestionConfig
from ml.telemetry.ingestion import CloudIngestionService

logger = get_logger("phantex.router.cloud_telemetry")

router = APIRouter(
    prefix="/api/v1/cloud/telemetry",
    tags=["cloud-telemetry"],
)

# ── Service Singleton ────────────────────────────────────────────────────────
_config = CloudIngestionConfig()
_service = CloudIngestionService(config=_config)

# IP-based rate limiter (defense-in-depth alongside tenant-hash limiting)
_ip_request_log: dict[str, list[float]] = {}
_IP_MAX_PER_MINUTE = 120
_IP_MAX_TRACKED = 50_000

def _get_service() -> CloudIngestionService:
    return _service

def _validate_ingestion_key(request: Request) -> None:
    """Defense-in-depth: validate X-Phantex-Ingestion-Key header.

    In production, set PHANTEX_CLOUD_INGESTION_KEY env var.
    In dev/test, the header check is skipped when the env var is unset.
    """
    expected_key = os.environ.get("PHANTEX_CLOUD_INGESTION_KEY", "")
    if not expected_key:
        # Dev/test mode — no key enforcement
        return
    provided = request.headers.get("x-phantex-ingestion-key", "")
    if provided != expected_key:
        logger.warning(
            "cloud_ingestion_auth_failed",
            client_ip=request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=403, detail="Invalid ingestion key")

def _check_ip_rate_limit(request: Request) -> None:
    """Per-IP rate limiting (defense-in-depth against RATE-1 bypass)."""
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60

    # Evict oldest IP if at capacity (BEFORE adding the new one)
    if ip not in _ip_request_log and len(_ip_request_log) >= _IP_MAX_TRACKED:
        oldest_ip = min(_ip_request_log, key=lambda k: _ip_request_log[k][-1] if _ip_request_log[k] else 0)
        del _ip_request_log[oldest_ip]

    if ip in _ip_request_log:
        _ip_request_log[ip] = [t for t in _ip_request_log[ip] if t > window_start]
    else:
        _ip_request_log[ip] = []

    if len(_ip_request_log[ip]) >= _IP_MAX_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    _ip_request_log[ip].append(now)

# ── POST /ingest — Submit Telemetry Batch ────────────────────────────────────

@router.post("/ingest", response_model=IngestionResult, status_code=200)
async def ingest_telemetry(
    batch: TelemetryBatch,
    request: Request,
):
    """Ingest a batch of anonymized telemetry vectors.

    Security:
    - mTLS enforced at gateway level (X-Client-CN header for audit)
    - API key validated (X-Phantex-Ingestion-Key header)
    - IP-based rate limiting (defense-in-depth)
    - All data is anonymized (HMAC-SHA256 tenant hashes, DP-noised features)
    """
    # Auth + rate limit (defense-in-depth)
    _validate_ingestion_key(request)
    _check_ip_rate_limit(request)
    service = _get_service()

    # Extract records as dicts
    records = [r.model_dump() for r in batch.records]

    # Determine source tenant hash for rate limiting
    source_hash = None
    if records:
        source_hash = records[0].get("anonymized_tenant_hash")

    # Ingest
    outcome = await service.ingest(records, source_tenant_hash=source_hash)

    # If everything was rejected due to rate limiting, return 429
    if outcome.rejected == len(records) and "Rate limit exceeded" in outcome.errors:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for this tenant",
        )

    return IngestionResult(
        accepted=outcome.accepted,
        rejected=outcome.rejected,
        duplicates=outcome.duplicates,
        batch_id=batch.batch_id,
    )

# ── GET /stats — Ingestion Statistics ────────────────────────────────────────

@router.get("/stats", response_model=IngestionStats, status_code=200)
async def get_ingestion_stats(request: Request):
    """Get aggregate telemetry ingestion statistics.

    Requires cloud admin authentication (API key).
    """
    _validate_ingestion_key(request)
    service = _get_service()
    stats = await service.get_stats()

    return IngestionStats(
        total_records_ingested=stats.get("total_records_ingested", 0),
        total_batches_received=stats.get("total_batches_received", 0),
        unique_tenant_hashes=stats.get("unique_tenant_hashes", 0),
        records_last_24h=stats.get("records_in_storage", 0),
        storage_size_bytes=0,  # Populated from ClickHouse in production
        oldest_record_timestamp=stats.get("oldest_record"),
        newest_record_timestamp=stats.get("newest_record"),
    )
