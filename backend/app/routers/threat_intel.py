# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Threat Intelligence Router.

Endpoints:
  GET   /api/v1/threat-intel/indicators            — List local IoCs
  POST  /api/v1/threat-intel/indicators            — Add indicator(s)
  POST  /api/v1/threat-intel/correlate             — Correlate value(s)
  GET   /api/v1/threat-intel/matches               — List correlation matches
  GET   /api/v1/threat-intel/stats                 — IoC + export + import stats
  DELETE /api/v1/threat-intel/indicators            — Deactivate an indicator
  POST  /api/v1/threat-intel/expire                — Expire stale indicators
  GET   /api/v1/threat-intel/export/destinations   — List export destinations
  POST  /api/v1/threat-intel/export/destinations   — Add export destination
  DELETE /api/v1/threat-intel/export/destinations   — Remove destination
  POST  /api/v1/threat-intel/export/local          — Export STIX bundle (local)
  POST  /api/v1/threat-intel/export/push           — Export to destination
  GET   /api/v1/threat-intel/export/history        — Export history
  GET   /api/v1/threat-intel/feeds                 — List import feeds
  POST  /api/v1/threat-intel/feeds                 — Add import feed
  DELETE /api/v1/threat-intel/feeds                 — Remove feed
  POST  /api/v1/threat-intel/feeds/toggle          — Enable/disable feed
  POST  /api/v1/threat-intel/import/stix           — Import STIX bundle
  POST  /api/v1/threat-intel/import/csv            — Import CSV data
  POST  /api/v1/threat-intel/import/json           — Import JSON data
  POST  /api/v1/threat-intel/import/manual         — Import manual indicators
  GET   /api/v1/threat-intel/import/history        — Import history

All endpoints are tenant-scoped via auth token.
"""

from __future__ import annotations

import hashlib
import re as _re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.services.threat_intel.feed_importer import (
    FeedImporter,
    FeedType,
)
from app.services.threat_intel.ioc_engine import (
    IoCEngine,
    IoCSeverity,
    IoCSource,
    IoCType,
)
from app.services.threat_intel.stix_exporter import (
    ExportDestinationType,
    STIXExporter,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.threat_intel_router")

router = APIRouter(
    prefix="/api/v1/threat-intel",
    tags=["threat-intel"],
    dependencies=[
        Depends(rate_limit),
        Depends(require_permission("analytics.view")),
    ],
)

# Service singletons (production: DI container)
_ioc_engine = IoCEngine(store_raw=False)
_exporter = STIXExporter(_ioc_engine)
_importer = FeedImporter(_ioc_engine)

_User = Annotated[CurrentUser, Depends(get_current_active_user)]
_SAFE_ID = _re.compile(r"^[a-zA-Z0-9_\-.:]+$")

_VALID_IOC_TYPES = {t.value for t in IoCType}
_VALID_SEVERITIES = {s.value for s in IoCSeverity}
_VALID_SOURCES = {s.value for s in IoCSource}
_VALID_DEST_TYPES = {d.value for d in ExportDestinationType}
_VALID_FEED_TYPES = {f.value for f in FeedType}

# ── Helpers ──────────────────────────────────────────────────────────────

def _tenant(user: CurrentUser) -> str:
    return str(user.tenant_id)

def _user_id(user: CurrentUser) -> str:
    return str(user.user_id)

def _validated_id(value: str, name: str, max_len: int = 128) -> str:
    if len(value) > max_len:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{name} too long")
    if not _SAFE_ID.match(value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid {name}")
    return value

# ── Request models ───────────────────────────────────────────────────────

class AddIndicatorRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    ioc_type: str = Field("ipv4", max_length=32)
    severity: str = Field("medium", max_length=16)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list, max_length=20)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("context")
    @classmethod
    def validate_context_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json as _j

        if len(_j.dumps(v, default=str)) > 8192:
            raise ValueError("context must be < 8 KB")
        return v

    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        if v not in _VALID_IOC_TYPES:
            raise ValueError(f"ioc_type must be one of: {', '.join(sorted(_VALID_IOC_TYPES))}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(_VALID_SEVERITIES))}")
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        return [t[:64] for t in v[:20]]

class BulkAddRequest(BaseModel):
    indicators: list[AddIndicatorRequest] = Field(..., max_length=1000)

class CorrelateRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("context")
    @classmethod
    def validate_context_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json as _j

        if len(_j.dumps(v, default=str)) > 8192:
            raise ValueError("context must be < 8 KB")
        return v

class BatchCorrelateRequest(BaseModel):
    values: list[CorrelateRequest] = Field(..., max_length=500)

class DeactivateRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)

class AddDestinationRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    destination_type: str = Field(..., max_length=32)
    url: str = Field("", max_length=2048)
    api_key: str = Field("", max_length=512)

    @field_validator("destination_type")
    @classmethod
    def validate_dest_type(cls, v: str) -> str:
        if v not in _VALID_DEST_TYPES:
            raise ValueError(f"destination_type must be one of: {', '.join(sorted(_VALID_DEST_TYPES))}")
        return v

class RemoveDestinationRequest(BaseModel):
    destination_id: str = Field(..., max_length=64)

class ExportPushRequest(BaseModel):
    destination_id: str = Field(..., max_length=64)
    ioc_type: str | None = Field(None, max_length=32)
    severity: str | None = Field(None, max_length=16)
    limit: int = Field(1000, ge=1, le=5000)

class ExportLocalRequest(BaseModel):
    ioc_type: str | None = Field(None, max_length=32)
    severity: str | None = Field(None, max_length=16)
    limit: int = Field(1000, ge=1, le=5000)

class AddFeedRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    feed_type: str = Field(..., max_length=32)
    url: str = Field("", max_length=2048)
    api_key: str = Field("", max_length=512)
    polling_interval_seconds: int = Field(3600, ge=60, le=86400)

    @field_validator("feed_type")
    @classmethod
    def validate_feed_type(cls, v: str) -> str:
        if v not in _VALID_FEED_TYPES:
            raise ValueError(f"feed_type must be one of: {', '.join(sorted(_VALID_FEED_TYPES))}")
        return v

class RemoveFeedRequest(BaseModel):
    feed_id: str = Field(..., max_length=64)

class ToggleFeedRequest(BaseModel):
    feed_id: str = Field(..., max_length=64)
    enabled: bool

class ImportSTIXRequest(BaseModel):
    feed_id: str = Field("manual", max_length=64)
    bundle: dict[str, Any]

    @field_validator("bundle")
    @classmethod
    def validate_bundle_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        objects = v.get("objects", [])
        if not isinstance(objects, list):
            raise ValueError("bundle.objects must be a list")
        if len(objects) > 10_000:
            raise ValueError("bundle.objects limited to 10,000 entries")
        return v

class ImportCSVRequest(BaseModel):
    feed_id: str = Field("manual", max_length=64)
    csv_text: str = Field(..., min_length=1, max_length=1_000_000)

class ImportJSONRequest(BaseModel):
    feed_id: str = Field("manual", max_length=64)
    json_text: str = Field(..., min_length=1, max_length=1_000_000)

class ManualImportRequest(BaseModel):
    indicators: list[AddIndicatorRequest] = Field(..., max_length=500)

# ── IoC Indicator endpoints ──────────────────────────────────────────────

@router.get("/indicators")
async def list_indicators(
    user: _User,
    ioc_type: str | None = Query(None, max_length=32),
    severity: str | None = Query(None, max_length=16),
    source: str | None = Query(None, max_length=32),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """List local IoCs for the tenant."""
    try:
        ioc_t = IoCType(ioc_type) if ioc_type else None
        sev = IoCSeverity(severity) if severity else None
        src = IoCSource(source) if source else None
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    indicators = _ioc_engine.get_indicators(
        _tenant(user),
        ioc_type=ioc_t,
        severity=sev,
        source=src,
        limit=limit,
    )
    logger.info(
        "threat_intel.indicators.list",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        count=len(indicators),
    )
    return {"indicators": [i.to_dict() for i in indicators], "count": len(indicators)}

@router.post("/indicators")
async def add_indicator(body: AddIndicatorRequest, user: _User) -> dict[str, Any]:
    """Add a single IoC indicator."""
    ind = _ioc_engine.add_indicator(
        _tenant(user),
        IoCType(body.ioc_type),
        body.value,
        severity=IoCSeverity(body.severity),
        source=IoCSource.MANUAL,
        confidence=body.confidence,
        tags=body.tags,
        context=body.context,
    )
    logger.info(
        "threat_intel.indicator.added",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        ioc_type=body.ioc_type,
    )
    return ind.to_dict()

@router.post("/indicators/bulk")
async def add_indicators_bulk(body: BulkAddRequest, user: _User) -> dict[str, Any]:
    """Bulk-add IoC indicators."""
    items = [
        {
            "ioc_type": i.ioc_type,
            "value": i.value,
            "severity": i.severity,
            "source": "manual",
            "confidence": i.confidence,
            "tags": i.tags,
            "context": i.context,
        }
        for i in body.indicators
    ]
    added = _ioc_engine.add_indicators_bulk(_tenant(user), items)
    logger.info(
        "threat_intel.indicators.bulk_added",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        added=added,
        total=len(items),
    )
    return {"added": added, "total": len(items), "duplicates": len(items) - added}

@router.delete("/indicators")
async def deactivate_indicator(body: DeactivateRequest, user: _User) -> dict[str, Any]:
    """Deactivate an IoC indicator by value."""
    success = _ioc_engine.deactivate(_tenant(user), body.value)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    logger.info("threat_intel.indicator.deactivated", user_id=_user_id(user), tenant_id=_tenant(user))
    return {"deactivated": True}

@router.post("/expire")
async def expire_stale(user: _User) -> dict[str, Any]:
    """Remove all expired IoCs for the tenant."""
    count = _ioc_engine.expire_stale(_tenant(user))
    logger.info("threat_intel.expire", user_id=_user_id(user), tenant_id=_tenant(user), expired=count)
    return {"expired_count": count}

# ── Correlation endpoints ────────────────────────────────────────────────

@router.post("/correlate")
async def correlate_value(body: CorrelateRequest, user: _User) -> dict[str, Any]:
    """Check a value against stored IoCs."""
    match = _ioc_engine.correlate(
        _tenant(user),
        body.value,
        event_context=body.context,
    )
    if match:
        logger.info(
            "threat_intel.correlation.hit",
            user_id=_user_id(user),
            tenant_id=_tenant(user),
            severity=match.severity.value,
        )
        return {"match": True, "correlation": match.to_dict()}
    return {"match": False, "correlation": None}

@router.post("/correlate/batch")
async def correlate_batch(body: BatchCorrelateRequest, user: _User) -> dict[str, Any]:
    """Correlate multiple values against stored IoCs."""
    values = [{"value": v.value, "context": v.context} for v in body.values]
    matches = _ioc_engine.correlate_batch(_tenant(user), values)
    if matches:
        logger.info(
            "threat_intel.correlation.batch_hits",
            user_id=_user_id(user),
            tenant_id=_tenant(user),
            matches=len(matches),
        )
    return {"matches": [m.to_dict() for m in matches], "count": len(matches)}

@router.get("/matches")
async def list_matches(
    user: _User,
    severity: str | None = Query(None, max_length=16),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """List correlation matches for the tenant."""
    try:
        sev = IoCSeverity(severity) if severity else None
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    matches = _ioc_engine.get_matches(_tenant(user), severity=sev, limit=limit)
    return {"matches": [m.to_dict() for m in matches], "count": len(matches)}

@router.get("/stats")
async def get_stats(user: _User) -> dict[str, Any]:
    """Aggregate stats: IoC engine + export + import."""
    return {
        "ioc": _ioc_engine.stats(_tenant(user)),
        "export": _exporter.stats(_tenant(user)),
        "import": _importer.stats(_tenant(user)),
    }

# ── Export endpoints ─────────────────────────────────────────────────────

@router.get("/export/destinations")
async def list_destinations(user: _User) -> dict[str, Any]:
    """List export destinations."""
    dests = _exporter.get_destinations(_tenant(user))
    return {"destinations": [d.to_dict() for d in dests], "count": len(dests)}

@router.post("/export/destinations")
async def add_destination(body: AddDestinationRequest, user: _User) -> dict[str, Any]:
    """Add an export destination."""
    dest = _exporter.add_destination(
        _tenant(user),
        body.name,
        ExportDestinationType(body.destination_type),
        url=body.url,
        api_key=body.api_key,
    )
    logger.info(
        "threat_intel.export.destination_added",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        dest_type=body.destination_type,
    )
    return dest.to_dict()

@router.delete("/export/destinations")
async def remove_destination(body: RemoveDestinationRequest, user: _User) -> dict[str, Any]:
    """Remove an export destination."""
    _validated_id(body.destination_id, "destination_id")
    success = _exporter.remove_destination(_tenant(user), body.destination_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")
    logger.info("threat_intel.export.destination_removed", user_id=_user_id(user), tenant_id=_tenant(user))
    return {"removed": True}

@router.post("/export/local")
async def export_local(body: ExportLocalRequest, user: _User) -> dict[str, Any]:
    """Export IoCs as a local STIX 2.1 bundle (no network traffic)."""
    ioc_t = IoCType(body.ioc_type) if body.ioc_type else None
    sev = IoCSeverity(body.severity) if body.severity else None

    bundle = _exporter.export_to_local(
        _tenant(user),
        ioc_type=ioc_t,
        severity=sev,
        limit=body.limit,
    )
    logger.info(
        "threat_intel.export.local",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        objects=len(bundle.get("objects", [])),
    )
    return bundle

@router.post("/export/push")
async def export_to_destination(body: ExportPushRequest, user: _User) -> dict[str, Any]:
    """Export IoCs to a configured destination."""
    ioc_t = IoCType(body.ioc_type) if body.ioc_type else None
    sev = IoCSeverity(body.severity) if body.severity else None

    _validated_id(body.destination_id, "destination_id")
    result = _exporter.export_to_destination(
        _tenant(user),
        body.destination_id,
        ioc_type=ioc_t,
        severity=sev,
        limit=body.limit,
    )
    logger.info(
        "threat_intel.export.push",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        dest=body.destination_id,
        success=result.success,
    )
    return result.to_dict()

@router.get("/export/history")
async def export_history(user: _User, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    """List recent export results."""
    history = _exporter.get_export_history(_tenant(user), limit=limit)
    return {"exports": history, "count": len(history)}

# ── Feed / Import endpoints ─────────────────────────────────────────────

@router.get("/feeds")
async def list_feeds(user: _User) -> dict[str, Any]:
    """List import feeds."""
    feeds = _importer.get_feeds(_tenant(user))
    return {"feeds": [f.to_dict() for f in feeds], "count": len(feeds)}

@router.post("/feeds")
async def add_feed(body: AddFeedRequest, user: _User) -> dict[str, Any]:
    """Add an import feed."""
    api_key_hash = ""
    if body.api_key:
        api_key_hash = hashlib.sha256(body.api_key.encode("utf-8")).hexdigest()

    feed = _importer.add_feed(
        _tenant(user),
        body.name,
        FeedType(body.feed_type),
        url=body.url,
        api_key_hash=api_key_hash,
        polling_interval_seconds=body.polling_interval_seconds,
    )
    logger.info(
        "threat_intel.feed.added",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        feed_type=body.feed_type,
    )
    return feed.to_dict()

@router.delete("/feeds")
async def remove_feed(body: RemoveFeedRequest, user: _User) -> dict[str, Any]:
    """Remove an import feed."""
    _validated_id(body.feed_id, "feed_id")
    success = _importer.remove_feed(_tenant(user), body.feed_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    logger.info("threat_intel.feed.removed", user_id=_user_id(user), tenant_id=_tenant(user))
    return {"removed": True}

@router.post("/feeds/toggle")
async def toggle_feed(body: ToggleFeedRequest, user: _User) -> dict[str, Any]:
    """Enable or disable a feed."""
    _validated_id(body.feed_id, "feed_id")
    feed = _importer.toggle_feed(_tenant(user), body.feed_id, body.enabled)
    if not feed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    return feed.to_dict()

@router.post("/import/stix")
async def import_stix(body: ImportSTIXRequest, user: _User) -> dict[str, Any]:
    """Import indicators from a STIX 2.1 bundle."""
    result = _importer.import_stix_bundle(_tenant(user), body.feed_id, body.bundle)
    logger.info(
        "threat_intel.import.stix",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        imported=result.imported_count,
        matches=result.correlation_matches,
    )
    return result.to_dict()

@router.post("/import/csv")
async def import_csv(body: ImportCSVRequest, user: _User) -> dict[str, Any]:
    """Import indicators from CSV data."""
    result = _importer.import_csv(_tenant(user), body.feed_id, body.csv_text)
    logger.info(
        "threat_intel.import.csv",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        imported=result.imported_count,
    )
    return result.to_dict()

@router.post("/import/json")
async def import_json(body: ImportJSONRequest, user: _User) -> dict[str, Any]:
    """Import indicators from JSON data."""
    result = _importer.import_json(_tenant(user), body.feed_id, body.json_text)
    logger.info(
        "threat_intel.import.json",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        imported=result.imported_count,
    )
    return result.to_dict()

@router.post("/import/manual")
async def import_manual(body: ManualImportRequest, user: _User) -> dict[str, Any]:
    """Import manually submitted indicators."""
    items = [
        {
            "ioc_type": i.ioc_type,
            "value": i.value,
            "severity": i.severity,
            "source": "manual",
            "confidence": i.confidence,
            "tags": i.tags,
            "context": i.context,
        }
        for i in body.indicators
    ]
    result = _importer.import_manual(_tenant(user), items)
    logger.info(
        "threat_intel.import.manual",
        user_id=_user_id(user),
        tenant_id=_tenant(user),
        imported=result.imported_count,
    )
    return result.to_dict()

@router.get("/import/history")
async def import_history(user: _User, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    """List recent import results."""
    history = _importer.get_import_history(_tenant(user), limit=limit)
    return {"imports": history, "count": len(history)}
