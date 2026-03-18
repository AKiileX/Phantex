# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Threat Intel Feed Importer.

Imports threat intelligence from external sources:
  - STIX/TAXII 2.1 feeds (any compliant server)
  - CSV/JSON file upload (manual import)
  - MISP format (Open Source Threat Intelligence Platform)

Correlates imported IoCs against live events and raises alerts
on matches.  Works fully offline — import feeds are optional.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.services.threat_intel.ioc_engine import (
    IoCEngine,
    IoCSeverity,
    IoCType,
)

class FeedType(StrEnum):
    """Supported feed types."""

    STIX_TAXII = "stix_taxii"  # STIX/TAXII 2.1 server
    CSV = "csv"  # Comma-separated values
    JSON = "json"  # JSON array of indicators
    MISP = "misp"  # MISP format

class FeedStatus(StrEnum):
    """Feed operational status."""

    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    NEVER_SYNCED = "never_synced"

@dataclass
class FeedConfig:
    """Configuration for an external threat intel feed."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tenant_id: str = ""
    name: str = ""
    feed_type: FeedType = FeedType.STIX_TAXII
    url: str = ""  # Feed URL (STIX/TAXII endpoint)
    api_key_hash: str = ""  # SHA-256 of API key — never plaintext
    enabled: bool = True
    polling_interval_seconds: int = 3600  # Default: hourly
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_sync_at: str | None = None
    last_sync_count: int = 0
    status: FeedStatus = FeedStatus.NEVER_SYNCED
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize — never expose API key."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "feed_type": self.feed_type.value,
            "url": self.url,
            "has_api_key": bool(self.api_key_hash),
            "enabled": self.enabled,
            "polling_interval_seconds": self.polling_interval_seconds,
            "created_at": self.created_at,
            "last_sync_at": self.last_sync_at,
            "last_sync_count": self.last_sync_count,
            "status": self.status.value,
            "error_message": self.error_message,
        }

@dataclass
class ImportResult:
    """Result of a feed import/sync operation."""

    feed_id: str
    feed_name: str
    imported_count: int
    duplicate_count: int
    correlation_matches: int
    imported_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    success: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

# ── Parsers ──────────────────────────────────────────────────────────────

_STIX_TYPE_TO_IOC: dict[str, IoCType] = {
    "ipv4-addr": IoCType.IPV4,
    "ipv6-addr": IoCType.IPV6,
    "domain-name": IoCType.DOMAIN,
    "url": IoCType.URL,
    "email-addr": IoCType.EMAIL,
    "file": IoCType.FILE_HASH,
}

def parse_stix_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract IoC dicts from a STIX 2.1 bundle."""
    results = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        value = _extract_pattern_value(pattern)
        if not value:
            continue

        ioc_type = _infer_ioc_type_from_pattern(pattern)
        confidence = obj.get("confidence", 50) / 100.0
        severity = _confidence_to_severity(confidence)

        results.append(
            {
                "ioc_type": ioc_type.value,
                "value": value,
                "severity": severity.value,
                "source": "feed_import",
                "confidence": confidence,
                "tags": obj.get("labels", []),
                "context": {
                    "stix_id": obj.get("id", ""),
                    "name": obj.get("name", ""),
                    "created": obj.get("created", ""),
                },
            }
        )
    return results

def parse_csv_data(csv_text: str) -> list[dict[str, Any]]:
    """Parse CSV threat intel data.

    Expected columns: value, ioc_type, severity, tags
    First row is header.
    """
    results = []
    lines = csv_text.strip().split("\n")
    if len(lines) < 2:
        return results

    headers = [h.strip().lower() for h in lines[0].split(",")]
    value_idx = headers.index("value") if "value" in headers else 0
    type_idx = headers.index("ioc_type") if "ioc_type" in headers else -1
    sev_idx = headers.index("severity") if "severity" in headers else -1
    tag_idx = headers.index("tags") if "tags" in headers else -1

    for line in lines[1:]:
        cols = [c.strip() for c in line.split(",")]
        if not cols or not cols[value_idx]:
            continue

        ioc_type = "ipv4"
        if type_idx >= 0 and type_idx < len(cols):
            ioc_type = cols[type_idx]

        severity = "medium"
        if sev_idx >= 0 and sev_idx < len(cols):
            severity = cols[sev_idx]

        tags: list[str] = []
        if tag_idx >= 0 and tag_idx < len(cols):
            tags = [t.strip() for t in cols[tag_idx].split("|") if t.strip()]

        results.append(
            {
                "ioc_type": ioc_type,
                "value": cols[value_idx],
                "severity": severity,
                "source": "feed_import",
                "confidence": 0.5,
                "tags": tags,
            }
        )
    return results

def parse_json_data(json_text: str) -> list[dict[str, Any]]:
    """Parse JSON threat intel data.  Expects list of indicator objects."""
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, TypeError):
        return []

    if isinstance(data, dict):
        # Could be a STIX bundle
        if data.get("type") == "bundle":
            return parse_stix_bundle(data)
        data = data.get("indicators", [data])

    if not isinstance(data, list):
        return []

    results = []
    for item in data:
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("indicator", ""))
        if not value or not isinstance(value, str):
            continue
        results.append(
            {
                "ioc_type": item.get("ioc_type", item.get("type", "ipv4")),
                "value": value,
                "severity": item.get("severity", "medium"),
                "source": "feed_import",
                "confidence": float(item.get("confidence", 0.5)),
                "tags": item.get("tags", []),
                "context": item.get("context", {}),
            }
        )
    return results

# ── Feed Importer ────────────────────────────────────────────────────────

class FeedImporter:
    """Manages external threat intel feeds and imports IoCs.

    Actual HTTP fetching is a deployment concern (httpx + TLS + retry).
    This class handles feed config, parsing, dedup, and correlation.
    """

    _MAX_FEEDS_PER_TENANT = 50
    _MAX_IMPORT_HISTORY = 500

    def __init__(self, ioc_engine: IoCEngine) -> None:
        self._ioc_engine = ioc_engine
        # tenant_id → {feed_id → FeedConfig}
        self._feeds: dict[str, dict[str, FeedConfig]] = {}
        # tenant_id → [ImportResult]
        self._import_history: dict[str, list[ImportResult]] = {}

    # ── Feed management ──────────────────────────────────────────────

    def add_feed(
        self,
        tenant_id: str,
        name: str,
        feed_type: FeedType,
        *,
        url: str = "",
        api_key_hash: str = "",
        polling_interval_seconds: int = 3600,
    ) -> FeedConfig:
        """Add an import feed configuration."""
        if tenant_id not in self._feeds:
            self._feeds[tenant_id] = {}

        if len(self._feeds[tenant_id]) >= self._MAX_FEEDS_PER_TENANT:
            raise ValueError("Maximum feeds per tenant reached")

        feed = FeedConfig(
            tenant_id=tenant_id,
            name=name,
            feed_type=feed_type,
            url=url,
            api_key_hash=api_key_hash,
            polling_interval_seconds=polling_interval_seconds,
        )
        self._feeds[tenant_id][feed.id] = feed
        return feed

    def remove_feed(self, tenant_id: str, feed_id: str) -> bool:
        """Remove a feed."""
        feeds = self._feeds.get(tenant_id, {})
        if feed_id in feeds:
            del feeds[feed_id]
            return True
        return False

    def toggle_feed(self, tenant_id: str, feed_id: str, enabled: bool) -> FeedConfig | None:
        """Enable or disable a feed."""
        feed = self._feeds.get(tenant_id, {}).get(feed_id)
        if feed:
            feed.enabled = enabled
            feed.status = FeedStatus.ACTIVE if enabled else FeedStatus.PAUSED
            return feed
        return None

    def get_feeds(self, tenant_id: str) -> list[FeedConfig]:
        """List all feeds for a tenant."""
        return list(self._feeds.get(tenant_id, {}).values())

    def get_feed(self, tenant_id: str, feed_id: str) -> FeedConfig | None:
        """Get a specific feed."""
        return self._feeds.get(tenant_id, {}).get(feed_id)

    # ── Import ───────────────────────────────────────────────────────

    def import_stix_bundle(
        self,
        tenant_id: str,
        feed_id: str,
        bundle: dict[str, Any],
    ) -> ImportResult:
        """Import indicators from a STIX 2.1 bundle."""
        feed = self._feeds.get(tenant_id, {}).get(feed_id)
        feed_name = feed.name if feed else "Manual"

        parsed = parse_stix_bundle(bundle)
        return self._ingest_parsed(tenant_id, feed_id, feed_name, parsed, feed)

    def import_csv(
        self,
        tenant_id: str,
        feed_id: str,
        csv_text: str,
    ) -> ImportResult:
        """Import indicators from CSV data."""
        feed = self._feeds.get(tenant_id, {}).get(feed_id)
        feed_name = feed.name if feed else "CSV Upload"

        parsed = parse_csv_data(csv_text)
        return self._ingest_parsed(tenant_id, feed_id, feed_name, parsed, feed)

    def import_json(
        self,
        tenant_id: str,
        feed_id: str,
        json_text: str,
    ) -> ImportResult:
        """Import indicators from JSON data."""
        feed = self._feeds.get(tenant_id, {}).get(feed_id)
        feed_name = feed.name if feed else "JSON Upload"

        parsed = parse_json_data(json_text)
        return self._ingest_parsed(tenant_id, feed_id, feed_name, parsed, feed)

    def import_manual(
        self,
        tenant_id: str,
        indicators: list[dict[str, Any]],
    ) -> ImportResult:
        """Import manually submitted indicators."""
        for item in indicators:
            item.setdefault("source", "manual")
        return self._ingest_parsed(tenant_id, "manual", "Manual Entry", indicators, None)

    # ── History ──────────────────────────────────────────────────────

    def get_import_history(self, tenant_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """Recent import results."""
        history = self._import_history.get(tenant_id, [])
        return [r.to_dict() for r in history[-limit:]]

    def stats(self, tenant_id: str) -> dict[str, Any]:
        """Import statistics."""
        feeds = self._feeds.get(tenant_id, {})
        history = self._import_history.get(tenant_id, [])
        return {
            "total_feeds": len(feeds),
            "active_feeds": sum(1 for f in feeds.values() if f.enabled),
            "total_imports": len(history),
            "total_imported": sum(r.imported_count for r in history),
            "total_correlation_matches": sum(r.correlation_matches for r in history),
        }

    # ── Internal ─────────────────────────────────────────────────────

    def _ingest_parsed(
        self,
        tenant_id: str,
        feed_id: str,
        feed_name: str,
        parsed: list[dict[str, Any]],
        feed: FeedConfig | None,
    ) -> ImportResult:
        """Ingest parsed indicators, run correlation, record result."""
        if not parsed:
            result = ImportResult(
                feed_id=feed_id,
                feed_name=feed_name,
                imported_count=0,
                duplicate_count=0,
                correlation_matches=0,
                success=True,
            )
            self._record_history(tenant_id, result)
            return result

        added = self._ioc_engine.add_indicators_bulk(tenant_id, parsed)
        dupes = len(parsed) - added

        # Run correlation on all imported values against existing events
        matches = 0
        for item in parsed:
            value = item.get("value", "")
            if value:
                m = self._ioc_engine.correlate(tenant_id, value)
                if m:
                    matches += 1

        # Update feed status
        if feed:
            feed.last_sync_at = datetime.now(UTC).isoformat()
            feed.last_sync_count = len(parsed)
            feed.status = FeedStatus.ACTIVE
            feed.error_message = None

        result = ImportResult(
            feed_id=feed_id,
            feed_name=feed_name,
            imported_count=added,
            duplicate_count=dupes,
            correlation_matches=matches,
        )
        self._record_history(tenant_id, result)
        return result

    def _record_history(self, tenant_id: str, result: ImportResult) -> None:
        if tenant_id not in self._import_history:
            self._import_history[tenant_id] = []
        self._import_history[tenant_id].append(result)
        if len(self._import_history[tenant_id]) > self._MAX_IMPORT_HISTORY:
            self._import_history[tenant_id] = self._import_history[tenant_id][-self._MAX_IMPORT_HISTORY :]

# ── Pattern parsing helpers ──────────────────────────────────────────────

def _extract_pattern_value(pattern: str) -> str:
    """Extract the value from a STIX pattern string.

    e.g. "[ipv4-addr:value = '1.2.3.4']" → "1.2.3.4"
    """
    try:
        if "'" in pattern:
            parts = pattern.split("'")
            if len(parts) >= 2:
                return parts[1]
    except (IndexError, AttributeError):
        pass
    return ""

def _infer_ioc_type_from_pattern(pattern: str) -> IoCType:
    """Infer IoC type from a STIX pattern string."""
    for stix_type, ioc_type in _STIX_TYPE_TO_IOC.items():
        if stix_type in pattern:
            return ioc_type
    if "hashes" in pattern.lower():
        return IoCType.FILE_HASH
    return IoCType.ATTACK_SIGNATURE

def _confidence_to_severity(confidence: float) -> IoCSeverity:
    """Map a confidence score to a severity level."""
    if confidence >= 0.9:
        return IoCSeverity.CRITICAL
    if confidence >= 0.7:
        return IoCSeverity.HIGH
    if confidence >= 0.4:
        return IoCSeverity.MEDIUM
    return IoCSeverity.LOW
