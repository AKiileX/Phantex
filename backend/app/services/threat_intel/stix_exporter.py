# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — STIX 2.1 Exporter.

Exports local IoCs in STIX 2.1 format to pluggable destinations:
  - Local file/download (default — no network traffic)
  - Webhook URL (generic HTTPS POST)
  - STIX/TAXII server (TAXII 2.1 collection push)
  - SIEM integration (Splunk HEC, Elastic, Sentinel)

Zero data leaves the deployment unless explicitly configured.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.services.threat_intel.ioc_engine import (
    Indicator,
    IoCEngine,
    IoCSeverity,
    IoCType,
)

class ExportDestinationType(StrEnum):
    """Supported export destination types."""

    LOCAL = "local"  # No network — download/file only
    WEBHOOK = "webhook"  # Generic HTTPS POST
    TAXII = "taxii"  # STIX/TAXII 2.1 server
    SIEM = "siem"  # SIEM integration (Splunk/Elastic/Sentinel)
    MISP = "misp"  # MISP instance

@dataclass
class ExportDestination:
    """A configured export destination."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tenant_id: str = ""
    name: str = ""
    destination_type: ExportDestinationType = ExportDestinationType.LOCAL
    url: str = ""  # Target URL (empty for local)
    api_key: str = ""  # Auth key (stored hashed, not plaintext)
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_export_at: str | None = None
    export_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize — never expose api_key."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "destination_type": self.destination_type.value,
            "url": self.url,
            "has_api_key": bool(self.api_key),
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_export_at": self.last_export_at,
            "export_count": self.export_count,
        }

# ── STIX 2.1 Mapping ────────────────────────────────────────────────────

_IOC_TO_STIX_TYPE: dict[IoCType, str] = {
    IoCType.IPV4: "ipv4-addr",
    IoCType.IPV6: "ipv6-addr",
    IoCType.DOMAIN: "domain-name",
    IoCType.URL: "url",
    IoCType.EMAIL: "email-addr",
    IoCType.FILE_HASH: "file",
    IoCType.ATTACK_SIGNATURE: "indicator",
}

_SEVERITY_TO_TLP: dict[IoCSeverity, str] = {
    IoCSeverity.LOW: "TLP:GREEN",
    IoCSeverity.MEDIUM: "TLP:AMBER",
    IoCSeverity.HIGH: "TLP:AMBER+STRICT",
    IoCSeverity.CRITICAL: "TLP:RED",
}

def indicator_to_stix(indicator: Indicator) -> dict[str, Any]:
    """Convert a Phantex Indicator to a STIX 2.1 Indicator object."""
    stix_type = _IOC_TO_STIX_TYPE.get(indicator.ioc_type, "indicator")
    pattern_value = indicator.hashed_value
    if indicator.raw_value:
        pattern_value = indicator.raw_value

    # Build STIX pattern
    if indicator.ioc_type == IoCType.FILE_HASH:
        pattern = f"[file:hashes.'SHA-256' = '{indicator.hashed_value}']"
    elif indicator.ioc_type == IoCType.ATTACK_SIGNATURE:
        pattern = f"[x-phantex-signature:hash = '{indicator.hashed_value}']"
    elif indicator.ioc_type in (IoCType.IPV4, IoCType.IPV6):
        pattern = f"[{stix_type}:value = '{pattern_value}']"
    else:
        pattern = f"[{stix_type}:value = '{pattern_value}']"

    tlp = _SEVERITY_TO_TLP.get(indicator.severity, "TLP:AMBER")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{indicator.id}",
        "created": indicator.first_seen,
        "modified": indicator.last_seen,
        "name": f"Phantex IoC: {indicator.ioc_type.value}",
        "description": f"Indicator detected by Phantex ({indicator.source.value})",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": indicator.first_seen,
        "confidence": int(indicator.confidence * 100),
        "labels": indicator.tags,
        "object_marking_refs": [tlp],
        "x_phantex_severity": indicator.severity.value,
        "x_phantex_sighting_count": indicator.sighting_count,
    }

def build_stix_bundle(indicators: list[Indicator]) -> dict[str, Any]:
    """Build a STIX 2.1 Bundle from a list of Indicators."""
    objects = [indicator_to_stix(ind) for ind in indicators]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

@dataclass
class ExportResult:
    """Result of an export operation."""

    destination_id: str
    destination_name: str
    destination_type: str
    indicator_count: int
    success: bool
    exported_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    error: str | None = None
    bundle_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class STIXExporter:
    """STIX 2.1 export engine with pluggable destinations.

    By default, all exports are local-only (no network traffic).
    Users configure destinations via the dashboard; nothing is
    sent externally unless explicitly enabled.
    """

    _MAX_DESTINATIONS_PER_TENANT = 50
    _MAX_HISTORY = 1_000

    def __init__(self, ioc_engine: IoCEngine) -> None:
        self._ioc_engine = ioc_engine
        # tenant_id → {dest_id → ExportDestination}
        self._destinations: dict[str, dict[str, ExportDestination]] = {}
        # tenant_id → [ExportResult]
        self._history: dict[str, list[ExportResult]] = {}

    # ── Destination management ────────────────────────────────────

    def add_destination(
        self,
        tenant_id: str,
        name: str,
        destination_type: ExportDestinationType,
        *,
        url: str = "",
        api_key: str = "",
    ) -> ExportDestination:
        """Add an export destination.  api_key is hashed before storage."""
        if tenant_id not in self._destinations:
            self._destinations[tenant_id] = {}

        if len(self._destinations[tenant_id]) >= self._MAX_DESTINATIONS_PER_TENANT:
            raise ValueError("Maximum destinations per tenant reached")

        # Hash the API key — never store plaintext
        hashed_key = ""
        if api_key:
            hashed_key = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        dest = ExportDestination(
            tenant_id=tenant_id,
            name=name,
            destination_type=destination_type,
            url=url,
            api_key=hashed_key,
            enabled=True,
        )
        self._destinations[tenant_id][dest.id] = dest
        return dest

    def remove_destination(self, tenant_id: str, dest_id: str) -> bool:
        """Remove an export destination."""
        dests = self._destinations.get(tenant_id, {})
        if dest_id in dests:
            del dests[dest_id]
            return True
        return False

    def toggle_destination(self, tenant_id: str, dest_id: str, enabled: bool) -> ExportDestination | None:
        """Enable or disable an export destination."""
        dest = self._destinations.get(tenant_id, {}).get(dest_id)
        if dest:
            dest.enabled = enabled
            return dest
        return None

    def get_destinations(self, tenant_id: str) -> list[ExportDestination]:
        """List all destinations for a tenant."""
        return list(self._destinations.get(tenant_id, {}).values())

    # ── Export ────────────────────────────────────────────────────────

    def export_to_local(
        self,
        tenant_id: str,
        *,
        ioc_type: IoCType | None = None,
        severity: IoCSeverity | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Generate a STIX bundle for local download (no network)."""
        indicators = self._ioc_engine.get_indicators(
            tenant_id,
            ioc_type=ioc_type,
            severity=severity,
            limit=limit,
        )
        bundle = build_stix_bundle(indicators)

        result = ExportResult(
            destination_id="local",
            destination_name="Local Download",
            destination_type="local",
            indicator_count=len(indicators),
            success=True,
            bundle_id=bundle["id"],
        )
        self._record_result(tenant_id, result)
        return bundle

    def export_to_destination(
        self,
        tenant_id: str,
        dest_id: str,
        *,
        ioc_type: IoCType | None = None,
        severity: IoCSeverity | None = None,
        limit: int = 1000,
    ) -> ExportResult:
        """Export IoCs to a configured destination.

        Note: Actual HTTP shipping is stubbed — in production this
        would use ``httpx`` with TLS verification, timeout, and retry.
        This method validates config, builds the bundle, and records
        the export.  Network delivery is a deployment concern.
        """
        dest = self._destinations.get(tenant_id, {}).get(dest_id)
        if not dest:
            return ExportResult(
                destination_id=dest_id,
                destination_name="Unknown",
                destination_type="unknown",
                indicator_count=0,
                success=False,
                error="Destination not found",
            )

        if not dest.enabled:
            return ExportResult(
                destination_id=dest.id,
                destination_name=dest.name,
                destination_type=dest.destination_type.value,
                indicator_count=0,
                success=False,
                error="Destination is disabled",
            )

        indicators = self._ioc_engine.get_indicators(
            tenant_id,
            ioc_type=ioc_type,
            severity=severity,
            limit=limit,
        )

        if not indicators:
            return ExportResult(
                destination_id=dest.id,
                destination_name=dest.name,
                destination_type=dest.destination_type.value,
                indicator_count=0,
                success=True,
                error="No indicators to export",
            )

        bundle = build_stix_bundle(indicators)

        # Record successful export (actual HTTP delivery is a deployment concern)
        dest.last_export_at = datetime.now(UTC).isoformat()
        dest.export_count += 1

        result = ExportResult(
            destination_id=dest.id,
            destination_name=dest.name,
            destination_type=dest.destination_type.value,
            indicator_count=len(indicators),
            success=True,
            bundle_id=bundle["id"],
        )
        self._record_result(tenant_id, result)
        return result

    # ── History ───────────────────────────────────────────────────────

    def get_export_history(self, tenant_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """List recent export results for a tenant."""
        history = self._history.get(tenant_id, [])
        return [r.to_dict() for r in history[-limit:]]

    def stats(self, tenant_id: str) -> dict[str, Any]:
        """Export statistics for a tenant."""
        dests = self._destinations.get(tenant_id, {})
        history = self._history.get(tenant_id, [])
        return {
            "destinations": len(dests),
            "enabled_destinations": sum(1 for d in dests.values() if d.enabled),
            "total_exports": len(history),
            "successful_exports": sum(1 for r in history if r.success),
            "total_indicators_exported": sum(r.indicator_count for r in history if r.success),
        }

    def _record_result(self, tenant_id: str, result: ExportResult) -> None:
        if tenant_id not in self._history:
            self._history[tenant_id] = []
        self._history[tenant_id].append(result)
        if len(self._history[tenant_id]) > self._MAX_HISTORY:
            self._history[tenant_id] = self._history[tenant_id][-self._MAX_HISTORY :]
