# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for Phase 4, Block AH — Threat Intelligence (Pluggable).

Covers:
- IoCEngine: add, dedup, correlate, batch, filters, deactivate, expire, stats, memory bounds
- STIXExporter: destinations, local export, push export, STIX bundle format, history
- FeedImporter: feeds, STIX/CSV/JSON parsing, import, correlation on import, history
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.services.threat_intel.feed_importer import (
    FeedImporter,
    FeedStatus,
    FeedType,
    parse_csv_data,
    parse_json_data,
    parse_stix_bundle,
)
from app.services.threat_intel.ioc_engine import (
    CorrelationMatch,
    Indicator,
    IoCEngine,
    IoCSeverity,
    IoCType,
    _sha256,
)
from app.services.threat_intel.stix_exporter import (
    ExportDestinationType,
    STIXExporter,
    build_stix_bundle,
    indicator_to_stix,
)

TENANT = uuid.uuid4().hex
TENANT_B = uuid.uuid4().hex

# ── IoCEngine ────────────────────────────────────────────────────────────────

class TestIoCEngine:
    def _engine(self, **kw) -> IoCEngine:
        return IoCEngine(**kw)

    def test_add_and_retrieve(self):
        e = self._engine()
        ind = e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.HIGH)
        assert isinstance(ind, Indicator)
        assert ind.hashed_value == _sha256("1.2.3.4")
        assert ind.ioc_type == IoCType.IPV4
        assert ind.severity == IoCSeverity.HIGH
        assert ind.sighting_count == 1

    def test_raw_not_stored_by_default(self):
        e = self._engine()
        ind = e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        assert ind.raw_value == ""

    def test_raw_stored_when_requested(self):
        e = self._engine(store_raw=True)
        ind = e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        assert ind.raw_value == "evil.com"

    def test_dedup_bumps_sighting(self):
        e = self._engine()
        ind1 = e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        ind2 = e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        assert ind1 is ind2
        assert ind2.sighting_count == 2

    def test_dedup_upgrades_severity(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.LOW)
        ind = e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.CRITICAL)
        assert ind.severity == IoCSeverity.CRITICAL

    def test_case_insensitive_hash(self):
        e = self._engine()
        ind1 = e.add_indicator(TENANT, IoCType.DOMAIN, "Evil.com")
        ind2 = e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        assert ind1 is ind2

    def test_add_bulk(self):
        e = self._engine()
        items = [
            {"ioc_type": "ipv4", "value": "10.0.0.1"},
            {"ioc_type": "domain", "value": "bad.net"},
            {"ioc_type": "ipv4", "value": "10.0.0.1"},  # duplicate
        ]
        added = e.add_indicators_bulk(TENANT, items)
        assert added == 2

    def test_correlate_match(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        m = e.correlate(TENANT, "1.2.3.4")
        assert m is not None
        assert isinstance(m, CorrelationMatch)
        assert m.severity == IoCSeverity.MEDIUM

    def test_correlate_miss(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        m = e.correlate(TENANT, "5.6.7.8")
        assert m is None

    def test_correlate_inactive_no_match(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        e.deactivate(TENANT, "1.2.3.4")
        m = e.correlate(TENANT, "1.2.3.4")
        assert m is None

    def test_correlate_batch(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        matches = e.correlate_batch(
            TENANT,
            [
                {"value": "1.2.3.4"},
                {"value": "clean.org"},
                {"value": "evil.com"},
            ],
        )
        assert len(matches) == 2

    def test_get_indicators_filters(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.HIGH)
        e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com", severity=IoCSeverity.LOW)
        e.add_indicator(TENANT, IoCType.IPV4, "5.6.7.8", severity=IoCSeverity.HIGH)

        all_inds = e.get_indicators(TENANT)
        assert len(all_inds) == 3

        ipv4_only = e.get_indicators(TENANT, ioc_type=IoCType.IPV4)
        assert len(ipv4_only) == 2

        high_only = e.get_indicators(TENANT, severity=IoCSeverity.HIGH)
        assert len(high_only) == 2

    def test_deactivate(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        assert e.deactivate(TENANT, "1.2.3.4") is True
        assert e.get_indicators(TENANT, active_only=True) == []
        assert len(e.get_indicators(TENANT, active_only=False)) == 1

    def test_deactivate_unknown_returns_false(self):
        e = self._engine()
        assert e.deactivate(TENANT, "9.9.9.9") is False

    def test_get_indicator_by_value(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        ind = e.get_indicator_by_value(TENANT, "evil.com")
        assert ind is not None
        assert ind.ioc_type == IoCType.DOMAIN

    def test_get_indicator_by_value_missing(self):
        e = self._engine()
        assert e.get_indicator_by_value(TENANT, "nope.org") is None

    def test_get_matches(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.CRITICAL)
        e.correlate(TENANT, "1.2.3.4")
        matches = e.get_matches(TENANT)
        assert len(matches) == 1
        assert matches[0].severity == IoCSeverity.CRITICAL

    def test_stats(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.HIGH)
        e.add_indicator(TENANT, IoCType.DOMAIN, "evil.com", severity=IoCSeverity.LOW)
        e.correlate(TENANT, "1.2.3.4")
        s = e.stats(TENANT)
        assert s["active_indicators"] == 2
        assert s["total_matches"] == 1
        assert s["by_type"]["ipv4"] == 1
        assert s["by_severity"]["high"] == 1

    def test_tenant_isolation(self):
        e = self._engine()
        e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        e.add_indicator(TENANT_B, IoCType.IPV4, "5.6.7.8")
        assert len(e.get_indicators(TENANT)) == 1
        assert len(e.get_indicators(TENANT_B)) == 1
        assert e.correlate(TENANT, "5.6.7.8") is None
        assert e.correlate(TENANT_B, "1.2.3.4") is None

    def test_memory_bound_evicts_oldest(self):
        e = self._engine()
        e._MAX_INDICATORS_PER_TENANT = 5
        for i in range(10):
            e.add_indicator(TENANT, IoCType.IPV4, f"10.0.0.{i}")
        assert len(e._indicators[TENANT]) <= 5

    def test_expire_stale(self):
        e = self._engine()
        ind = e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", ttl_seconds=0)
        # Fake old first_seen
        ind.first_seen = "2000-01-01T00:00:00+00:00"
        assert ind.expired is True
        removed = e.expire_stale(TENANT)
        assert removed == 1
        assert len(e.get_indicators(TENANT)) == 0

    def test_to_dict(self):
        e = self._engine()
        ind = e.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        d = ind.to_dict()
        assert d["ioc_type"] == "ipv4"
        assert "hashed_value" in d
        assert "expired" in d

# ── STIXExporter ─────────────────────────────────────────────────────────────

class TestSTIXExporter:
    def _setup(self) -> tuple[IoCEngine, STIXExporter]:
        engine = IoCEngine()
        return engine, STIXExporter(engine)

    def test_add_destination(self):
        engine, exp = self._setup()
        dest = exp.add_destination(TENANT, "Test SIEM", ExportDestinationType.SIEM, url="https://siem.local")
        assert dest.name == "Test SIEM"
        assert dest.destination_type == ExportDestinationType.SIEM
        assert dest.enabled is True

    def test_api_key_hashed(self):
        engine, exp = self._setup()
        dest = exp.add_destination(TENANT, "W", ExportDestinationType.WEBHOOK, api_key="secret123")
        assert dest.api_key != "secret123"
        assert len(dest.api_key) == 64  # SHA-256 hex

    def test_api_key_not_in_to_dict(self):
        engine, exp = self._setup()
        dest = exp.add_destination(TENANT, "W", ExportDestinationType.WEBHOOK, api_key="secret123")
        d = dest.to_dict()
        assert "api_key" not in d
        assert d["has_api_key"] is True

    def test_remove_destination(self):
        engine, exp = self._setup()
        dest = exp.add_destination(TENANT, "D", ExportDestinationType.LOCAL)
        assert exp.remove_destination(TENANT, dest.id) is True
        assert exp.remove_destination(TENANT, dest.id) is False

    def test_toggle_destination(self):
        engine, exp = self._setup()
        dest = exp.add_destination(TENANT, "D", ExportDestinationType.LOCAL)
        result = exp.toggle_destination(TENANT, dest.id, False)
        assert result is not None
        assert result.enabled is False

    def test_max_destinations_enforced(self):
        engine, exp = self._setup()
        exp._MAX_DESTINATIONS_PER_TENANT = 3
        for i in range(3):
            exp.add_destination(TENANT, f"D{i}", ExportDestinationType.LOCAL)
        with pytest.raises(ValueError, match="Maximum destinations"):
            exp.add_destination(TENANT, "D3", ExportDestinationType.LOCAL)

    def test_export_local(self):
        engine, exp = self._setup()
        engine.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        engine.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        bundle = exp.export_to_local(TENANT)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) == 2

    def test_export_local_empty(self):
        engine, exp = self._setup()
        bundle = exp.export_to_local(TENANT)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 0

    def test_export_to_destination_success(self):
        engine, exp = self._setup()
        engine.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        dest = exp.add_destination(TENANT, "W", ExportDestinationType.WEBHOOK, url="https://hook.local")
        result = exp.export_to_destination(TENANT, dest.id)
        assert result.success is True
        assert result.indicator_count == 1

    def test_export_to_unknown_destination(self):
        engine, exp = self._setup()
        result = exp.export_to_destination(TENANT, "nonexistent")
        assert result.success is False
        assert "not found" in result.error

    def test_export_to_disabled_destination(self):
        engine, exp = self._setup()
        dest = exp.add_destination(TENANT, "D", ExportDestinationType.WEBHOOK)
        exp.toggle_destination(TENANT, dest.id, False)
        result = exp.export_to_destination(TENANT, dest.id)
        assert result.success is False
        assert "disabled" in result.error

    def test_export_history(self):
        engine, exp = self._setup()
        engine.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        exp.export_to_local(TENANT)
        history = exp.get_export_history(TENANT)
        assert len(history) == 1
        assert history[0]["success"] is True

    def test_stats(self):
        engine, exp = self._setup()
        exp.add_destination(TENANT, "D1", ExportDestinationType.LOCAL)
        exp.add_destination(TENANT, "D2", ExportDestinationType.WEBHOOK)
        s = exp.stats(TENANT)
        assert s["destinations"] == 2
        assert s["enabled_destinations"] == 2

    def test_indicator_to_stix_format(self):
        engine = IoCEngine(store_raw=True)
        ind = engine.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4", severity=IoCSeverity.HIGH)
        stix = indicator_to_stix(ind)
        assert stix["type"] == "indicator"
        assert stix["spec_version"] == "2.1"
        assert "1.2.3.4" in stix["pattern"]
        assert stix["x_phantex_severity"] == "high"

    def test_build_stix_bundle(self):
        engine = IoCEngine()
        ind = engine.add_indicator(TENANT, IoCType.DOMAIN, "evil.com")
        bundle = build_stix_bundle([ind])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1

    def test_file_hash_stix_pattern(self):
        engine = IoCEngine()
        ind = engine.add_indicator(TENANT, IoCType.FILE_HASH, "abc123hash")
        stix = indicator_to_stix(ind)
        assert "hashes" in stix["pattern"]

# ── FeedImporter ─────────────────────────────────────────────────────────────

class TestFeedImporter:
    def _setup(self) -> tuple[IoCEngine, FeedImporter]:
        engine = IoCEngine()
        return engine, FeedImporter(engine)

    def test_add_feed(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "AbuseIPDB", FeedType.CSV, url="https://abuse.ch/feed.csv")
        assert feed.name == "AbuseIPDB"
        assert feed.feed_type == FeedType.CSV
        assert feed.status == FeedStatus.NEVER_SYNCED

    def test_remove_feed(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "F1", FeedType.CSV)
        assert imp.remove_feed(TENANT, feed.id) is True
        assert imp.remove_feed(TENANT, feed.id) is False

    def test_toggle_feed(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "F1", FeedType.CSV)
        toggled = imp.toggle_feed(TENANT, feed.id, False)
        assert toggled.enabled is False
        assert toggled.status == FeedStatus.PAUSED

    def test_max_feeds_enforced(self):
        engine, imp = self._setup()
        imp._MAX_FEEDS_PER_TENANT = 3
        for i in range(3):
            imp.add_feed(TENANT, f"F{i}", FeedType.CSV)
        with pytest.raises(ValueError, match="Maximum feeds"):
            imp.add_feed(TENANT, "F3", FeedType.CSV)

    def test_get_feeds(self):
        engine, imp = self._setup()
        imp.add_feed(TENANT, "F1", FeedType.CSV)
        imp.add_feed(TENANT, "F2", FeedType.JSON)
        feeds = imp.get_feeds(TENANT)
        assert len(feeds) == 2

    def test_get_feed(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "F1", FeedType.STIX_TAXII)
        assert imp.get_feed(TENANT, feed.id) is not None
        assert imp.get_feed(TENANT, "nope") is None

    def test_parse_csv(self):
        csv = "value,ioc_type,severity,tags\n1.2.3.4,ipv4,high,malware|botnet\nevil.com,domain,medium,phishing"
        parsed = parse_csv_data(csv)
        assert len(parsed) == 2
        assert parsed[0]["value"] == "1.2.3.4"
        assert parsed[0]["ioc_type"] == "ipv4"
        assert parsed[0]["tags"] == ["malware", "botnet"]

    def test_parse_csv_empty(self):
        assert parse_csv_data("") == []
        assert parse_csv_data("value,ioc_type\n") == []

    def test_parse_json(self):
        data = [
            {"value": "1.2.3.4", "ioc_type": "ipv4", "severity": "high"},
            {"value": "evil.com", "ioc_type": "domain"},
        ]
        parsed = parse_json_data(json.dumps(data))
        assert len(parsed) == 2

    def test_parse_json_stix_bundle(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "confidence": 80,
                },
            ],
        }
        parsed = parse_json_data(json.dumps(bundle))
        assert len(parsed) == 1
        assert parsed[0]["value"] == "1.2.3.4"

    def test_parse_stix_bundle(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "confidence": 60,
                },
                {"type": "malware", "name": "Bad"},  # non-indicator, skipped
            ],
        }
        parsed = parse_stix_bundle(bundle)
        assert len(parsed) == 1
        assert parsed[0]["value"] == "evil.com"

    def test_import_csv(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "CSV Feed", FeedType.CSV)
        csv = "value,ioc_type,severity,tags\n1.2.3.4,ipv4,high,malware"
        result = imp.import_csv(TENANT, feed.id, csv)
        assert result.imported_count == 1
        assert result.success is True
        assert feed.status == FeedStatus.ACTIVE

    def test_import_stix(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "STIX Feed", FeedType.STIX_TAXII)
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.1']", "confidence": 90},
                {"type": "indicator", "pattern": "[domain-name:value = 'bad.org']", "confidence": 70},
            ],
        }
        result = imp.import_stix_bundle(TENANT, feed.id, bundle)
        assert result.imported_count == 2
        assert result.success is True

    def test_import_json(self):
        engine, imp = self._setup()
        data = json.dumps(
            [
                {"value": "1.2.3.4", "ioc_type": "ipv4"},
                {"value": "evil.com", "ioc_type": "domain"},
            ]
        )
        result = imp.import_json(TENANT, "manual", data)
        assert result.imported_count == 2

    def test_import_manual(self):
        engine, imp = self._setup()
        items = [
            {"value": "1.2.3.4", "ioc_type": "ipv4"},
            {"value": "evil.com", "ioc_type": "domain"},
        ]
        result = imp.import_manual(TENANT, items)
        assert result.imported_count == 2
        assert result.feed_name == "Manual Entry"

    def test_import_with_correlation(self):
        engine, imp = self._setup()
        # Pre-load an indicator
        engine.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        # Now import the same value — should correlate
        result = imp.import_manual(TENANT, [{"value": "1.2.3.4", "ioc_type": "ipv4"}])
        assert result.correlation_matches >= 1

    def test_import_dedup(self):
        engine, imp = self._setup()
        items = [
            {"value": "1.2.3.4", "ioc_type": "ipv4"},
            {"value": "1.2.3.4", "ioc_type": "ipv4"},
        ]
        result = imp.import_manual(TENANT, items)
        assert result.imported_count == 1
        assert result.duplicate_count == 1

    def test_import_empty(self):
        engine, imp = self._setup()
        result = imp.import_manual(TENANT, [])
        assert result.imported_count == 0
        assert result.success is True

    def test_import_history(self):
        engine, imp = self._setup()
        imp.import_manual(TENANT, [{"value": "1.2.3.4", "ioc_type": "ipv4"}])
        history = imp.get_import_history(TENANT)
        assert len(history) == 1
        assert history[0]["success"] is True

    def test_stats(self):
        engine, imp = self._setup()
        imp.add_feed(TENANT, "F1", FeedType.CSV)
        imp.import_manual(TENANT, [{"value": "1.2.3.4", "ioc_type": "ipv4"}])
        s = imp.stats(TENANT)
        assert s["total_feeds"] == 1
        assert s["active_feeds"] == 1
        assert s["total_imported"] == 1

    def test_feed_to_dict_hides_api_key(self):
        engine, imp = self._setup()
        feed = imp.add_feed(TENANT, "F1", FeedType.STIX_TAXII, api_key_hash="hashed_secret")
        d = feed.to_dict()
        assert "api_key_hash" not in d
        assert d["has_api_key"] is True

    def test_tenant_isolation(self):
        engine, imp = self._setup()
        imp.add_feed(TENANT, "F1", FeedType.CSV)
        imp.add_feed(TENANT_B, "F2", FeedType.JSON)
        assert len(imp.get_feeds(TENANT)) == 1
        assert len(imp.get_feeds(TENANT_B)) == 1

# ── Security Regression Tests ────────────────────────────────────────────────

class TestSecurityRegression:
    """Regression tests for AH security audit findings."""

    def test_api_key_never_in_export_destination_serialization(self):
        """Export destination to_dict must never expose api_key."""
        engine = IoCEngine()
        exporter = STIXExporter(engine)
        dest = exporter.add_destination(TENANT, "D1", ExportDestinationType.WEBHOOK, api_key="super-secret")
        d = dest.to_dict()
        assert "api_key" not in d
        assert "super-secret" not in str(d)
        assert d["has_api_key"] is True

    def test_api_key_never_in_feed_serialization(self):
        """Feed to_dict must never expose api_key_hash."""
        engine = IoCEngine()
        imp = FeedImporter(engine)
        feed = imp.add_feed(TENANT, "F1", FeedType.STIX_TAXII, api_key_hash="secret_hash_value")
        d = feed.to_dict()
        assert "api_key_hash" not in d
        assert "secret_hash_value" not in str(d)

    def test_severity_ordering_correct(self):
        """Severity comparison uses numeric ordering, not alphabetical."""
        from app.services.threat_intel.ioc_engine import _SEVERITY_ORDER

        assert _SEVERITY_ORDER["low"] < _SEVERITY_ORDER["medium"]
        assert _SEVERITY_ORDER["medium"] < _SEVERITY_ORDER["high"]
        assert _SEVERITY_ORDER["high"] < _SEVERITY_ORDER["critical"]

    def test_raw_value_not_stored_by_default(self):
        """IoC engine must not store raw values in default (hashed-only) mode."""
        engine = IoCEngine(store_raw=False)
        ind = engine.add_indicator(TENANT, IoCType.IPV4, "10.0.0.1")
        assert ind.raw_value == ""
        assert ind.hashed_value != ""

    def test_stix_bundle_object_limit(self):
        """STIX import should handle max bundle size."""
        engine = IoCEngine()
        imp = FeedImporter(engine)
        # Build bundle just at parseable size
        objects = [
            {"type": "indicator", "pattern": f"[ipv4-addr:value = '1.2.3.{i}']", "confidence": 50} for i in range(100)
        ]
        bundle = {"type": "bundle", "objects": objects}
        result = imp.import_stix_bundle(TENANT, "manual", bundle)
        assert result.imported_count == 100

    def test_matches_memory_bounded(self):
        """Correlation matches per tenant must not exceed cap."""
        engine = IoCEngine()
        engine._MAX_MATCHES_PER_TENANT = 10
        engine.add_indicator(TENANT, IoCType.IPV4, "1.2.3.4")
        for _i in range(20):
            engine.correlate(TENANT, "1.2.3.4")
        matches = engine._matches.get(TENANT, [])
        assert len(matches) <= 10
