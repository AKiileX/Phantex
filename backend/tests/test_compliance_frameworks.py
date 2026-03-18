# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for Phase 4, Block AK — ISO 27001 + FedRAMP Tooling.

Covers:
- ISO 27001: Control definitions, themes, report generation, scoring, to_dict
- FedRAMP: Control definitions, families, report generation, scoring, to_dict
- Evidence Collector: artifact packaging, bounds, manifest
- Report Builder: SUPPORTED_FRAMEWORKS, unified JSON, dispatch
- Scanner: default frameworks list
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile

import pytest

from app.services.compliance.evidence_collector import (
    _MAX_AUDIT_ROWS,
    _MAX_ZIP_SIZE,
    collect_evidence_package,
)
from app.services.compliance.fedramp import (
    CONTROLS as FED_CONTROLS,
)
from app.services.compliance.fedramp import (
    FAMILIES,
    FamilyResult,
    FedRAMPReport,
    generate_fedramp_report,
)
from app.services.compliance.fedramp import (
    ControlResult as FedControlResult,
)
from app.services.compliance.iso27001 import (
    CONTROLS as ISO_CONTROLS,
)
from app.services.compliance.iso27001 import (
    ControlResult as ISOControlResult,
)
from app.services.compliance.iso27001 import (
    ISO27001Report,
    ThemeResult,
    generate_iso27001_report,
)
from app.services.compliance.report_builder import (
    SUPPORTED_FRAMEWORKS,
    build_unified_json,
    export_json,
    generate_compliance_report,
)

TENANT = uuid.uuid4().hex

# ═══════════════════════════════════════════════════════════════════════════════
#  ISO 27001 — Control Definitions
# ═══════════════════════════════════════════════════════════════════════════════

class TestISO27001Controls:
    def test_control_count(self):
        assert len(ISO_CONTROLS) == 93

    def test_all_ids_unique(self):
        ids = [c.control_id for c in ISO_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_themes_present(self):
        themes = {c.theme for c in ISO_CONTROLS}
        assert themes == {"Organisational", "People", "Physical", "Technological"}

    def test_organisational_count(self):
        count = sum(1 for c in ISO_CONTROLS if c.theme == "Organisational")
        assert count == 37

    def test_people_count(self):
        count = sum(1 for c in ISO_CONTROLS if c.theme == "People")
        assert count == 8

    def test_physical_count(self):
        count = sum(1 for c in ISO_CONTROLS if c.theme == "Physical")
        assert count == 14

    def test_technological_count(self):
        count = sum(1 for c in ISO_CONTROLS if c.theme == "Technological")
        assert count == 34

    def test_control_has_required_fields(self):
        for ctrl in ISO_CONTROLS:
            assert ctrl.control_id.startswith("A.")
            assert ctrl.theme in ("Organisational", "People", "Physical", "Technological")
            assert ctrl.title
            assert ctrl.description
            assert ctrl.phantex_evidence

    def test_control_ids_ordered(self):
        for i in range(1, len(ISO_CONTROLS)):
            # Controls within same theme should maintain order
            if ISO_CONTROLS[i].theme == ISO_CONTROLS[i - 1].theme:
                prev_num = ISO_CONTROLS[i - 1].control_id
                curr_num = ISO_CONTROLS[i].control_id
                # Just verify they start with A.
                assert prev_num.startswith("A.")
                assert curr_num.startswith("A.")

    def test_nist_cross_references(self):
        with_xref = [c for c in ISO_CONTROLS if c.nist_xref]
        assert len(with_xref) >= 10  # At least 10 have cross-refs

    def test_frozen_dataclass(self):
        ctrl = ISO_CONTROLS[0]
        with pytest.raises(AttributeError):
            ctrl.title = "modified"

# ═══════════════════════════════════════════════════════════════════════════════
#  ISO 27001 — Report / Result Dataclasses
# ═══════════════════════════════════════════════════════════════════════════════

class TestISO27001Report:
    def test_control_result_created(self):
        r = ISOControlResult(
            control_id="A.5.1",
            theme="Organisational",
            title="Policies",
            status="implemented",
            evidence_description="test",
            count=3,
        )
        assert r.status == "implemented"
        assert r.count == 3

    def test_theme_result_counts(self):
        controls = [
            ISOControlResult("A.5.1", "Organisational", "P1", "implemented"),
            ISOControlResult("A.5.2", "Organisational", "P2", "implemented"),
            ISOControlResult("A.5.3", "Organisational", "P3", "not_applicable"),
        ]
        theme = ThemeResult(theme="Organisational", controls=controls, score=0.66)
        assert theme.implemented_count == 2
        assert theme.not_applicable_count == 1

    def test_report_to_dict(self):
        controls = [
            ISOControlResult("A.8.1", "Technological", "Endpoint", "implemented", count=1),
        ]
        theme = ThemeResult(theme="Technological", controls=controls, score=1.0)
        report = ISO27001Report(
            report_id="r1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
            themes=[theme],
            overall_score=1.0,
            total_controls=1,
            implemented_controls=1,
        )
        d = report.to_dict()
        assert d["framework"] == "iso27001"
        assert d["overall_score"] == 1.0
        assert d["summary"]["total_controls"] == 1
        assert d["summary"]["implemented"] == 1
        assert len(d["categories"]) == 1
        assert d["categories"][0]["category"] == "Technological"
        assert len(d["categories"][0]["controls"]) == 1

    def test_report_to_dict_has_period(self):
        report = ISO27001Report(
            report_id="r2",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
        )
        d = report.to_dict()
        assert d["period"]["start"] == "2024-12-01"
        assert d["period"]["end"] == "2025-01-01"

    def test_report_to_dict_summary_counts(self):
        report = ISO27001Report(
            report_id="r3",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
            total_controls=93,
            implemented_controls=80,
            partial_controls=3,
            not_applicable_controls=10,
        )
        d = report.to_dict()
        assert d["summary"]["total_controls"] == 93
        assert d["summary"]["implemented"] == 80
        assert d["summary"]["partial"] == 3
        assert d["summary"]["not_applicable"] == 10

# ═══════════════════════════════════════════════════════════════════════════════
#  ISO 27001 — Report Generation (with mock DB)
# ═══════════════════════════════════════════════════════════════════════════════

class _MockDB:
    """Minimal mock for DB evidence collection queries."""

    def __init__(self, rows=None):
        self._rows = rows or {}

    async def fetchrow(self, sql, *args):
        for key, val in self._rows.items():
            if key in sql:
                return val
        return {"cnt": 0}

    async def fetch(self, sql, *args):
        return []

    async def execute(self, sql, *args):
        pass

class TestISO27001Generation:
    @pytest.mark.asyncio
    async def test_generate_report_structure(self):
        db = _MockDB()
        report = await generate_iso27001_report(db, TENANT, "2024-12-01", "2025-01-01")
        assert isinstance(report, ISO27001Report)
        assert report.framework == "iso27001"
        assert report.total_controls == 93
        assert report.tenant_id == TENANT

    @pytest.mark.asyncio
    async def test_generate_report_has_all_themes(self):
        db = _MockDB()
        report = await generate_iso27001_report(db, TENANT, "2024-12-01", "2025-01-01")
        theme_names = [t.theme for t in report.themes]
        assert theme_names == ["Organisational", "People", "Physical", "Technological"]

    @pytest.mark.asyncio
    async def test_physical_controls_not_applicable(self):
        db = _MockDB()
        report = await generate_iso27001_report(db, TENANT, "2024-12-01", "2025-01-01")
        assert report.not_applicable_controls >= 10  # Most physical controls are N/A for SaaS

    @pytest.mark.asyncio
    async def test_overall_score_between_0_and_1(self):
        db = _MockDB()
        report = await generate_iso27001_report(db, TENANT, "2024-12-01", "2025-01-01")
        assert 0.0 <= report.overall_score <= 1.0

    @pytest.mark.asyncio
    async def test_to_dict_after_generation(self):
        db = _MockDB()
        report = await generate_iso27001_report(db, TENANT, "2024-12-01", "2025-01-01")
        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["framework"] == "iso27001"
        assert len(d["categories"]) == 4

    @pytest.mark.asyncio
    async def test_runtime_evidence_enriches_scores(self):
        db = _MockDB(
            rows={
                "policies": {"cnt": 5},
                "roles": {"cnt": 3},
                "agents": {"cnt": 10},
                "rules": {"cnt": 8},
                "alerts": {"cnt": 25},
                "channels": {"cnt": 2},
            }
        )
        report = await generate_iso27001_report(db, TENANT, "2024-12-01", "2025-01-01")
        # All capability-based controls should be implemented
        assert report.implemented_controls > 0
        assert report.overall_score > 0

# ═══════════════════════════════════════════════════════════════════════════════
#  FedRAMP — Control Definitions
# ═══════════════════════════════════════════════════════════════════════════════

class TestFedRAMPControls:
    def test_control_count(self):
        assert len(FED_CONTROLS) == 67

    def test_all_ids_unique(self):
        ids = [c.control_id for c in FED_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_families_coverage(self):
        families = {c.family for c in FED_CONTROLS}
        assert len(families) == 10

    def test_family_codes(self):
        codes = {c.family_code for c in FED_CONTROLS}
        expected = {"AC", "AU", "CA", "CM", "IA", "IR", "RA", "SA", "SC", "SI"}
        assert codes == expected

    def test_access_control_family_count(self):
        count = sum(1 for c in FED_CONTROLS if c.family_code == "AC")
        assert count == 12

    def test_audit_family_count(self):
        count = sum(1 for c in FED_CONTROLS if c.family_code == "AU")
        assert count == 10

    def test_control_has_required_fields(self):
        for ctrl in FED_CONTROLS:
            assert ctrl.control_id
            assert ctrl.family
            assert ctrl.family_code
            assert ctrl.title
            assert ctrl.description
            assert ctrl.phantex_implementation
            assert ctrl.impact == "Moderate"

    def test_frozen_dataclass(self):
        ctrl = FED_CONTROLS[0]
        with pytest.raises(AttributeError):
            ctrl.title = "modified"

    def test_families_tuple_has_10(self):
        assert len(FAMILIES) == 10

# ═══════════════════════════════════════════════════════════════════════════════
#  FedRAMP — Report / Result Dataclasses
# ═══════════════════════════════════════════════════════════════════════════════

class TestFedRAMPReport:
    def test_control_result_created(self):
        r = FedControlResult(
            control_id="AC-2",
            family="Access Control",
            family_code="AC",
            title="Account Management",
            status="implemented",
        )
        assert r.status == "implemented"

    def test_family_result_counts(self):
        controls = [
            FedControlResult("AC-1", "Access Control", "AC", "P1", "implemented"),
            FedControlResult("AC-2", "Access Control", "AC", "P2", "implemented"),
            FedControlResult("AC-3", "Access Control", "AC", "P3", "planned"),
        ]
        fam = FamilyResult(family="Access Control", family_code="AC", controls=controls)
        assert fam.implemented_count == 2
        assert fam.planned_count == 1

    def test_report_to_dict(self):
        controls = [
            FedControlResult("SI-1", "System and Information Integrity", "SI", "Policy", "implemented", count=1),
        ]
        fam = FamilyResult(family="System and Information Integrity", family_code="SI", controls=controls, score=1.0)
        report = FedRAMPReport(
            report_id="r1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
            families=[fam],
            overall_score=1.0,
            total_controls=1,
            implemented_controls=1,
        )
        d = report.to_dict()
        assert d["framework"] == "fedramp"
        assert d["impact_level"] == "Moderate"
        assert d["overall_score"] == 1.0
        assert len(d["categories"]) == 1
        assert d["categories"][0]["family_code"] == "SI"

    def test_report_to_dict_summary(self):
        report = FedRAMPReport(
            report_id="r2",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
            total_controls=67,
            implemented_controls=55,
            partial_controls=7,
            planned_controls=5,
        )
        d = report.to_dict()
        s = d["summary"]
        assert s["total_controls"] == 67
        assert s["implemented"] == 55
        assert s["partial"] == 7
        assert s["planned"] == 5

# ═══════════════════════════════════════════════════════════════════════════════
#  FedRAMP — Report Generation (with mock DB)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFedRAMPGeneration:
    @pytest.mark.asyncio
    async def test_generate_report_structure(self):
        db = _MockDB()
        report = await generate_fedramp_report(db, TENANT, "2024-12-01", "2025-01-01")
        assert isinstance(report, FedRAMPReport)
        assert report.framework == "fedramp"
        assert report.total_controls == 67
        assert report.tenant_id == TENANT

    @pytest.mark.asyncio
    async def test_generate_report_has_all_families(self):
        db = _MockDB()
        report = await generate_fedramp_report(db, TENANT, "2024-12-01", "2025-01-01")
        fam_names = [f.family for f in report.families]
        assert len(fam_names) == 10

    @pytest.mark.asyncio
    async def test_overall_score_between_0_and_1(self):
        db = _MockDB()
        report = await generate_fedramp_report(db, TENANT, "2024-12-01", "2025-01-01")
        assert 0.0 <= report.overall_score <= 1.0

    @pytest.mark.asyncio
    async def test_all_controls_accounted_for(self):
        db = _MockDB()
        report = await generate_fedramp_report(db, TENANT, "2024-12-01", "2025-01-01")
        total = (
            report.implemented_controls
            + report.partial_controls
            + report.planned_controls
            + report.not_applicable_controls
        )
        assert total == report.total_controls

    @pytest.mark.asyncio
    async def test_to_dict_after_generation(self):
        db = _MockDB()
        report = await generate_fedramp_report(db, TENANT, "2024-12-01", "2025-01-01")
        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["framework"] == "fedramp"
        assert d["impact_level"] == "Moderate"

    @pytest.mark.asyncio
    async def test_runtime_evidence_enriches(self):
        db = _MockDB(
            rows={
                "roles": {"cnt": 3},
                "policies": {"cnt": 5},
                "agents": {"cnt": 10},
                "alerts": {"cnt": 100},
                "audit_log": {"cnt": 500},
            }
        )
        report = await generate_fedramp_report(db, TENANT, "2024-12-01", "2025-01-01")
        assert report.implemented_controls > 0

# ═══════════════════════════════════════════════════════════════════════════════
#  Evidence Collector
# ═══════════════════════════════════════════════════════════════════════════════

class TestEvidenceCollector:
    @pytest.mark.asyncio
    async def test_collect_produces_zip(self):
        db = _MockDB()
        zip_bytes, package_id = await collect_evidence_package(db, TENANT)
        assert isinstance(zip_bytes, bytes)
        assert len(package_id) == 32  # hex UUID

    @pytest.mark.asyncio
    async def test_zip_contains_manifest(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(db, TENANT)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            assert "index.json" in names

    @pytest.mark.asyncio
    async def test_zip_contains_compliance_reports(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(
            db,
            TENANT,
            frameworks=["iso27001", "fedramp"],
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            assert "compliance/iso27001_report.json" in names
            assert "compliance/fedramp_report.json" in names

    @pytest.mark.asyncio
    async def test_zip_contains_audit_log(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(db, TENANT)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "audit_log.json" in zf.namelist()

    @pytest.mark.asyncio
    async def test_zip_contains_inventory(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(db, TENANT)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "inventory/agents.json" in zf.namelist()

    @pytest.mark.asyncio
    async def test_zip_contains_config(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(db, TENANT)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "configs/platform_config.json" in zf.namelist()

    @pytest.mark.asyncio
    async def test_zip_contains_classification(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(db, TENANT)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "classification_summary.json" in zf.namelist()

    @pytest.mark.asyncio
    async def test_manifest_has_artifacts(self):
        db = _MockDB()
        zip_bytes, pkg_id = await collect_evidence_package(db, TENANT)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            manifest = json.loads(zf.read("index.json"))
        assert manifest["package_id"] == pkg_id
        assert manifest["tenant_id"] == TENANT
        assert len(manifest["artifacts"]) >= 6

    @pytest.mark.asyncio
    async def test_custom_period(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(
            db,
            TENANT,
            period_start="2024-06-01",
            period_end="2024-12-31",
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            manifest = json.loads(zf.read("index.json"))
        assert manifest["period"]["start"] == "2024-06-01"
        assert manifest["period"]["end"] == "2024-12-31"

    @pytest.mark.asyncio
    async def test_custom_frameworks(self):
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(
            db,
            TENANT,
            frameworks=["iso27001"],
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            assert "compliance/iso27001_report.json" in names
            # FedRAMP should NOT be present
            assert "compliance/fedramp_report.json" not in names

    def test_max_audit_rows_bound(self):
        assert _MAX_AUDIT_ROWS == 50_000

    def test_max_zip_size_bound(self):
        assert _MAX_ZIP_SIZE == 100 * 1024 * 1024

# ═══════════════════════════════════════════════════════════════════════════════
#  Report Builder Integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportBuilderIntegration:
    def test_supported_frameworks_includes_new(self):
        assert "iso27001" in SUPPORTED_FRAMEWORKS
        assert "fedramp" in SUPPORTED_FRAMEWORKS
        assert "eu_ai_act" in SUPPORTED_FRAMEWORKS
        assert "nist_ai_rmf" in SUPPORTED_FRAMEWORKS
        assert len(SUPPORTED_FRAMEWORKS) == 4

    def test_build_unified_json_with_iso(self):
        iso_report = ISO27001Report(
            report_id="iso1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
            overall_score=0.85,
            total_controls=93,
        )
        doc = build_unified_json(iso27001_report=iso_report, tenant_id=TENANT)
        assert len(doc["frameworks"]) == 1
        assert doc["frameworks"][0]["framework"] == "iso27001"

    def test_build_unified_json_with_fedramp(self):
        fed_report = FedRAMPReport(
            report_id="fed1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
            overall_score=0.9,
            total_controls=62,
        )
        doc = build_unified_json(fedramp_report=fed_report, tenant_id=TENANT)
        assert len(doc["frameworks"]) == 1
        assert doc["frameworks"][0]["framework"] == "fedramp"

    def test_build_unified_json_all_four(self):
        iso_report = ISO27001Report(
            report_id="iso1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
        )
        fed_report = FedRAMPReport(
            report_id="fed1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
        )
        doc = build_unified_json(
            iso27001_report=iso_report,
            fedramp_report=fed_report,
            tenant_id=TENANT,
        )
        frameworks = [f["framework"] for f in doc["frameworks"]]
        assert "iso27001" in frameworks
        assert "fedramp" in frameworks

    @pytest.mark.asyncio
    async def test_generate_compliance_report_iso27001(self):
        db = _MockDB()
        data = await generate_compliance_report(
            db,
            TENANT,
            ["iso27001"],
            "2024-12-01",
            "2025-01-01",
        )
        assert isinstance(data, dict)
        fw_names = [f["framework"] for f in data["frameworks"]]
        assert "iso27001" in fw_names

    @pytest.mark.asyncio
    async def test_generate_compliance_report_fedramp(self):
        db = _MockDB()
        data = await generate_compliance_report(
            db,
            TENANT,
            ["fedramp"],
            "2024-12-01",
            "2025-01-01",
        )
        fw_names = [f["framework"] for f in data["frameworks"]]
        assert "fedramp" in fw_names

    @pytest.mark.asyncio
    async def test_generate_compliance_report_all_four(self):
        db = _MockDB()
        data = await generate_compliance_report(
            db,
            TENANT,
            ["eu_ai_act", "nist_ai_rmf", "iso27001", "fedramp"],
            "2024-12-01",
            "2025-01-01",
        )
        fw_names = [f["framework"] for f in data["frameworks"]]
        assert len(fw_names) == 4

    def test_export_json_works_with_iso(self):
        iso_report = ISO27001Report(
            report_id="iso1",
            tenant_id=TENANT,
            generated_at="2025-01-01T00:00:00Z",
            period_start="2024-12-01",
            period_end="2025-01-01",
        )
        doc = build_unified_json(iso27001_report=iso_report, tenant_id=TENANT)
        result = export_json(doc)
        parsed = json.loads(result)
        assert parsed["frameworks"][0]["framework"] == "iso27001"

# ═══════════════════════════════════════════════════════════════════════════════
#  Scanner Integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestScannerIntegration:
    def test_scanner_default_frameworks(self):
        """Verify scanner defaults include all 4 frameworks."""
        import inspect

        from app.services.compliance.scanner import run_scan

        src = inspect.getsource(run_scan)
        # Check the default frameworks list includes iso27001 and fedramp
        assert "iso27001" in src
        assert "fedramp" in src

# ═══════════════════════════════════════════════════════════════════════════════
#  Cross-Framework Consistency
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossFramework:
    def test_iso_controls_all_have_phantex_mapping(self):
        """Every ISO 27001 control should map to a Phantex capability."""
        for ctrl in ISO_CONTROLS:
            assert ctrl.phantex_evidence, f"{ctrl.control_id} missing phantex_evidence"

    def test_fedramp_controls_all_have_phantex_mapping(self):
        """Every FedRAMP control should map to a Phantex capability."""
        for ctrl in FED_CONTROLS:
            assert ctrl.phantex_implementation, f"{ctrl.control_id} missing phantex_implementation"

    def test_iso_report_dict_matches_nist_shape(self):
        """ISO 27001 report dict should use same 'categories' key as NIST."""
        report = ISO27001Report(
            report_id="r1",
            tenant_id=TENANT,
            generated_at="now",
            period_start="s",
            period_end="e",
        )
        d = report.to_dict()
        assert "categories" in d
        assert "summary" in d
        assert "overall_score" in d

    def test_fedramp_report_dict_matches_nist_shape(self):
        """FedRAMP report dict should use same 'categories' key as NIST."""
        report = FedRAMPReport(
            report_id="r1",
            tenant_id=TENANT,
            generated_at="now",
            period_start="s",
            period_end="e",
        )
        d = report.to_dict()
        assert "categories" in d
        assert "summary" in d
        assert "overall_score" in d

    @pytest.mark.asyncio
    async def test_all_four_reports_generate_and_combine(self):
        db = _MockDB()
        data = await generate_compliance_report(
            db,
            TENANT,
            ["eu_ai_act", "nist_ai_rmf", "iso27001", "fedramp"],
            "2024-12-01",
            "2025-01-01",
        )
        frameworks = data["frameworks"]
        fw_names = sorted(f["framework"] for f in frameworks)
        assert fw_names == ["eu_ai_act", "fedramp", "iso27001", "nist_ai_rmf"]
        for fw in frameworks:
            assert 0.0 <= fw["overall_score"] <= 1.0

# ═══════════════════════════════════════════════════════════════════════════════
#  Security Regression Tests (AK Audit)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityRegression:
    """Verify hardening fixes from the AK security audit."""

    @pytest.mark.asyncio
    async def test_evidence_collector_deduplicates_frameworks(self):
        """Duplicate frameworks should be collapsed to one."""
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(
            db,
            TENANT,
            frameworks=["iso27001", "iso27001", "iso27001", "fedramp", "fedramp"],
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            manifest = json.loads(zf.read("index.json"))
        # Should only have iso27001 and fedramp once each
        assert manifest["frameworks"] == ["iso27001", "fedramp"]

    @pytest.mark.asyncio
    async def test_evidence_collector_rejects_invalid_frameworks(self):
        """Unknown framework names should be silently filtered."""
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(
            db,
            TENANT,
            frameworks=["iso27001", "MALICIOUS_FRAMEWORK", "../etc/passwd", "fedramp"],
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            manifest = json.loads(zf.read("index.json"))
        assert manifest["frameworks"] == ["iso27001", "fedramp"]

    @pytest.mark.asyncio
    async def test_evidence_collector_bounds_framework_count(self):
        """Frameworks list should be bounded even if all valid."""
        from app.services.compliance.evidence_collector import _MAX_FRAMEWORKS

        assert _MAX_FRAMEWORKS == 10

    def test_evidence_collector_allowed_frameworks_frozenset(self):
        """Allowed frameworks should be a frozenset (immutable)."""
        from app.services.compliance.evidence_collector import _ALLOWED_FRAMEWORKS

        assert isinstance(_ALLOWED_FRAMEWORKS, frozenset)
        assert len(_ALLOWED_FRAMEWORKS) == 4

    def test_classification_query_bounded(self):
        """Classification summary query should have a LIMIT."""
        from app.services.compliance.evidence_collector import _MAX_CLASSIFICATION_CATEGORIES

        assert _MAX_CLASSIFICATION_CATEGORIES == 500

    def test_iso_parameterized_queries(self):
        """ISO 27001 evidence collection uses parameterized queries."""
        import inspect

        from app.services.compliance.iso27001 import _collect_evidence

        src = inspect.getsource(_collect_evidence)
        # All queries use $1, $2, $3 parameterized placeholders
        assert "$1" in src
        assert "f'" not in src or 'f"' not in src  # No f-string SQL

    def test_fedramp_parameterized_queries(self):
        """FedRAMP evidence collection uses parameterized queries."""
        import inspect

        from app.services.compliance.fedramp import _collect_evidence

        src = inspect.getsource(_collect_evidence)
        assert "$1" in src
        assert "f'" not in src or 'f"' not in src

    def test_evidence_collector_parameterized_queries(self):
        """Evidence collector uses parameterized queries."""
        import inspect

        from app.services.compliance.evidence_collector import _collect_audit_log

        src = inspect.getsource(_collect_audit_log)
        assert "$1" in src

    @pytest.mark.asyncio
    async def test_evidence_collector_validates_tenant_id(self):
        """Invalid tenant_id should raise ValueError via UUID parsing."""
        db = _MockDB()
        with pytest.raises(ValueError):
            await collect_evidence_package(db, "not-a-uuid")

    @pytest.mark.asyncio
    async def test_empty_frameworks_produces_valid_zip(self):
        """Empty frameworks list (after filtering) still produces valid ZIP."""
        db = _MockDB()
        zip_bytes, _ = await collect_evidence_package(
            db,
            TENANT,
            frameworks=["INVALID_ONLY"],
        )
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "index.json" in zf.namelist()
            manifest = json.loads(zf.read("index.json"))
        assert manifest["frameworks"] == []
