# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Compliance Report Builder (T3).

Unified report generator supporting:
  - EU AI Act
  - NIST AI RMF
  - SOC 2 (placeholder)
  - Custom frameworks

Output formats:
  - PDF (via fpdf2 — lightweight, no system deps)
  - JSON (for GRC tool integration)

Each report includes:
  - Executive summary (1-page compliance scorecard)
  - Detailed evidence per requirement/control
  - Gap analysis with remediation recommendations
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from typing import Any

from app.services.compliance.eu_ai_act import (
    EUAIActReport,
    generate_eu_ai_act_report,
)
from app.services.compliance.fedramp import (
    FedRAMPReport,
    generate_fedramp_report,
)
from app.services.compliance.iso27001 import (
    ISO27001Report,
    generate_iso27001_report,
)
from app.services.compliance.nist_ai_rmf import (
    NISTAIRMFReport,
    generate_nist_ai_rmf_report,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.compliance.report_builder")

# ── Supported Frameworks ──────────────────────────────────────────────────────

SUPPORTED_FRAMEWORKS = ("eu_ai_act", "nist_ai_rmf", "iso27001", "fedramp")

# ── Unified Report Shape ─────────────────────────────────────────────────────

def build_unified_json(
    *,
    eu_report: EUAIActReport | None = None,
    nist_report: NISTAIRMFReport | None = None,
    iso27001_report: ISO27001Report | None = None,
    fedramp_report: FedRAMPReport | None = None,
    tenant_id: str = "",
) -> dict[str, Any]:
    """Build a single JSON document combining all requested frameworks."""
    now = datetime.now(UTC).isoformat()
    doc: dict[str, Any] = {
        "generated_at": now,
        "tenant_id": tenant_id,
        "frameworks": [],
    }

    if eu_report:
        doc["frameworks"].append(eu_report.to_dict())
    if nist_report:
        doc["frameworks"].append(nist_report.to_dict())
    if iso27001_report:
        doc["frameworks"].append(iso27001_report.to_dict())
    if fedramp_report:
        doc["frameworks"].append(fedramp_report.to_dict())

    # Cross-reference summary
    doc["cross_reference"] = _build_cross_references(eu_report, nist_report)
    return doc

def _build_cross_references(
    eu: EUAIActReport | None,
    nist: NISTAIRMFReport | None,
) -> list[dict[str, str]]:
    """Build EU ↔ NIST cross-reference table."""
    xrefs: list[dict[str, str]] = []
    if not nist:
        return xrefs

    for cat in nist.categories:
        for ctrl in cat.controls:
            if ctrl.eu_ai_act_xref:
                xrefs.append(
                    {
                        "nist_control": ctrl.control_id,
                        "nist_title": ctrl.title,
                        "eu_article": ctrl.eu_ai_act_xref,
                        "nist_status": ctrl.status,
                    }
                )
    return xrefs

# ── JSON Export ───────────────────────────────────────────────────────────────

def export_json(report_data: dict[str, Any]) -> str:
    """Serialize report to JSON string."""
    return json.dumps(report_data, indent=2, default=str, ensure_ascii=False)

# ── PDF Export ────────────────────────────────────────────────────────────────

def export_pdf(
    report_data: dict[str, Any],
    *,
    title: str = "Phantex Compliance Report",
) -> bytes:
    """Generate a PDF compliance report.

    Uses fpdf2 for lightweight PDF generation without system dependencies.
    Falls back to a simple text-based PDF if fpdf2 is not installed.
    """
    try:
        return _generate_pdf_fpdf2(report_data, title=title)
    except ImportError:
        logger.warning("fpdf2_not_installed, using fallback PDF generator")
        return _generate_pdf_fallback(report_data, title=title)

def _generate_pdf_fpdf2(report_data: dict[str, Any], *, title: str) -> bytes:
    """Generate PDF using fpdf2 library."""
    from fpdf import FPDF

    def _safe(text: str) -> str:
        """Replace non-Latin-1 chars that Helvetica can't render."""
        return (
            text.replace("\u2014", "-")  # em-dash
            .replace("\u2013", "-")  # en-dash
            .replace("\u2018", "'")  # left single quote
            .replace("\u2019", "'")  # right single quote
            .replace("\u201c", '"')  # left double quote
            .replace("\u201d", '"')  # right double quote
            .replace("\u2026", "...")  # ellipsis
            .replace("\u2192", "->")  # right arrow
            .replace("\u2194", "<->")  # left-right arrow
            .encode("latin-1", errors="replace")
            .decode("latin-1")
        )

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Title Page ────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 40, _safe(title), new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_font("Helvetica", "", 12)
    pdf.cell(
        0, 10, _safe(f"Generated: {report_data.get('generated_at', 'N/A')}"), new_x="LMARGIN", new_y="NEXT", align="C"
    )
    pdf.cell(0, 10, _safe(f"Tenant: {report_data.get('tenant_id', 'N/A')}"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(20)

    # ── Executive Summary ─────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    for fw in report_data.get("frameworks", []):
        framework_name = fw.get("framework", "unknown").upper().replace("_", " ")
        score = fw.get("overall_score", 0)
        summary = fw.get("summary", {})

        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, _safe(framework_name), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 11)
        score_pct = round(score * 100, 1)
        pdf.cell(0, 7, _safe(f"  Overall Score: {score_pct}%"), new_x="LMARGIN", new_y="NEXT")

        total_key = "total_requirements" if "total_requirements" in summary else "total_controls"
        sat_key = "satisfied" if "satisfied" in summary else "implemented"
        gap_key = "gaps" if "gaps" in summary else "not_implemented"

        pdf.cell(
            0,
            7,
            _safe(
                f"  Total: {summary.get(total_key, 0)}  |  "
                f"Satisfied: {summary.get(sat_key, 0)}  |  "
                f"Gaps: {summary.get(gap_key, 0)}"
            ),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.ln(5)

    # ── Detailed Sections ─────────────────────────────────────────────────
    for fw in report_data.get("frameworks", []):
        framework_name = fw.get("framework", "unknown").upper().replace("_", " ")

        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, _safe(f"{framework_name} - Detailed Report"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        period = fw.get("period", {})
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(
            0,
            7,
            _safe(f"Period: {period.get('start', 'N/A')} to {period.get('end', 'N/A')}"),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.ln(3)

        # Articles (EU AI Act) or Categories (NIST)
        sections = fw.get("articles") or fw.get("categories", [])
        for section in sections:
            section_title = section.get("title") or section.get("category", "")
            section_score = section.get("score", 0)

            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 9, _safe(f"{section_title}  ({round(section_score * 100, 1)}%)"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

            items = section.get("requirements") or section.get("controls", [])
            for item in items:
                status = item.get("status", "unknown")
                status_icon = {
                    "satisfied": "[OK]",
                    "implemented": "[OK]",
                    "partial": "[!!]",
                    "gap": "[GAP]",
                    "not_implemented": "[GAP]",
                }.get(status, "[??]")

                pdf.set_font("Helvetica", "B", 10)
                item_id = item.get("req_id") or item.get("control_id", "")
                pdf.cell(
                    0,
                    6,
                    _safe(f"  {status_icon}  {item_id}: {item.get('description') or item.get('title', '')}"),
                    new_x="LMARGIN",
                    new_y="NEXT",
                )

                pdf.set_font("Helvetica", "", 9)
                if item.get("evidence"):
                    for ev in item["evidence"][:3]:  # Cap at 3 evidence items
                        pdf.cell(
                            0,
                            5,
                            _safe(f"      Evidence: {ev.get('description', '')} (n={ev.get('count', 0)})"),
                            new_x="LMARGIN",
                            new_y="NEXT",
                        )
                elif item.get("evidence_description"):
                    pdf.cell(
                        0, 5, _safe(f"      Evidence: {item['evidence_description']}"), new_x="LMARGIN", new_y="NEXT"
                    )

                if item.get("gap_detail"):
                    pdf.set_font("Helvetica", "I", 9)
                    pdf.cell(0, 5, _safe(f"      Gap: {item['gap_detail']}"), new_x="LMARGIN", new_y="NEXT")
                if item.get("remediation"):
                    pdf.cell(0, 5, _safe(f"      Fix: {item['remediation']}"), new_x="LMARGIN", new_y="NEXT")

                pdf.ln(1)

    # ── Cross-References ──────────────────────────────────────────────────
    xrefs = report_data.get("cross_reference", [])
    if xrefs:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "Cross-Reference: EU AI Act <-> NIST AI RMF", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(40, 7, "NIST Control", border=1)
        pdf.cell(60, 7, "NIST Title", border=1)
        pdf.cell(30, 7, "EU Article", border=1)
        pdf.cell(30, 7, "Status", border=1)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for xr in xrefs[:50]:  # Cap for PDF
            pdf.cell(40, 6, _safe(xr.get("nist_control", "")), border=1)
            pdf.cell(60, 6, _safe(xr.get("nist_title", "")[:35]), border=1)
            pdf.cell(30, 6, _safe(xr.get("eu_article", "")), border=1)
            pdf.cell(30, 6, _safe(xr.get("nist_status", "")), border=1)
            pdf.ln()

    return bytes(pdf.output())

def _generate_pdf_fallback(report_data: dict[str, Any], *, title: str) -> bytes:
    """Minimal text-based PDF without fpdf2 dependency."""
    lines = [
        title,
        "=" * len(title),
        f"Generated: {report_data.get('generated_at', 'N/A')}",
        f"Tenant: {report_data.get('tenant_id', 'N/A')}",
        "",
    ]

    for fw in report_data.get("frameworks", []):
        name = fw.get("framework", "").upper().replace("_", " ")
        score = round(fw.get("overall_score", 0) * 100, 1)
        lines.append(f"\n{name} — Score: {score}%")
        lines.append("-" * 40)

        sections = fw.get("articles") or fw.get("categories", [])
        for sec in sections:
            sec_title = sec.get("title") or sec.get("category", "")
            lines.append(f"\n  {sec_title}")
            items = sec.get("requirements") or sec.get("controls", [])
            for item in items:
                status = item.get("status", "?")
                item_id = item.get("req_id") or item.get("control_id", "")
                desc = item.get("description") or item.get("title", "")
                lines.append(f"    [{status}] {item_id}: {desc}")

    text = "\n".join(lines)

    # Minimal PDF structure
    buf = io.BytesIO()
    text.encode("latin-1", errors="replace")
    stream = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        b"/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
        b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Courier>>endobj\n"
    )
    # Build content stream
    text_ops = b"BT /F1 8 Tf 36 756 Td "
    for line in text.split("\n")[:90]:  # Cap lines for single page
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        text_ops += f"({safe}) Tj 0 -10 Td ".encode("latin-1", errors="replace")
    text_ops += b"ET"
    stream_obj = f"4 0 obj<</Length {len(text_ops)}>>stream\n".encode() + text_ops + b"\nendstream\nendobj\n"

    xref_offset = len(stream) + len(stream_obj)
    buf.write(stream)
    buf.write(stream_obj)
    buf.write(b"xref\n0 6\n")
    buf.write(b"0000000000 65535 f \n")
    for i in range(1, 6):
        buf.write(f"{i:010d} 00000 n \n".encode())
    buf.write(f"trailer<</Size 6/Root 1 0 R>>\nstartxref\n{xref_offset}\n%%EOF".encode())

    return buf.getvalue()

# ── Main Interface ────────────────────────────────────────────────────────────

async def generate_compliance_report(
    db,
    tenant_id: str,
    frameworks: list[str],
    period_start: str,
    period_end: str,
) -> dict[str, Any]:
    """Generate compliance report for specified frameworks.

    Parameters
    ----------
    db : RawSessionWrapper
    tenant_id : str
    frameworks : list of str
        e.g. ["eu_ai_act", "nist_ai_rmf"]
    period_start, period_end : str
        ISO-8601 datetime strings.

    Returns
    -------
    dict
        Unified JSON report data (can be passed to export_pdf or export_json).
    """
    eu_report = None
    nist_report = None
    iso_report = None
    fed_report = None

    if "eu_ai_act" in frameworks:
        eu_report = await generate_eu_ai_act_report(db, tenant_id, period_start, period_end)
    if "nist_ai_rmf" in frameworks:
        nist_report = await generate_nist_ai_rmf_report(db, tenant_id, period_start, period_end)
    if "iso27001" in frameworks:
        iso_report = await generate_iso27001_report(db, tenant_id, period_start, period_end)
    if "fedramp" in frameworks:
        fed_report = await generate_fedramp_report(db, tenant_id, period_start, period_end)

    return build_unified_json(
        eu_report=eu_report,
        nist_report=nist_report,
        iso27001_report=iso_report,
        fedramp_report=fed_report,
        tenant_id=tenant_id,
    )
