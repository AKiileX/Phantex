# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Evidence Collector Pipeline.

Collects, packages, and exports audit-ready evidence from:
  - Audit logs
  - Compliance reports (EU AI Act, NIST AI RMF, ISO 27001, FedRAMP)
  - Data classification labels
  - Agent inventory / trust scores
  - Configuration snapshots

Produces a single ZIP archive with:
  - index.json          — manifest of all evidence artifacts
  - audit_log.json      — audit trail excerpt for the period
  - compliance/         — compliance report JSONs per framework
  - configs/            — anonymized configuration snapshots
  - inventory/          — agent and MCP server inventories

All data is tenant-scoped and size-bounded.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.compliance.evidence_collector")

# ── Safety Bounds ─────────────────────────────────────────────────────────────

_MAX_AUDIT_ROWS = 50_000
_MAX_AGENTS = 10_000
_MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100 MB hard cap
_MAX_FRAMEWORKS = 10
_ALLOWED_FRAMEWORKS = frozenset({"eu_ai_act", "nist_ai_rmf", "iso27001", "fedramp"})
_MAX_CLASSIFICATION_CATEGORIES = 500

# ── Public API ────────────────────────────────────────────────────────────────

async def collect_evidence_package(
    db,
    tenant_id: str,
    period_start: str | None = None,
    period_end: str | None = None,
    *,
    frameworks: list[str] | None = None,
) -> tuple[bytes, str]:
    """Collect all evidence and package into a ZIP archive.

    Returns
    -------
    tuple[bytes, str]
        (zip_bytes, package_id)
    """
    now = datetime.now(UTC)
    if not period_end:
        period_end = now.isoformat()
    if not period_start:
        period_start = (now - timedelta(days=30)).isoformat()
    if frameworks is None:
        frameworks = ["eu_ai_act", "nist_ai_rmf", "iso27001", "fedramp"]

    # Deduplicate, validate, and bound frameworks
    seen: set[str] = set()
    validated: list[str] = []
    for fw in frameworks:
        if fw in _ALLOWED_FRAMEWORKS and fw not in seen:
            seen.add(fw)
            validated.append(fw)
        if len(validated) >= _MAX_FRAMEWORKS:
            break
    frameworks = validated

    package_id = uuid.uuid4().hex
    tid = uuid.UUID(tenant_id)

    manifest: dict[str, Any] = {
        "package_id": package_id,
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "period": {"start": period_start, "end": period_end},
        "frameworks": frameworks,
        "artifacts": [],
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # ── 1. Audit Log Excerpt ──────────────────────────────────────────
        audit_data = await _collect_audit_log(db, tid, period_start, period_end)
        _add_json_artifact(zf, manifest, "audit_log.json", audit_data, "Audit trail excerpt")

        # ── 2. Compliance Reports ─────────────────────────────────────────
        for fw in frameworks:
            report_data = await _collect_compliance_report(db, tenant_id, fw, period_start, period_end)
            if report_data:
                _add_json_artifact(
                    zf,
                    manifest,
                    f"compliance/{fw}_report.json",
                    report_data,
                    f"{fw} compliance report",
                )

        # ── 3. Agent Inventory ────────────────────────────────────────────
        agents = await _collect_agent_inventory(db, tid)
        _add_json_artifact(zf, manifest, "inventory/agents.json", agents, "Agent inventory")

        # ── 4. Configuration Snapshot ─────────────────────────────────────
        config = await _collect_config_snapshot(db, tid)
        _add_json_artifact(zf, manifest, "configs/platform_config.json", config, "Configuration snapshot")

        # ── 5. Data Classification Summary ────────────────────────────────
        classification = await _collect_classification_summary(db, tid, period_start, period_end)
        _add_json_artifact(zf, manifest, "classification_summary.json", classification, "Data classification summary")

        # ── Write manifest ────────────────────────────────────────────────
        zf.writestr("index.json", json.dumps(manifest, indent=2, default=str))

    zip_bytes = buf.getvalue()

    if len(zip_bytes) > _MAX_ZIP_SIZE:
        logger.warning("evidence_package_too_large", size=len(zip_bytes), max=_MAX_ZIP_SIZE)
        raise ValueError(f"Evidence package exceeds {_MAX_ZIP_SIZE // (1024 * 1024)}MB limit")

    logger.info(
        "evidence_package_created",
        package_id=package_id,
        tenant=tenant_id,
        size_bytes=len(zip_bytes),
        artifact_count=len(manifest["artifacts"]),
    )
    return zip_bytes, package_id

# ── Internal Collectors ───────────────────────────────────────────────────────

def _add_json_artifact(
    zf: zipfile.ZipFile,
    manifest: dict,
    path: str,
    data: Any,
    description: str,
) -> None:
    """Add a JSON artifact to the ZIP and register in manifest."""
    content = json.dumps(data, indent=2, default=str, ensure_ascii=False)
    zf.writestr(path, content)
    manifest["artifacts"].append(
        {
            "path": path,
            "description": description,
            "size_bytes": len(content.encode("utf-8")),
        }
    )

async def _collect_audit_log(db, tid: uuid.UUID, start: str, end: str) -> list[dict]:
    """Fetch audit log entries for the evidence period."""
    try:
        rows = await db.fetch(
            """
            SELECT id, action, resource_type, resource_id,
                   user_id, details, created_at
            FROM audit_log
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            ORDER BY created_at DESC
            LIMIT $4
            """,
            tid,
            start,
            end,
            _MAX_AUDIT_ROWS,
        )
        return [
            {
                "id": str(r["id"]),
                "action": r["action"],
                "resource_type": r["resource_type"],
                "resource_id": str(r["resource_id"]) if r["resource_id"] else None,
                "user_id": str(r["user_id"]) if r["user_id"] else None,
                "details": r["details"],
                "created_at": str(r["created_at"]),
            }
            for r in rows
        ]
    except Exception as e:
        logger.warning("audit_log_collection_failed", error=str(e))
        return [{"note": "Audit log collection unavailable", "error": str(e)}]

async def _collect_compliance_report(
    db,
    tenant_id: str,
    framework: str,
    start: str,
    end: str,
) -> dict | None:
    """Generate or fetch the latest compliance report for a framework."""
    generators = {
        "eu_ai_act": "_gen_eu",
        "nist_ai_rmf": "_gen_nist",
        "iso27001": "_gen_iso",
        "fedramp": "_gen_fedramp",
    }
    if framework not in generators:
        return None

    try:
        if framework == "eu_ai_act":
            from app.services.compliance.eu_ai_act import generate_eu_ai_act_report

            report = await generate_eu_ai_act_report(db, tenant_id, start, end)
        elif framework == "nist_ai_rmf":
            from app.services.compliance.nist_ai_rmf import generate_nist_ai_rmf_report

            report = await generate_nist_ai_rmf_report(db, tenant_id, start, end)
        elif framework == "iso27001":
            from app.services.compliance.iso27001 import generate_iso27001_report

            report = await generate_iso27001_report(db, tenant_id, start, end)
        elif framework == "fedramp":
            from app.services.compliance.fedramp import generate_fedramp_report

            report = await generate_fedramp_report(db, tenant_id, start, end)
        else:
            return None
        return report.to_dict()
    except Exception as e:
        logger.warning("compliance_report_collection_failed", framework=framework, error=str(e))
        return {"framework": framework, "error": str(e), "note": "Report generation failed"}

async def _collect_agent_inventory(db, tid: uuid.UUID) -> list[dict]:
    """Fetch agent inventory for the tenant."""
    try:
        rows = await db.fetch(
            """
            SELECT id, name, agent_type, status, trust_score,
                   protocol, first_seen, last_seen
            FROM agents
            WHERE tenant_id = $1
            ORDER BY last_seen DESC
            LIMIT $2
            """,
            tid,
            _MAX_AGENTS,
        )
        return [
            {
                "id": str(r["id"]),
                "name": r["name"],
                "agent_type": r.get("agent_type"),
                "status": r["status"],
                "trust_score": float(r["trust_score"]) if r.get("trust_score") else None,
                "protocol": r.get("protocol"),
                "first_seen": str(r["first_seen"]) if r.get("first_seen") else None,
                "last_seen": str(r["last_seen"]) if r.get("last_seen") else None,
            }
            for r in rows
        ]
    except Exception as e:
        logger.warning("agent_inventory_collection_failed", error=str(e))
        return [{"note": "Agent inventory unavailable", "error": str(e)}]

async def _collect_config_snapshot(db, tid: uuid.UUID) -> dict:
    """Collect an anonymized configuration snapshot."""
    config: dict[str, Any] = {
        "collected_at": datetime.now(UTC).isoformat(),
        "tenant_id": str(tid),
    }
    try:
        # Fetch compliance scan config
        row = await db.fetchrow(
            "SELECT frameworks, cron, enabled FROM compliance_scan_config WHERE tenant_id = $1",
            tid,
        )
        if row:
            config["compliance_scan"] = {
                "frameworks": row["frameworks"],
                "cron": row["cron"],
                "enabled": row["enabled"],
            }
    except Exception:
        config["compliance_scan"] = {"note": "Not configured or table missing"}

    try:
        # Fetch notification channel count (no secrets)
        row = await db.fetchrow(
            "SELECT COUNT(*) as cnt FROM pdr_channels WHERE tenant_id = $1 AND enabled = true",
            tid,
        )
        config["notification_channels"] = row["cnt"] if row else 0
    except Exception:
        config["notification_channels"] = 0

    try:
        # Policy count
        row = await db.fetchrow(
            "SELECT COUNT(*) as cnt FROM policies WHERE tenant_id = $1 AND enabled = true",
            tid,
        )
        config["active_policies"] = row["cnt"] if row else 0
    except Exception:
        config["active_policies"] = 0

    return config

async def _collect_classification_summary(
    db,
    tid: uuid.UUID,
    start: str,
    end: str,
) -> dict:
    """Collect data classification summary for the period."""
    try:
        rows = await db.fetch(
            """
            SELECT category, COUNT(*) as cnt
            FROM data_classifications
            WHERE tenant_id = $1 AND classified_at >= $2 AND classified_at <= $3
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT $4
            """,
            tid,
            start,
            end,
            _MAX_CLASSIFICATION_CATEGORIES,
        )
        return {
            "period": {"start": start, "end": end},
            "categories": [{"category": r["category"], "count": r["cnt"]} for r in rows],
            "total_classified": sum(r["cnt"] for r in rows),
        }
    except Exception as e:
        logger.warning("classification_summary_failed", error=str(e))
        return {"note": "Classification data unavailable", "error": str(e)}
