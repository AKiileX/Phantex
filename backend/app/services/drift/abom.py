# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Bill of Materials Generator

Generates a comprehensive ABOM from an agent's configuration snapshot:
  - 11 ABOM components (Section 34.1): LLM model, framework, tools/MCP,
    prompt hashes, RAG sources, dependencies, API keys/permissions,
    data sources, output destinations, owner, compliance tags.
  - Composite risk scoring with 7 weighted factors (Section 34.4).
  - Export formats: JSON, CycloneDX SBOM extension.
  - Versioned per agent with full history.

Security:
  - Tenant-scoped (RLS)
  - No raw secrets in ABOM — only hashes/metadata
  - Risk scores computed server-side (not client-editable)
  - Parameterised SQL
"""

from __future__ import annotations

import json as _json
import uuid
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.service.drift.abom")

# ── Risk factor weights (Section 34.4) ────────────────────────────────────────

RISK_FACTORS = [
    {
        "factor": "tools_count",
        "weight": 10,
        "threshold": 10,
        "description": "Number of tools/MCP servers (>threshold = risk)",
    },
    {"factor": "external_mcp", "weight": 20, "threshold": 0, "description": "Uses external (non-internal) MCP servers"},
    {
        "factor": "sensitive_data",
        "weight": 15,
        "threshold": 0,
        "description": "Handles PII, financial, or classified data",
    },
    {
        "factor": "broad_permissions",
        "weight": 20,
        "threshold": 5,
        "description": "Number of permission categories (>threshold = risk)",
    },
    {
        "factor": "outdated_deps",
        "weight": 10,
        "threshold": 0,
        "description": "Has dependencies with known vulnerabilities",
    },
    {"factor": "unverified_rag", "weight": 15, "threshold": 0, "description": "Uses unverified/external RAG sources"},
    {"factor": "no_hitl", "weight": 10, "threshold": 0, "description": "No human-in-the-loop (HITL) configured"},
]

# ── ABOM Generation ──────────────────────────────────────────────────────────

async def generate_abom(
    db: Any,
    tenant_id: Any,
    agent_id: str,
    snapshot_id: str,
    *,
    compliance_tags: list[str] | None = None,
    owner: str | None = None,
    data_sources: list[dict] | None = None,
    output_destinations: list[dict] | None = None,
    hitl_enabled: bool = False,
) -> dict:
    """
    Generate a new ABOM for an agent from its snapshot.

    Pulls configuration from the snapshot table, computes risk score,
    and persists the ABOM with a monotonic version.
    """
    await db.set_tenant(str(tenant_id))

    # Load snapshot
    snap_row = await db.fetchrow(
        "SELECT * FROM agent_config_snapshots WHERE id = $1 AND tenant_id = $2",
        snapshot_id,
        tenant_id,
    )
    if not snap_row:
        raise ValueError(f"Snapshot {snapshot_id} not found")

    # Build ABOM components (Section 34.1)
    components = _build_components(snap_row, compliance_tags, owner, data_sources, output_destinations, hitl_enabled)

    # Compute risk score
    risk_score, risk_factors = _compute_risk(components)

    # Count vulnerability placeholders (from dependency data)
    vuln_count = _count_vulnerabilities(snap_row)

    # Generate CycloneDX-style export
    cyclonedx = _generate_cyclonedx(agent_id, components, risk_score)

    # Determine version
    ver_row = await db.fetchrow(
        """
        SELECT COALESCE(MAX(version), 0) + 1 AS next_ver
        FROM agent_aboms
        WHERE tenant_id = $1 AND agent_id = $2
        """,
        tenant_id,
        agent_id,
    )
    next_version = ver_row["next_ver"]

    abom_id = str(uuid.uuid4())

    row = await db.fetchrow(
        """
        INSERT INTO agent_aboms (
            id, tenant_id, agent_id, version, snapshot_id,
            components, risk_score, risk_factors, compliance_tags,
            vulnerability_count, cyclonedx_json
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        """,
        abom_id,
        tenant_id,
        agent_id,
        next_version,
        snapshot_id,
        _json.dumps(components),
        risk_score,
        _json.dumps(risk_factors),
        _json.dumps(compliance_tags or []),
        vuln_count,
        _json.dumps(cyclonedx),
    )

    logger.info(
        "abom_generated",
        abom_id=abom_id,
        agent_id=agent_id,
        version=next_version,
        risk_score=risk_score,
        tenant_id=str(tenant_id),
    )
    return _abom_to_dict(row)

async def list_aboms(
    db: Any,
    tenant_id: Any,
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """List ABOMs with optional agent filter and pagination."""
    await db.set_tenant(str(tenant_id))

    where = ["tenant_id = $1"]
    params: list[Any] = [tenant_id]
    idx = 2

    if agent_id:
        where.append(f"agent_id = ${idx}")
        params.append(agent_id)
        idx += 1

    where_sql = " AND ".join(where)

    count_row = await db.fetchrow(
        f"SELECT count(*) AS cnt FROM agent_aboms WHERE {where_sql}",
        *params,
    )
    total = count_row["cnt"] if count_row else 0

    rows = await db.fetch(
        f"""
        SELECT * FROM agent_aboms
        WHERE {where_sql}
        ORDER BY generated_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )

    return [_abom_to_dict(r) for r in rows], total

async def get_abom(db: Any, tenant_id: Any, abom_id: str) -> dict | None:
    """Retrieve a single ABOM by ID."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM agent_aboms WHERE id = $1 AND tenant_id = $2",
        abom_id,
        tenant_id,
    )
    return _abom_to_dict(row) if row else None

async def get_latest_abom(db: Any, tenant_id: Any, agent_id: str) -> dict | None:
    """Get the latest ABOM for an agent."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        """
        SELECT * FROM agent_aboms
        WHERE tenant_id = $1 AND agent_id = $2
        ORDER BY version DESC LIMIT 1
        """,
        tenant_id,
        agent_id,
    )
    return _abom_to_dict(row) if row else None

async def export_abom_cyclonedx(db: Any, tenant_id: Any, abom_id: str) -> dict | None:
    """Export an ABOM in CycloneDX format."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT cyclonedx_json FROM agent_aboms WHERE id = $1 AND tenant_id = $2",
        abom_id,
        tenant_id,
    )
    if not row:
        return None
    val = row["cyclonedx_json"]
    if isinstance(val, str):
        return _json.loads(val)
    return val

# ── Risk Scoring Engine ───────────────────────────────────────────────────────

def _compute_risk(components: dict) -> tuple[float, list[dict]]:
    """
    Compute composite risk score (0-100) from 7 weighted factors.

    Returns (score, [factor_details]).
    """
    factors_result: list[dict] = []
    total_weight = sum(f["weight"] for f in RISK_FACTORS)
    raw_score = 0.0

    for factor in RISK_FACTORS:
        name = factor["factor"]
        weight = factor["weight"]
        threshold = factor["threshold"]
        value = 0.0
        contribution = 0.0

        if name == "tools_count":
            count = len(components.get("tools_mcp", []))
            value = count
            if count > threshold:
                contribution = min((count - threshold) / threshold, 1.0) * weight if threshold > 0 else weight

        elif name == "external_mcp":
            external = [t for t in components.get("tools_mcp", []) if t.get("external", False)]
            value = len(external)
            if value > 0:
                contribution = min(value / 3, 1.0) * weight

        elif name == "sensitive_data":
            tags = components.get("compliance_tags", [])
            sensitive = [
                t for t in tags if any(k in t.lower() for k in ("pii", "financial", "classified", "hipaa", "pci"))
            ]
            value = len(sensitive)
            if value > 0:
                contribution = min(value / 3, 1.0) * weight

        elif name == "broad_permissions":
            perms = components.get("permissions", {})
            count = len(perms) if isinstance(perms, dict) else 0
            value = count
            if count > threshold:
                contribution = min((count - threshold) / threshold, 1.0) * weight if threshold > 0 else weight

        elif name == "outdated_deps":
            deps = components.get("dependencies", [])
            vuln = [d for d in deps if d.get("has_vulnerability", False)]
            value = len(vuln)
            if value > 0:
                contribution = min(value / 5, 1.0) * weight

        elif name == "unverified_rag":
            rag = components.get("rag_sources", [])
            unverified = [r for r in rag if not r.get("verified", False)]
            value = len(unverified)
            if value > 0:
                contribution = min(value / 3, 1.0) * weight

        elif name == "no_hitl":
            if not components.get("hitl_enabled", False):
                value = 1
                contribution = weight

        factors_result.append(
            {
                "factor": name,
                "weight": weight,
                "value": value,
                "contribution": round(contribution, 2),
                "description": factor["description"],
            }
        )
        raw_score += contribution

    # Normalise to 0-100
    score = min(round((raw_score / total_weight) * 100, 1), 100.0) if total_weight > 0 else 0.0

    return score, factors_result

# ── Component Builder ─────────────────────────────────────────────────────────

def _build_components(
    snap_row: Any,
    compliance_tags: list[str] | None,
    owner: str | None,
    data_sources: list[dict] | None,
    output_destinations: list[dict] | None,
    hitl_enabled: bool,
) -> dict:
    """Build the 11 ABOM components from a snapshot row."""
    return {
        # 1. LLM Model
        "llm_model": {
            "provider": snap_row.get("model_provider"),
            "name": snap_row.get("model_name"),
            "version": snap_row.get("model_version"),
        },
        # 2. Framework
        "framework": {
            "name": snap_row.get("framework_name"),
            "version": snap_row.get("framework_version"),
        },
        # 3. Tools / MCP servers
        "tools_mcp": _parse_json(snap_row.get("tool_list")),
        # 4. Prompt hashes
        "prompt_hashes": {
            "system_prompt_sha256": snap_row.get("prompt_hash"),
        },
        # 5. RAG sources
        "rag_sources": _parse_json(snap_row.get("rag_sources")),
        # 6. Dependencies
        "dependencies": _parse_json(snap_row.get("dependencies")),
        # 7. API keys / permissions
        "permissions": _parse_json(snap_row.get("permissions")),
        "env_var_keys": list(_parse_json(snap_row.get("env_var_hashes")).keys()),
        # 8. Data sources
        "data_sources": data_sources or [],
        # 9. Output destinations
        "output_destinations": output_destinations or [],
        # 10. Owner
        "owner": owner,
        # 11. Compliance & config
        "compliance_tags": compliance_tags or [],
        "temperature": snap_row.get("temperature"),
        "hitl_enabled": hitl_enabled,
    }

def _count_vulnerabilities(snap_row: Any) -> int:
    """Count dependencies flagged as vulnerable."""
    deps = _parse_json(snap_row.get("dependencies"))
    if not isinstance(deps, list):
        return 0
    return sum(1 for d in deps if isinstance(d, dict) and d.get("has_vulnerability", False))

# ── CycloneDX Export ──────────────────────────────────────────────────────────

def _generate_cyclonedx(agent_id: str, components: dict, risk_score: float) -> dict:
    """
    Generate a CycloneDX-compatible SBOM with AI agent extensions.

    Based on CycloneDX 1.6 with custom agent metadata.
    """
    bom_components: list[dict] = []

    # LLM model as a component
    llm = components.get("llm_model", {})
    if llm.get("name"):
        bom_components.append(
            {
                "type": "machine-learning-model",
                "name": llm.get("name", "unknown"),
                "version": llm.get("version", "latest"),
                "supplier": {"name": llm.get("provider", "unknown")},
                "properties": [
                    {"name": "phantex:component-type", "value": "llm-model"},
                ],
            }
        )

    # Framework as a component
    fw = components.get("framework", {})
    if fw.get("name"):
        bom_components.append(
            {
                "type": "framework",
                "name": fw.get("name", "unknown"),
                "version": fw.get("version", "unknown"),
                "properties": [
                    {"name": "phantex:component-type", "value": "agent-framework"},
                ],
            }
        )

    # Dependencies
    for dep in components.get("dependencies", []):
        if isinstance(dep, dict):
            bom_components.append(
                {
                    "type": "library",
                    "name": dep.get("name", "unknown"),
                    "version": dep.get("version", "unknown"),
                    "properties": [
                        {"name": "phantex:ecosystem", "value": dep.get("ecosystem", "python")},
                    ],
                }
            )

    # Tools / MCP servers
    for tool in components.get("tools_mcp", []):
        if isinstance(tool, dict):
            bom_components.append(
                {
                    "type": "application",
                    "name": tool.get("name", "unknown"),
                    "properties": [
                        {"name": "phantex:component-type", "value": "mcp-tool"},
                        {"name": "phantex:external", "value": str(tool.get("external", False)).lower()},
                    ],
                }
            )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": agent_id,
                "properties": [
                    {"name": "phantex:type", "value": "ai-agent"},
                    {"name": "phantex:risk-score", "value": str(risk_score)},
                ],
            },
        },
        "components": bom_components,
    }

# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_json(val: Any) -> Any:
    """Parse JSON string or return as-is."""
    if val is None:
        return {}
    if isinstance(val, dict | list):
        return val
    try:
        return _json.loads(val)
    except (ValueError, TypeError):
        return {}

def _abom_to_dict(row: Any) -> dict:
    """Convert asyncpg Record to serialisable dict."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "agent_id": row["agent_id"],
        "version": row["version"],
        "snapshot_id": str(row["snapshot_id"]),
        "components": _parse_json(row.get("components")),
        "risk_score": row["risk_score"],
        "risk_factors": _parse_json(row.get("risk_factors")),
        "compliance_tags": _parse_json(row.get("compliance_tags")),
        "vulnerability_count": row["vulnerability_count"],
        "generated_at": str(row["generated_at"]),
        "updated_at": str(row["updated_at"]),
    }
