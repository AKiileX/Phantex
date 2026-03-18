# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Configuration Snapshot Engine

Captures point-in-time agent configuration state:
  - 9 tracked elements (Section 31.1): model, prompt hash, tools, permissions,
    env vars, dependencies, RAG sources, temperature, framework version.
  - Snapshots triggered on: discovery, change, manual, scheduled.
  - Full history with monotonic versioning per agent.
  - Git-style diff between any two snapshots.

Security:
  - All queries tenant-scoped (RLS enforced via set_tenant)
  - Prompt contents never stored — only SHA-256 hashes
  - Env var values never stored — only key name → SHA-256 hash
  - All parameters positional ($1, $2) — no string interpolation
"""

from __future__ import annotations

import hashlib
import json as _json
import uuid
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.service.drift.snapshot")

# ── Hash helpers (defence-in-depth: never store raw secrets) ──────────────────

def hash_prompt(prompt_text: str) -> str:
    """SHA-256 hash of system prompt — raw text is never persisted."""
    return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

def hash_env_vars(env_vars: dict[str, str]) -> dict[str, str]:
    """Convert {KEY: value} to {KEY: sha256(value)} — values never stored."""
    return {k: hashlib.sha256(str(v).encode("utf-8")).hexdigest() for k, v in env_vars.items()}

# ── Snapshot CRUD ─────────────────────────────────────────────────────────────

async def create_snapshot(
    db: Any,
    tenant_id: Any,
    agent_id: str,
    *,
    model_provider: str | None = None,
    model_name: str | None = None,
    model_version: str | None = None,
    prompt_hash: str | None = None,
    tool_list: list[dict] | None = None,
    permissions: dict | None = None,
    env_var_hashes: dict | None = None,
    dependencies: list[dict] | None = None,
    rag_sources: list[dict] | None = None,
    temperature: float | None = None,
    framework_name: str | None = None,
    framework_version: str | None = None,
    snapshot_trigger: str = "discovery",
    captured_by: str | None = None,
) -> dict:
    """
    Capture a new configuration snapshot for an agent.

    Version is auto-incremented (monotonic per agent within tenant).
    Returns the full snapshot dict including the new version number.
    """
    await db.set_tenant(str(tenant_id))

    # Determine next version
    ver_row = await db.fetchrow(
        """
        SELECT COALESCE(MAX(version), 0) + 1 AS next_ver
        FROM agent_config_snapshots
        WHERE tenant_id = $1 AND agent_id = $2
        """,
        tenant_id,
        agent_id,
    )
    next_version = ver_row["next_ver"]

    snap_id = str(uuid.uuid4())

    row = await db.fetchrow(
        """
        INSERT INTO agent_config_snapshots (
            id, tenant_id, agent_id, version,
            model_provider, model_name, model_version, prompt_hash,
            tool_list, permissions, env_var_hashes, dependencies,
            rag_sources, temperature, framework_name, framework_version,
            snapshot_trigger, captured_by
        ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7, $8,
            $9, $10, $11, $12,
            $13, $14, $15, $16,
            $17, $18
        )
        RETURNING *
        """,
        snap_id,
        tenant_id,
        agent_id,
        next_version,
        model_provider,
        model_name,
        model_version,
        prompt_hash,
        _json.dumps(tool_list or []),
        _json.dumps(permissions or {}),
        _json.dumps(env_var_hashes or {}),
        _json.dumps(dependencies or []),
        _json.dumps(rag_sources or []),
        temperature,
        framework_name,
        framework_version,
        snapshot_trigger,
        captured_by,
    )

    logger.info(
        "snapshot_created",
        snapshot_id=snap_id,
        agent_id=agent_id,
        version=next_version,
        trigger=snapshot_trigger,
        tenant_id=str(tenant_id),
    )
    return _snapshot_to_dict(row)

async def list_snapshots(
    db: Any,
    tenant_id: Any,
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """List snapshots with optional agent filter, pagination."""
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
        f"SELECT count(*) AS cnt FROM agent_config_snapshots WHERE {where_sql}",
        *params,
    )
    total = count_row["cnt"] if count_row else 0

    rows = await db.fetch(
        f"""
        SELECT * FROM agent_config_snapshots
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )

    return [_snapshot_to_dict(r) for r in rows], total

async def get_snapshot(db: Any, tenant_id: Any, snapshot_id: str) -> dict | None:
    """Retrieve a single snapshot by ID."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM agent_config_snapshots WHERE id = $1 AND tenant_id = $2",
        snapshot_id,
        tenant_id,
    )
    return _snapshot_to_dict(row) if row else None

async def get_latest_snapshot(db: Any, tenant_id: Any, agent_id: str) -> dict | None:
    """Get the most recent snapshot for a specific agent."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        """
        SELECT * FROM agent_config_snapshots
        WHERE tenant_id = $1 AND agent_id = $2
        ORDER BY version DESC LIMIT 1
        """,
        tenant_id,
        agent_id,
    )
    return _snapshot_to_dict(row) if row else None

async def diff_snapshots(db: Any, tenant_id: Any, snapshot_id_a: str, snapshot_id_b: str) -> dict:
    """
    Compute a git-style diff between two snapshots.

    Returns a dict of {field_name: {old: ..., new: ...}} for every changed field.
    Only config-relevant fields are compared (metadata excluded).
    """
    await db.set_tenant(str(tenant_id))

    row_a = await db.fetchrow(
        "SELECT * FROM agent_config_snapshots WHERE id = $1 AND tenant_id = $2",
        snapshot_id_a,
        tenant_id,
    )
    row_b = await db.fetchrow(
        "SELECT * FROM agent_config_snapshots WHERE id = $1 AND tenant_id = $2",
        snapshot_id_b,
        tenant_id,
    )

    if not row_a or not row_b:
        return {"error": "One or both snapshots not found", "changes": []}

    diff_fields = [
        "model_provider",
        "model_name",
        "model_version",
        "prompt_hash",
        "tool_list",
        "permissions",
        "env_var_hashes",
        "dependencies",
        "rag_sources",
        "temperature",
        "framework_name",
        "framework_version",
    ]

    changes: list[dict] = []
    for field in diff_fields:
        val_a = _normalise(row_a.get(field))
        val_b = _normalise(row_b.get(field))
        if val_a != val_b:
            changes.append(
                {
                    "field": field,
                    "old": val_a,
                    "new": val_b,
                }
            )

    return {
        "snapshot_a": {"id": str(row_a["id"]), "version": row_a["version"], "agent_id": row_a["agent_id"]},
        "snapshot_b": {"id": str(row_b["id"]), "version": row_b["version"], "agent_id": row_b["agent_id"]},
        "changes": changes,
        "total_changes": len(changes),
    }

async def get_agent_ids(db: Any, tenant_id: Any) -> list[str]:
    """List distinct agent IDs that have snapshots."""
    await db.set_tenant(str(tenant_id))
    rows = await db.fetch(
        """
        SELECT DISTINCT agent_id
        FROM agent_config_snapshots
        WHERE tenant_id = $1
        ORDER BY agent_id
        """,
        tenant_id,
    )
    return [r["agent_id"] for r in rows]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalise(val: Any) -> Any:
    """Normalise a DB value for comparison (parse JSON strings)."""
    if val is None:
        return None
    if isinstance(val, str):
        try:
            return _json.loads(val)
        except (ValueError, TypeError):
            return val
    if isinstance(val, dict | list):
        return val
    return val

def _parse_json(val: Any) -> Any:
    """Parse JSON string or return as-is if already a dict/list."""
    if val is None:
        return {}
    if isinstance(val, dict | list):
        return val
    try:
        return _json.loads(val)
    except (ValueError, TypeError):
        return {}

def _snapshot_to_dict(row: Any) -> dict:
    """Convert asyncpg Record to serialisable dict."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "agent_id": row["agent_id"],
        "version": row["version"],
        "model_provider": row.get("model_provider"),
        "model_name": row.get("model_name"),
        "model_version": row.get("model_version"),
        "prompt_hash": row.get("prompt_hash"),
        "tool_list": _parse_json(row.get("tool_list")),
        "permissions": _parse_json(row.get("permissions")),
        "env_var_hashes": _parse_json(row.get("env_var_hashes")),
        "dependencies": _parse_json(row.get("dependencies")),
        "rag_sources": _parse_json(row.get("rag_sources")),
        "temperature": row.get("temperature"),
        "framework_name": row.get("framework_name"),
        "framework_version": row.get("framework_version"),
        "snapshot_trigger": row.get("snapshot_trigger"),
        "captured_by": row.get("captured_by"),
        "created_at": str(row["created_at"]),
    }
