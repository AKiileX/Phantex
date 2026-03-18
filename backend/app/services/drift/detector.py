# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Configuration Drift Detector

Compares a new snapshot against the agent's baseline (latest approved snapshot)
to detect configuration drift events.

Drift types (Section 31.2):
  - model_swap:             LLM model changed (provider, name, or version)
  - prompt_change:          System prompt hash changed
  - tool_added / tool_removed: MCP tool list modified
  - permission_escalation:  Permissions widened
  - dependency_change:      Package versions changed or new deps added
  - rag_change:             RAG sources changed
  - config_change:          Temperature, framework version, env vars changed

Detection modes:
  - strict:   Every config change produces a drift event (always alert)
  - standard: Alert on unexpected changes outside maintenance windows
  - learning: Record diffs silently — no drift events created

Security:
  - Tenant-scoped via RLS (set_tenant)
  - Old/new values stored as hashes or truncated summaries (never raw secrets)
  - All SQL parameterised
"""

from __future__ import annotations

import json as _json
import uuid
from datetime import UTC, datetime
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.service.drift.detector")

# ── Severity classification ───────────────────────────────────────────────────

# Map drift_type → default severity
_SEVERITY_MAP: dict[str, str] = {
    "model_swap": "critical",
    "prompt_change": "high",
    "tool_added": "high",
    "tool_removed": "medium",
    "permission_escalation": "critical",
    "dependency_change": "medium",
    "rag_change": "high",
    "config_change": "low",
}

# ── Core drift detection ─────────────────────────────────────────────────────

async def detect_drift(
    db: Any,
    tenant_id: Any,
    agent_id: str,
    baseline_snapshot: dict,
    current_snapshot: dict,
) -> list[dict]:
    """
    Compare current snapshot against baseline and return a list of drift dicts.

    Each dict has: drift_type, severity, field_name, old_value, new_value.
    Does NOT write to DB — caller decides whether to persist based on policy mode.
    """
    drifts: list[dict] = []

    # Model swap check
    for field in ("model_provider", "model_name", "model_version"):
        old_val = baseline_snapshot.get(field)
        new_val = current_snapshot.get(field)
        if old_val != new_val and new_val is not None:
            drift_type = "model_swap"
            drifts.append(_make_drift(drift_type, field, old_val, new_val))

    # Prompt hash change
    old_prompt = baseline_snapshot.get("prompt_hash")
    new_prompt = current_snapshot.get("prompt_hash")
    if old_prompt and new_prompt and old_prompt != new_prompt:
        drifts.append(_make_drift("prompt_change", "prompt_hash", old_prompt, new_prompt))

    # Tool list changes
    old_tools = _tool_names(baseline_snapshot.get("tool_list", []))
    new_tools = _tool_names(current_snapshot.get("tool_list", []))
    added = new_tools - old_tools
    removed = old_tools - new_tools
    for t in sorted(added):
        drifts.append(_make_drift("tool_added", "tool_list", None, t))
    for t in sorted(removed):
        drifts.append(_make_drift("tool_removed", "tool_list", t, None))

    # Permission escalation
    old_perms = baseline_snapshot.get("permissions", {})
    new_perms = current_snapshot.get("permissions", {})
    if isinstance(old_perms, str):
        old_perms = _safe_json(old_perms)
    if isinstance(new_perms, str):
        new_perms = _safe_json(new_perms)
    escalated = _detect_permission_escalation(old_perms, new_perms)
    if escalated:
        drifts.append(
            _make_drift(
                "permission_escalation",
                "permissions",
                _truncate(_json.dumps(old_perms)),
                _truncate(_json.dumps(new_perms)),
            )
        )

    # Dependency changes
    old_deps = _dep_set(baseline_snapshot.get("dependencies", []))
    new_deps = _dep_set(current_snapshot.get("dependencies", []))
    if old_deps != new_deps:
        dep_added = new_deps - old_deps
        dep_removed = old_deps - new_deps
        for d in sorted(dep_added):
            drifts.append(_make_drift("dependency_change", "dependencies", None, d))
        for d in sorted(dep_removed):
            drifts.append(_make_drift("dependency_change", "dependencies", d, None))

    # RAG source changes
    old_rag = _rag_set(baseline_snapshot.get("rag_sources", []))
    new_rag = _rag_set(current_snapshot.get("rag_sources", []))
    if old_rag != new_rag:
        drifts.append(
            _make_drift(
                "rag_change",
                "rag_sources",
                _truncate(str(sorted(old_rag))),
                _truncate(str(sorted(new_rag))),
            )
        )

    # Env var hash changes
    old_env = baseline_snapshot.get("env_var_hashes", {})
    new_env = current_snapshot.get("env_var_hashes", {})
    if isinstance(old_env, str):
        old_env = _safe_json(old_env)
    if isinstance(new_env, str):
        new_env = _safe_json(new_env)
    if old_env != new_env:
        drifts.append(_make_drift("config_change", "env_var_hashes", "[hashes changed]", "[hashes changed]"))

    # Temperature change
    old_temp = baseline_snapshot.get("temperature")
    new_temp = current_snapshot.get("temperature")
    if old_temp is not None and new_temp is not None and old_temp != new_temp:
        drifts.append(_make_drift("config_change", "temperature", str(old_temp), str(new_temp)))

    # Framework version change
    old_fw = baseline_snapshot.get("framework_version")
    new_fw = current_snapshot.get("framework_version")
    if old_fw and new_fw and old_fw != new_fw:
        drifts.append(_make_drift("config_change", "framework_version", old_fw, new_fw))

    return drifts

async def process_snapshot_drift(
    db: Any,
    tenant_id: Any,
    agent_id: str,
    current_snapshot_id: str,
) -> list[dict]:
    """
    Full drift detection pipeline:
      1. Load the drift policy for the tenant.
      2. Load the baseline (second-latest snapshot) and current snapshot.
      3. Detect drifts.
      4. If policy mode is not 'learning', persist drift events.

    Returns a list of created drift event dicts (empty if learning mode or no drift).
    """
    await db.set_tenant(str(tenant_id))

    # Load policy
    policy = await _get_policy(db, tenant_id)
    mode = policy.get("mode", "learning") if policy else "learning"

    # Get current snapshot
    current_row = await db.fetchrow(
        "SELECT * FROM agent_config_snapshots WHERE id = $1 AND tenant_id = $2",
        current_snapshot_id,
        tenant_id,
    )
    if not current_row:
        return []

    current_snap = _row_to_snap_dict(current_row)

    # Get baseline (the snapshot just before current)
    baseline_row = await db.fetchrow(
        """
        SELECT * FROM agent_config_snapshots
        WHERE tenant_id = $1 AND agent_id = $2 AND version < $3
        ORDER BY version DESC LIMIT 1
        """,
        tenant_id,
        agent_id,
        current_row["version"],
    )
    if not baseline_row:
        # First snapshot — no baseline to compare against
        logger.info("no_baseline_for_drift", agent_id=agent_id, tenant_id=str(tenant_id))
        return []

    baseline_snap = _row_to_snap_dict(baseline_row)

    # Detect drifts
    drifts = await detect_drift(db, tenant_id, agent_id, baseline_snap, current_snap)

    if not drifts:
        return []

    # Filter by policy alert settings
    drifts = _apply_policy_filter(drifts, policy)

    if mode == "learning":
        logger.info(
            "drift_learning_mode",
            agent_id=agent_id,
            drift_count=len(drifts),
            tenant_id=str(tenant_id),
        )
        return []  # Silently ignore in learning mode

    # Check maintenance window
    if _in_maintenance_window(policy):
        logger.info(
            "drift_in_maintenance",
            agent_id=agent_id,
            drift_count=len(drifts),
            tenant_id=str(tenant_id),
        )
        if mode == "standard":
            return []  # Standard mode ignores changes during maintenance

    # Persist drift events
    created_events: list[dict] = []
    for drift in drifts:
        event_id = str(uuid.uuid4())
        row = await db.fetchrow(
            """
            INSERT INTO agent_drift_events (
                id, tenant_id, agent_id, drift_type, severity,
                field_name, old_value, new_value,
                baseline_snapshot_id, current_snapshot_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            """,
            event_id,
            tenant_id,
            agent_id,
            drift["drift_type"],
            drift["severity"],
            drift["field_name"],
            drift.get("old_value"),
            drift.get("new_value"),
            str(baseline_row["id"]),
            current_snapshot_id,
        )
        created_events.append(_drift_event_to_dict(row))

    if created_events:
        logger.warning(
            "drift_detected",
            agent_id=agent_id,
            drift_count=len(created_events),
            types=[e["drift_type"] for e in created_events],
            mode=mode,
            tenant_id=str(tenant_id),
        )

    return created_events

# ── Drift Events CRUD ─────────────────────────────────────────────────────────

async def list_drift_events(
    db: Any,
    tenant_id: Any,
    agent_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """List drift events with optional filters and pagination."""
    await db.set_tenant(str(tenant_id))

    where = ["tenant_id = $1"]
    params: list[Any] = [tenant_id]
    idx = 2

    if agent_id:
        where.append(f"agent_id = ${idx}")
        params.append(agent_id)
        idx += 1
    if status:
        where.append(f"status = ${idx}")
        params.append(status)
        idx += 1
    if severity:
        where.append(f"severity = ${idx}")
        params.append(severity)
        idx += 1

    where_sql = " AND ".join(where)

    count_row = await db.fetchrow(
        f"SELECT count(*) AS cnt FROM agent_drift_events WHERE {where_sql}",
        *params,
    )
    total = count_row["cnt"] if count_row else 0

    rows = await db.fetch(
        f"""
        SELECT * FROM agent_drift_events
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )

    return [_drift_event_to_dict(r) for r in rows], total

async def get_drift_event(db: Any, tenant_id: Any, event_id: str) -> dict | None:
    """Retrieve a single drift event by ID."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        "SELECT * FROM agent_drift_events WHERE id = $1 AND tenant_id = $2",
        event_id,
        tenant_id,
    )
    return _drift_event_to_dict(row) if row else None

async def get_drift_stats(db: Any, tenant_id: Any) -> dict:
    """Aggregated drift statistics for the dashboard."""
    await db.set_tenant(str(tenant_id))

    total = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_drift_events WHERE tenant_id = $1",
        tenant_id,
    )
    open_count = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_drift_events WHERE tenant_id = $1 AND status = 'open'",
        tenant_id,
    )
    critical = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_drift_events WHERE tenant_id = $1 AND severity = 'critical'",
        tenant_id,
    )
    last_24h = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_drift_events WHERE tenant_id = $1 AND created_at > now() - interval '24 hours'",
        tenant_id,
    )
    snapshot_count = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_config_snapshots WHERE tenant_id = $1",
        tenant_id,
    )
    agent_count = await db.fetchrow(
        "SELECT count(DISTINCT agent_id) AS cnt FROM agent_config_snapshots WHERE tenant_id = $1",
        tenant_id,
    )
    abom_count = await db.fetchrow(
        "SELECT count(*) AS cnt FROM agent_aboms WHERE tenant_id = $1",
        tenant_id,
    )

    # Get policy
    policy = await _get_policy(db, tenant_id)

    return {
        "total_drift_events": total["cnt"] if total else 0,
        "open_drift_events": open_count["cnt"] if open_count else 0,
        "critical_drift_events": critical["cnt"] if critical else 0,
        "drift_events_last_24h": last_24h["cnt"] if last_24h else 0,
        "total_snapshots": snapshot_count["cnt"] if snapshot_count else 0,
        "monitored_agents": agent_count["cnt"] if agent_count else 0,
        "total_aboms": abom_count["cnt"] if abom_count else 0,
        "policy_mode": policy["mode"] if policy else "learning",
    }

# ── Policy Management ─────────────────────────────────────────────────────────

async def get_policy(db: Any, tenant_id: Any) -> dict | None:
    """Get the drift policy for a tenant (public wrapper)."""
    await db.set_tenant(str(tenant_id))
    return await _get_policy(db, tenant_id)

async def upsert_policy(
    db: Any,
    tenant_id: Any,
    mode: str,
    **kwargs: Any,
) -> dict:
    """Create or update the tenant's drift policy."""
    await db.set_tenant(str(tenant_id))

    # Validate mode
    if mode not in ("strict", "standard", "learning"):
        raise ValueError(f"Invalid mode: {mode}. Must be strict, standard, or learning")

    existing = await _get_policy(db, tenant_id)

    if existing:
        row = await db.fetchrow(
            """
            UPDATE drift_policy SET
                mode = $2,
                alert_on_model_swap = $3,
                alert_on_prompt_change = $4,
                alert_on_tool_change = $5,
                alert_on_permission_escalation = $6,
                alert_on_dependency_change = $7,
                alert_on_rag_change = $8,
                auto_revert_enabled = $9,
                maintenance_windows = $10,
                updated_at = now()
            WHERE tenant_id = $1
            RETURNING *
            """,
            tenant_id,
            mode,
            kwargs.get("alert_on_model_swap", True),
            kwargs.get("alert_on_prompt_change", True),
            kwargs.get("alert_on_tool_change", True),
            kwargs.get("alert_on_permission_escalation", True),
            kwargs.get("alert_on_dependency_change", False),
            kwargs.get("alert_on_rag_change", True),
            kwargs.get("auto_revert_enabled", False),
            _json.dumps(kwargs.get("maintenance_windows", [])),
        )
    else:
        row = await db.fetchrow(
            """
            INSERT INTO drift_policy (
                id, tenant_id, mode,
                alert_on_model_swap, alert_on_prompt_change, alert_on_tool_change,
                alert_on_permission_escalation, alert_on_dependency_change,
                alert_on_rag_change, auto_revert_enabled, maintenance_windows
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            """,
            str(uuid.uuid4()),
            tenant_id,
            mode,
            kwargs.get("alert_on_model_swap", True),
            kwargs.get("alert_on_prompt_change", True),
            kwargs.get("alert_on_tool_change", True),
            kwargs.get("alert_on_permission_escalation", True),
            kwargs.get("alert_on_dependency_change", False),
            kwargs.get("alert_on_rag_change", True),
            kwargs.get("auto_revert_enabled", False),
            _json.dumps(kwargs.get("maintenance_windows", [])),
        )

    logger.info("drift_policy_upserted", mode=mode, tenant_id=str(tenant_id))
    return _policy_to_dict(row)

# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_policy(db: Any, tenant_id: Any) -> dict | None:
    """Load drift policy for tenant."""
    row = await db.fetchrow(
        "SELECT * FROM drift_policy WHERE tenant_id = $1",
        tenant_id,
    )
    return _policy_to_dict(row) if row else None

def _make_drift(drift_type: str, field_name: str, old_value: Any, new_value: Any) -> dict:
    """Build a drift detection result dict."""
    return {
        "drift_type": drift_type,
        "severity": _SEVERITY_MAP.get(drift_type, "medium"),
        "field_name": field_name,
        "old_value": str(old_value) if old_value is not None else None,
        "new_value": str(new_value) if new_value is not None else None,
    }

def _tool_names(tool_list: Any) -> set[str]:
    """Extract a set of tool names from the tool_list JSONB."""
    if isinstance(tool_list, str):
        tool_list = _safe_json(tool_list)
    if not isinstance(tool_list, list):
        return set()
    names = set()
    for t in tool_list:
        if isinstance(t, dict):
            names.add(t.get("name", str(t)))
        else:
            names.add(str(t))
    return names

def _dep_set(deps: Any) -> set[str]:
    """Extract dependency fingerprints as a set of 'name@version' strings."""
    if isinstance(deps, str):
        deps = _safe_json(deps)
    if not isinstance(deps, list):
        return set()
    result = set()
    for d in deps:
        if isinstance(d, dict):
            result.add(f"{d.get('name', '?')}@{d.get('version', '?')}")
        else:
            result.add(str(d))
    return result

def _rag_set(rag: Any) -> set[str]:
    """Extract RAG source fingerprints."""
    if isinstance(rag, str):
        rag = _safe_json(rag)
    if not isinstance(rag, list):
        return set()
    result = set()
    for r in rag:
        if isinstance(r, dict):
            result.add(f"{r.get('type', '?')}:{r.get('endpoint', r.get('collection', '?'))}")
        else:
            result.add(str(r))
    return result

def _detect_permission_escalation(old: dict, new: dict) -> bool:
    """Check if permissions widened (any new key or any value went from false to true)."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return old != new
    new_keys = set(new.keys()) - set(old.keys())
    if new_keys:
        return True
    for k in old:
        if k in new:
            old_val = old[k]
            new_val = new[k]
            if old_val is False and new_val is True:
                return True
            if isinstance(old_val, list) and isinstance(new_val, list) and set(new_val) - set(old_val):
                return True
    return False

def _apply_policy_filter(drifts: list[dict], policy: dict | None) -> list[dict]:
    """Filter drifts based on policy alert settings."""
    if not policy:
        return drifts

    type_to_alert = {
        "model_swap": policy.get("alert_on_model_swap", True),
        "prompt_change": policy.get("alert_on_prompt_change", True),
        "tool_added": policy.get("alert_on_tool_change", True),
        "tool_removed": policy.get("alert_on_tool_change", True),
        "permission_escalation": policy.get("alert_on_permission_escalation", True),
        "dependency_change": policy.get("alert_on_dependency_change", False),
        "rag_change": policy.get("alert_on_rag_change", True),
        "config_change": True,  # Always track config changes
    }

    return [d for d in drifts if type_to_alert.get(d["drift_type"], True)]

def _in_maintenance_window(policy: dict | None) -> bool:
    """Check if current time is within a maintenance window."""
    if not policy:
        return False
    windows = policy.get("maintenance_windows", [])
    if isinstance(windows, str):
        windows = _safe_json(windows)
    if not windows:
        return False

    now = datetime.now(UTC)
    current_dow = now.weekday()  # 0=Monday
    current_hour = now.hour

    for w in windows:
        if not isinstance(w, dict):
            continue
        if w.get("day_of_week") == current_dow:
            start = w.get("start_hour", 0)
            end = w.get("end_hour", 0)
            if start <= current_hour < end:
                return True
    return False

def _truncate(val: str, max_len: int = 256) -> str:
    """Truncate a string for safe storage in old_value/new_value."""
    if len(val) <= max_len:
        return val
    return val[: max_len - 3] + "..."

def _safe_json(val: str) -> Any:
    """Safely parse JSON string."""
    try:
        return _json.loads(val)
    except (ValueError, TypeError):
        return {}

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

def _row_to_snap_dict(row: Any) -> dict:
    """Convert DB row to snapshot dict for drift comparison."""
    return {
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
    }

def _drift_event_to_dict(row: Any) -> dict:
    """Convert asyncpg Record for drift event."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "agent_id": row["agent_id"],
        "drift_type": row["drift_type"],
        "severity": row["severity"],
        "field_name": row["field_name"],
        "old_value": row.get("old_value"),
        "new_value": row.get("new_value"),
        "baseline_snapshot_id": str(row["baseline_snapshot_id"]),
        "current_snapshot_id": str(row["current_snapshot_id"]),
        "status": row["status"],
        "resolved_by": str(row["resolved_by"]) if row.get("resolved_by") else None,
        "resolved_at": str(row["resolved_at"]) if row.get("resolved_at") else None,
        "resolution_reason": row.get("resolution_reason"),
        "created_at": str(row["created_at"]),
    }

def _policy_to_dict(row: Any) -> dict:
    """Convert asyncpg Record for drift policy."""
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "mode": row["mode"],
        "alert_on_model_swap": row["alert_on_model_swap"],
        "alert_on_prompt_change": row["alert_on_prompt_change"],
        "alert_on_tool_change": row["alert_on_tool_change"],
        "alert_on_permission_escalation": row["alert_on_permission_escalation"],
        "alert_on_dependency_change": row["alert_on_dependency_change"],
        "alert_on_rag_change": row["alert_on_rag_change"],
        "auto_revert_enabled": row["auto_revert_enabled"],
        "maintenance_windows": _parse_json(row.get("maintenance_windows")),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
