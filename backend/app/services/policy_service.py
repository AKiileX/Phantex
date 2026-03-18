# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Policy Service.

CRUD operations, YAML parsing, validation, versioning, and policy application.

Security:
- YAML parsing: yaml.safe_load() ONLY — never yaml.load() with FullLoader
- Rejects YAML with !!python/*, !!map, !!seq custom tags
- Size limit: 64KB per policy YAML
- Depth limit: 10 levels of nesting
- All operations are tenant-scoped
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from app.schemas.policy import (
    PolicyCreateRequest,
    PolicyUpdateRequest,
    PolicyValidationResult,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.policy_service")

# ── YAML Size / Depth Limits ─────────────────────────────────────────────────

MAX_YAML_SIZE = 65_536  # 64KB
MAX_YAML_DEPTH = 10

# Dangerous YAML tags — reject if any are found
_DANGEROUS_YAML_TAGS = re.compile(
    r"!!(python|ruby|perl|java|php|exec|import|module|object|apply|getattr|global|set|map|seq)"
    r"(/\S+)?",
    re.IGNORECASE,
)

# ── YAML Parsing ─────────────────────────────────────────────────────────────

def parse_yaml_safe(content: str) -> tuple[dict | None, list[str]]:
    """
    Parse YAML content safely.

    Returns (parsed_dict, errors).
    Uses yaml.safe_load() ONLY.
    Rejects dangerous tags, enforces size/depth limits.
    """
    errors: list[str] = []

    # Size check
    if len(content) > MAX_YAML_SIZE:
        errors.append(f"YAML too large: {len(content)} bytes (max {MAX_YAML_SIZE})")
        return None, errors

    # Reject dangerous tags before parsing
    if _DANGEROUS_YAML_TAGS.search(content):
        errors.append("YAML contains dangerous tags (!!python/*, etc.) — rejected")
        return None, errors

    try:
        import yaml

        result = yaml.safe_load(content)
    except Exception as e:
        errors.append(f"YAML parse error: {str(e)[:200]}")
        return None, errors

    if not isinstance(result, dict):
        errors.append("YAML root must be a mapping (dict)")
        return None, errors

    # Depth check
    depth = _measure_depth(result)
    if depth > MAX_YAML_DEPTH:
        errors.append(f"YAML nesting too deep: {depth} levels (max {MAX_YAML_DEPTH})")
        return None, errors

    return result, errors

def _measure_depth(obj: Any, current: int = 1) -> int:
    """Measure maximum nesting depth of a Python object."""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_measure_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_measure_depth(v, current + 1) for v in obj)
    return current

# ── Validation ───────────────────────────────────────────────────────────────

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_SCHEDULE_ACTIONS = {"suppress", "alert", "inherit"}

def validate_policy_definition(definition: dict) -> PolicyValidationResult:
    """
    Validate a parsed policy definition.

    Checks:
    - Rules have valid names and severity overrides
    - Parameters are primitive types (no nested objects > 2 levels)
    - Schedule format is valid
    - Scope tags are valid
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Validate rules
    rules = definition.get("rules", [])
    if not isinstance(rules, list):
        errors.append("'rules' must be a list")
    else:
        if len(rules) > 100:
            errors.append(f"Too many rules: {len(rules)} (max 100)")

        seen_names: set[str] = set()
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i}: must be a mapping")
                continue

            name = rule.get("name", "")
            if not name or not isinstance(name, str):
                errors.append(f"Rule {i}: missing or invalid 'name'")
            elif name in seen_names:
                errors.append(f"Rule {i}: duplicate rule name '{name}'")
            else:
                seen_names.add(name)

            sev = rule.get("severity_override")
            if sev is not None and sev not in _VALID_SEVERITIES:
                errors.append(
                    f"Rule '{name}': invalid severity_override '{sev}' (valid: {', '.join(sorted(_VALID_SEVERITIES))})"
                )

            params = rule.get("parameters", {})
            if not isinstance(params, dict):
                errors.append(f"Rule '{name}': parameters must be a mapping")
            elif params:
                for pk, pv in params.items():
                    if not isinstance(pv, str | int | float | bool | type(None)):
                        warnings.append(
                            f"Rule '{name}': parameter '{pk}' has complex type — "
                            "only str/int/float/bool/null recommended"
                        )

    # Validate schedule
    schedule = definition.get("schedule", {})
    if schedule and isinstance(schedule, dict):
        active_hours = schedule.get("active_hours", "")
        if active_hours:
            # Validate HH:MM-HH:MM format
            if not re.match(r"^\d{2}:\d{2}-\d{2}:\d{2}\s+\S+$", active_hours):
                errors.append(f"Schedule: invalid active_hours format '{active_hours}' (expected 'HH:MM-HH:MM TZ')")

        weekend = schedule.get("weekend", "")
        if weekend and weekend not in _VALID_SCHEDULE_ACTIONS:
            errors.append(
                f"Schedule: invalid weekend action '{weekend}' (valid: {', '.join(sorted(_VALID_SCHEDULE_ACTIONS))})"
            )

    # Validate scope
    scope = definition.get("scope", {})
    if scope and isinstance(scope, dict):
        for key in ("agent_tags", "frameworks"):
            tags = scope.get(key, [])
            if not isinstance(tags, list):
                errors.append(f"Scope: '{key}' must be a list")
            elif len(tags) > 50:
                errors.append(f"Scope: too many {key} ({len(tags)}, max 50)")
            else:
                for tag in tags:
                    if not isinstance(tag, str) or len(tag) > 128:
                        errors.append(f"Scope: invalid {key} entry: {str(tag)[:32]}")

    return PolicyValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        parsed=definition if len(errors) == 0 else None,
    )

# ── CRUD Operations ──────────────────────────────────────────────────────────

async def create_policy(
    conn,
    tenant_id: str,
    user_id: str,
    request: PolicyCreateRequest,
) -> dict:
    """Create a new policy and its initial version."""
    definition_dict = request.definition.model_dump()

    # Extract scope from definition
    scope = request.definition.scope
    scope_tags = scope.agent_tags
    scope_frameworks = scope.frameworks

    row = await conn.fetchrow(
        """
        INSERT INTO policies (
            tenant_id, name, description, version, enabled,
            definition, scope_agent_tags, scope_frameworks,
            created_by, updated_by
        ) VALUES ($1, $2, $3, 1, $4, $5::jsonb, $6, $7, $8, $8)
        RETURNING id, tenant_id, name, description, version, enabled,
                  definition, scope_agent_tags, scope_frameworks,
                  created_by, updated_by, created_at, updated_at
        """,
        uuid.UUID(tenant_id),
        request.name,
        request.description,
        request.enabled,
        _json_dumps(definition_dict),
        scope_tags,
        scope_frameworks,
        uuid.UUID(user_id),
    )

    # Create version 1 snapshot
    await conn.execute(
        """
        INSERT INTO policy_versions (
            policy_id, tenant_id, version, definition,
            change_summary, created_by
        ) VALUES ($1, $2, 1, $3::jsonb, $4, $5)
        """,
        row["id"],
        uuid.UUID(tenant_id),
        _json_dumps(definition_dict),
        "Initial creation",
        uuid.UUID(user_id),
    )

    return dict(row)

async def get_policy(conn, tenant_id: str, policy_id: str) -> dict | None:
    """Get a single policy by ID (non-deleted only)."""
    row = await conn.fetchrow(
        """
        SELECT id, tenant_id, name, description, version, enabled,
               definition, scope_agent_tags, scope_frameworks,
               created_by, updated_by, created_at, updated_at
        FROM policies
        WHERE id = $1 AND tenant_id = $2 AND NOT deleted
        """,
        uuid.UUID(policy_id),
        uuid.UUID(tenant_id),
    )
    return dict(row) if row else None

async def list_policies(
    conn,
    tenant_id: str,
    page: int = 1,
    page_size: int = 20,
    enabled_only: bool = False,
) -> tuple[list[dict], int]:
    """List policies for a tenant with pagination."""
    page_size = max(1, min(page_size, 100))
    page = max(1, page)
    offset = (page - 1) * page_size

    where_clause = "tenant_id = $1 AND NOT deleted"
    params: list = [uuid.UUID(tenant_id)]

    if enabled_only:
        where_clause += " AND enabled = true"

    total = await conn.fetchval(
        f"SELECT COUNT(*) FROM policies WHERE {where_clause}",
        *params,
    )

    rows = await conn.fetch(
        f"""
        SELECT id, tenant_id, name, description, version, enabled,
               definition, scope_agent_tags, scope_frameworks,
               created_by, updated_by, created_at, updated_at
        FROM policies
        WHERE {where_clause}
        ORDER BY created_at DESC, id DESC
        LIMIT $2 OFFSET $3
        """,
        *params,
        page_size,
        offset,
    )

    return [dict(r) for r in rows], total

async def update_policy(
    conn,
    tenant_id: str,
    policy_id: str,
    user_id: str,
    request: PolicyUpdateRequest,
) -> dict | None:
    """Update a policy and create a new version snapshot."""
    # Fetch current policy
    current = await get_policy(conn, tenant_id, policy_id)
    if current is None:
        return None

    new_version = current["version"] + 1

    # Build update fields
    name = request.name if request.name is not None else current["name"]
    description = request.description if request.description is not None else current["description"]
    enabled = request.enabled if request.enabled is not None else current["enabled"]

    if request.definition is not None:
        definition_dict = request.definition.model_dump()
        scope_tags = request.definition.scope.agent_tags
        scope_frameworks = request.definition.scope.frameworks
    else:
        definition_dict = current["definition"]
        scope_tags = current["scope_agent_tags"]
        scope_frameworks = current["scope_frameworks"]

    row = await conn.fetchrow(
        """
        UPDATE policies SET
            name = $3, description = $4, version = $5,
            enabled = $6, definition = $7::jsonb,
            scope_agent_tags = $8, scope_frameworks = $9,
            updated_by = $10
        WHERE id = $1 AND tenant_id = $2 AND NOT deleted
        RETURNING id, tenant_id, name, description, version, enabled,
                  definition, scope_agent_tags, scope_frameworks,
                  created_by, updated_by, created_at, updated_at
        """,
        uuid.UUID(policy_id),
        uuid.UUID(tenant_id),
        name,
        description,
        new_version,
        enabled,
        _json_dumps(definition_dict),
        scope_tags,
        scope_frameworks,
        uuid.UUID(user_id),
    )

    if row is None:
        return None

    # Create version snapshot
    await conn.execute(
        """
        INSERT INTO policy_versions (
            policy_id, tenant_id, version, definition,
            change_summary, created_by
        ) VALUES ($1, $2, $3, $4::jsonb, $5, $6)
        """,
        uuid.UUID(policy_id),
        uuid.UUID(tenant_id),
        new_version,
        _json_dumps(definition_dict),
        request.change_summary or f"Updated to version {new_version}",
        uuid.UUID(user_id),
    )

    return dict(row)

async def delete_policy(conn, tenant_id: str, policy_id: str, user_id: str) -> bool:
    """Soft-delete a policy (admin-recoverable)."""
    result = await conn.execute(
        """
        UPDATE policies SET
            deleted = true,
            deleted_at = now(),
            deleted_by = $3,
            enabled = false
        WHERE id = $1 AND tenant_id = $2 AND NOT deleted
        """,
        uuid.UUID(policy_id),
        uuid.UUID(tenant_id),
        uuid.UUID(user_id),
    )
    return result != "UPDATE 0"  # Postgres returns "UPDATE N"

async def get_policy_versions(conn, tenant_id: str, policy_id: str) -> list[dict]:
    """Get version history for a policy."""
    rows = await conn.fetch(
        """
        SELECT id, policy_id, version, definition,
               change_summary, created_by, created_at
        FROM policy_versions
        WHERE policy_id = $1 AND tenant_id = $2
        ORDER BY version DESC
        """,
        uuid.UUID(policy_id),
        uuid.UUID(tenant_id),
    )
    return [dict(r) for r in rows]

async def get_policies_for_agent(
    conn,
    tenant_id: str,
    agent_tags: list[str],
    framework: str = "",
) -> list[dict]:
    """
    Get all enabled policies that match an agent's tags/framework.

    A policy matches if:
    - Its scope_agent_tags is empty (applies to all), OR
    - Any of the agent's tags are in the policy's scope_agent_tags
    AND:
    - Its scope_frameworks is empty (applies to all), OR
    - The agent's framework is in the policy's scope_frameworks
    """
    rows = await conn.fetch(
        """
        SELECT id, tenant_id, name, description, version, enabled,
               definition, scope_agent_tags, scope_frameworks,
               created_by, updated_by, created_at, updated_at
        FROM policies
        WHERE tenant_id = $1
          AND enabled = true
          AND NOT deleted
          AND (scope_agent_tags = '{}' OR scope_agent_tags && $2)
          AND (scope_frameworks = '{}' OR $3 = ANY(scope_frameworks))
        ORDER BY created_at ASC
        """,
        uuid.UUID(tenant_id),
        agent_tags,
        framework,
    )
    return [dict(r) for r in rows]

# ── Helpers ──────────────────────────────────────────────────────────────────

def _json_dumps(obj: Any) -> str:
    """JSON serialize for PostgreSQL JSONB."""
    import json

    return json.dumps(obj, default=str)
