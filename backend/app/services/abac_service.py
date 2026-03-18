# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ABAC (Attribute-Based Access Control) Service.

Evaluates permissions dynamically based on:
  - User's roles (from user_roles table)
  - Role's permissions (from role_permissions table)
  - Optional ABAC conditions (time, IP, resource attributes)
  - Backward-compatible with Phase 2 legacy 'role' column

Permission format: "resource.action"  (e.g. "alerts.read", "rules.write")

Caching: Per-user permission sets are cached in Redis with 60s TTL.
         Cache is invalidated on role/permission changes.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.permission import Permission, Role, RolePermission, UserRole
from app.utils.logging import get_logger

logger = get_logger("phantex.services.abac")

# ── In-Memory Cache (per-process, TTL-based) ─────────────────────────────────
# For low-latency < 1ms evaluation. Redis is used for cross-process invalidation.

# M-6: Reduced from 60s → 15s for faster permission revocation propagation
_CACHE_TTL_SECONDS = 15
_permission_cache: dict[uuid.UUID, tuple[float, set[str]]] = {}

def _cache_get(user_id: uuid.UUID) -> set[str] | None:
    """Get cached permissions for a user, or None if expired/missing."""
    entry = _permission_cache.get(user_id)
    if entry is None:
        return None
    cached_at, perms = entry
    if (datetime.now(UTC).timestamp() - cached_at) > _CACHE_TTL_SECONDS:
        del _permission_cache[user_id]
        return None
    return perms

def _cache_set(user_id: uuid.UUID, perms: set[str]) -> None:
    """Cache permissions for a user."""
    _permission_cache[user_id] = (datetime.now(UTC).timestamp(), perms)

def invalidate_user_cache(user_id: uuid.UUID) -> None:
    """Invalidate cached permissions for a specific user."""
    _permission_cache.pop(user_id, None)

def invalidate_role_cache(role_id: uuid.UUID) -> None:
    """Invalidate cache for all users (role change affects unknown set of users)."""
    _permission_cache.clear()

def invalidate_all_cache() -> None:
    """Clear entire permission cache."""
    _permission_cache.clear()

# ── Legacy Role → Permission Mapping ─────────────────────────────────────────
# Used as fallback when user_roles table has no entries for a user.
# This ensures Phase 2 users work without migration.

LEGACY_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "agents.read",
        "agents.write",
        "agents.delete",
        "alerts.read",
        "alerts.acknowledge",
        "alerts.delete",
        "alerts.execute_action",
        "rules.read",
        "rules.write",
        "rules.delete",
        "events.read",
        "dashboard.view",
        "analytics.view",
        "investigation.run",
        "timeline.read",
        "ml.view",
        "ml.manage",
        "trust.read",
        "trust.compute",
        "policies.read",
        "policies.write",
        "users.read",
        "users.manage",
        "integrations.manage",
        "notifications.manage",
        "exports.generate",
        "telemetry.read",
        "cloud_telemetry.manage",
        "agent_policy.manage",
        "ws.subscribe",
        "auth.manage",
        "tenants.read",
        "tenants.manage",
        "copilot.use",
        "drift.read",
    },
    "analyst": {
        "agents.read",
        "agents.write",
        "alerts.read",
        "alerts.acknowledge",
        "alerts.execute_action",
        "rules.read",
        "rules.write",
        "events.read",
        "dashboard.view",
        "analytics.view",
        "investigation.run",
        "timeline.read",
        "ml.view",
        "trust.read",
        "trust.compute",
        "policies.read",
        "exports.generate",
        "telemetry.read",
        "agent_policy.manage",
        "ws.subscribe",
        "notifications.manage",
        "copilot.use",
        "drift.read",
    },
    "viewer": {
        "agents.read",
        "alerts.read",
        "rules.read",
        "events.read",
        "dashboard.view",
        "analytics.view",
        "timeline.read",
        "trust.read",
        "policies.read",
        "telemetry.read",
        "ws.subscribe",
    },
}

async def get_user_permissions(
    db: AsyncSession,
    user_id: uuid.UUID,
    legacy_role: str | None = None,
) -> set[str]:
    """
    Resolve the full set of permissions for a user.

    1. Check in-memory cache
    2. Query user_roles → roles → role_permissions → permissions
    3. If no user_roles entries, fall back to legacy role column
    4. Cache the result
    """
    # 1. Cache hit
    cached = _cache_get(user_id)
    if cached is not None:
        return cached

    # 2. Query via user_roles junction
    result = await db.execute(
        select(Permission.resource, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    rows = result.all()

    if rows:
        perms = {f"{r.resource}.{r.action}" for r in rows}
        _cache_set(user_id, perms)
        return perms

    # 3. Fallback to legacy role ONLY if user has never been migrated to user_roles.
    #    M-3: Check if the user has ANY user_roles entries (including deleted ones).
    #    If they do, the user was migrated — don't fall back to legacy.
    has_any_role_entry = await db.execute(select(UserRole.user_id).where(UserRole.user_id == user_id).limit(1))
    if has_any_role_entry.scalar_one_or_none() is not None:
        # User was migrated but has no current roles → empty permissions
        _cache_set(user_id, set())
        return set()

    if legacy_role and legacy_role in LEGACY_ROLE_PERMISSIONS:
        perms = LEGACY_ROLE_PERMISSIONS[legacy_role]
        _cache_set(user_id, perms)
        return perms

    # No permissions at all
    _cache_set(user_id, set())
    return set()

async def check_permission(
    db: AsyncSession,
    user_id: uuid.UUID,
    required_permission: str,
    legacy_role: str | None = None,
    context: dict[str, Any] | None = None,
) -> bool:
    """
    Check if a user has a specific permission.

    Args:
        db: Database session
        user_id: The user to check
        required_permission: e.g. "alerts.read"
        legacy_role: Fallback role from JWT
        context: Optional ABAC context (time, IP, resource attrs)

    Returns:
        True if the user has the permission
    """
    perms = await get_user_permissions(db, user_id, legacy_role)

    if required_permission not in perms:
        return False

    # If ABAC conditions exist on the role_permission, evaluate them
    if context:
        return await _evaluate_conditions(db, user_id, required_permission, context)

    return True

async def _evaluate_conditions(
    db: AsyncSession,
    user_id: uuid.UUID,
    permission: str,
    context: dict[str, Any],
) -> bool:
    """
    Evaluate ABAC conditions on a permission grant.

    Supported condition types:
      - time_range: {"after": "09:00", "before": "17:00", "timezone": "UTC"}
      - ip_range: {"allowed": ["10.0.0.0/8", "192.168.0.0/16"]}
      - resource_tags: {"required_tags": {"env": "production"}}
    """
    resource, action = permission.split(".", 1)

    # Get all conditions for this user's grants of this permission
    result = await db.execute(
        select(RolePermission.conditions)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            UserRole.user_id == user_id,
            Permission.resource == resource,
            Permission.action == action,
        )
    )
    conditions_rows = result.scalars().all()

    # No condition rows means user has no user_roles entries (legacy fallback)
    # or no ABAC conditions are configured — grant unconditionally since
    # check_permission() already verified the permission exists.
    if not conditions_rows:
        return True

    # If ANY role grants the permission unconditionally (empty conditions), allow
    for conditions in conditions_rows:
        if not conditions:
            return True

    # Check each condition set — at least one must pass (OR logic across roles)
    return any(_check_condition_set(conditions, context) for conditions in conditions_rows)

def _check_condition_set(conditions: dict, context: dict[str, Any]) -> bool:
    """
    Evaluate a single condition set against the provided context.
    All conditions within a set must pass (AND logic).
    """
    if not conditions:
        return True

    # Time-range condition
    if "time_range" in conditions:
        tr = conditions["time_range"]
        now = datetime.now(UTC)
        current_time_str = now.strftime("%H:%M")
        if "after" in tr and current_time_str < tr["after"]:
            return False
        if "before" in tr and current_time_str > tr["before"]:
            return False

    # IP range condition (M-2: handle malformed IPs gracefully)
    if "ip_range" in conditions:
        import ipaddress

        client_ip = context.get("client_ip")
        if client_ip:
            allowed = conditions["ip_range"].get("allowed", [])
            try:
                ip_obj = ipaddress.ip_address(client_ip)
                if not any(ip_obj in ipaddress.ip_network(net, strict=False) for net in allowed):
                    return False
            except ValueError:
                # Malformed IP — deny access
                return False

    # Resource tag condition
    if "resource_tags" in conditions:
        required_tags = conditions["resource_tags"].get("required_tags", {})
        resource_tags = context.get("resource_tags", {})
        for key, value in required_tags.items():
            if resource_tags.get(key) != value:
                return False

    return True

# ── Role CRUD ─────────────────────────────────────────────────────────────────

async def create_role(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    name: str,
    description: str = "",
    permission_ids: list[uuid.UUID] | None = None,
    policy: dict | None = None,
) -> Role:
    """Create a new custom role."""
    role = Role(
        tenant_id=tenant_id,
        name=name,
        description=description,
        is_builtin=False,
        policy=policy or {},
    )
    db.add(role)
    await db.flush()

    if permission_ids:
        for perm_id in permission_ids:
            db.add(RolePermission(role_id=role.id, permission_id=perm_id))
        await db.flush()

    invalidate_role_cache(role.id)
    logger.info("role_created", role_id=str(role.id), name=name, tenant_id=str(tenant_id))
    return role

async def assign_role_to_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    role_id: uuid.UUID,
) -> None:
    """Assign a role to a user."""
    db.add(UserRole(user_id=user_id, role_id=role_id))
    await db.flush()
    invalidate_user_cache(user_id)
    logger.info("role_assigned", user_id=str(user_id), role_id=str(role_id))

async def remove_role_from_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    role_id: uuid.UUID,
) -> None:
    """Remove a role from a user."""
    await db.execute(
        text("UPDATE user_roles SET deleted_at = now() WHERE user_id = :uid AND role_id = :rid AND deleted_at IS NULL"),
        {"uid": user_id, "rid": role_id},
    )
    invalidate_user_cache(user_id)
    logger.info("role_removed", user_id=str(user_id), role_id=str(role_id))

async def list_roles(db: AsyncSession, tenant_id: uuid.UUID) -> list[Role]:
    """List all roles for a tenant."""
    result = await db.execute(select(Role).where(Role.tenant_id == tenant_id).order_by(Role.name))
    return list(result.scalars().all())

async def list_permissions(db: AsyncSession) -> list[Permission]:
    """List all available permissions."""
    result = await db.execute(select(Permission).order_by(Permission.resource, Permission.action))
    return list(result.scalars().all())

async def get_user_roles(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
    """Get all roles assigned to a user."""
    result = await db.execute(
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id)
    )
    return list(result.scalars().all())
