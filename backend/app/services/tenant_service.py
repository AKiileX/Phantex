# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Tenant Management Service (S5).

Handles:
  - Tenant CRUD (create, update, suspend, delete)
  - Tenant onboarding (create admin user + built-in roles)
  - Usage metrics
  - Tenant data purge with audit trail
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.alert import Alert
from app.models.permission import Permission, Role, RolePermission, UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.services.auth_service import hash_password
from app.utils.logging import get_logger

logger = get_logger("phantex.services.tenant")

async def create_tenant(
    db: AsyncSession,
    name: str,
    slug: str,
    plan: str = "community",
    max_users: int = 100,
    max_agents: int = 50,
    max_events_per_day: int = 10_000_000,
) -> Tenant:
    """Create a new tenant."""
    # Check slug uniqueness
    existing = await db.execute(select(Tenant).where(Tenant.slug == slug))
    if existing.scalar_one_or_none():
        raise ValueError(f"Tenant slug '{slug}' already exists")

    tenant = Tenant(
        name=name,
        slug=slug,
        plan=plan,
        settings={},
    )
    # Set the new Phase 3 fields if they exist on the model
    if hasattr(tenant, "max_users"):
        tenant.max_users = max_users
    if hasattr(tenant, "max_agents"):
        tenant.max_agents = max_agents
    if hasattr(tenant, "max_events_per_day"):
        tenant.max_events_per_day = max_events_per_day

    db.add(tenant)
    await db.flush()

    logger.info("tenant_created", tenant_id=str(tenant.id), slug=slug, plan=plan)
    return tenant

async def onboard_tenant(
    db: AsyncSession,
    tenant: Tenant,
    admin_email: str,
    admin_password: str,
    admin_name: str | None = None,
) -> User:
    """
    Full tenant onboarding:
    1. Create built-in roles (admin, analyst, viewer)
    2. Create first admin user
    3. Assign admin role
    4. Mark tenant as onboarded
    """
    # 1. Create built-in roles
    builtin_roles = {}
    for role_name, desc in [
        ("admin", "Full administrative access"),
        ("analyst", "Security analyst — investigate and respond"),
        ("viewer", "Read-only dashboard access"),
    ]:
        role = Role(
            tenant_id=tenant.id,
            name=role_name,
            description=desc,
            is_builtin=True,
        )
        db.add(role)
        await db.flush()
        builtin_roles[role_name] = role

    # Assign permissions to built-in roles
    all_perms = await db.execute(select(Permission))
    all_perms_list = list(all_perms.scalars().all())

    # Admin gets everything
    for perm in all_perms_list:
        db.add(RolePermission(role_id=builtin_roles["admin"].id, permission_id=perm.id))

    # Analyst permissions
    analyst_perms = {
        ("agents", "read"),
        ("agents", "write"),
        ("alerts", "read"),
        ("alerts", "acknowledge"),
        ("rules", "read"),
        ("rules", "write"),
        ("events", "read"),
        ("dashboard", "view"),
        ("analytics", "view"),
        ("investigation", "run"),
        ("timeline", "read"),
        ("ml", "view"),
        ("trust", "read"),
        ("trust", "compute"),
        ("policies", "read"),
        ("exports", "generate"),
        ("telemetry", "read"),
        ("agent_policy", "manage"),
        ("ws", "subscribe"),
        ("notifications", "manage"),
    }
    for perm in all_perms_list:
        if (perm.resource, perm.action) in analyst_perms:
            db.add(RolePermission(role_id=builtin_roles["analyst"].id, permission_id=perm.id))

    # Viewer permissions (read-only)
    viewer_perms = {
        ("agents", "read"),
        ("alerts", "read"),
        ("rules", "read"),
        ("events", "read"),
        ("dashboard", "view"),
        ("analytics", "view"),
        ("timeline", "read"),
        ("trust", "read"),
        ("policies", "read"),
        ("telemetry", "read"),
        ("ws", "subscribe"),
    }
    for perm in all_perms_list:
        if (perm.resource, perm.action) in viewer_perms:
            db.add(RolePermission(role_id=builtin_roles["viewer"].id, permission_id=perm.id))

    await db.flush()

    # 2. Create admin user
    admin_user = User(
        tenant_id=tenant.id,
        email=admin_email.lower().strip(),
        password_hash=hash_password(admin_password),
        role="admin",
        name=admin_name,
        is_active=True,
    )
    db.add(admin_user)
    await db.flush()

    # 3. Assign admin role
    db.add(UserRole(user_id=admin_user.id, role_id=builtin_roles["admin"].id))
    await db.flush()

    # 4. Mark as onboarded
    if hasattr(tenant, "onboarded_at"):
        tenant.onboarded_at = datetime.now(UTC)
    tenant.updated_at = datetime.now(UTC)
    await db.flush()

    logger.info(
        "tenant_onboarded",
        tenant_id=str(tenant.id),
        admin_email=admin_email,
    )
    return admin_user

async def get_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant | None:
    """Get a tenant by ID."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    return result.scalar_one_or_none()

async def get_tenant_by_slug(db: AsyncSession, slug: str) -> Tenant | None:
    """Get a tenant by slug."""
    result = await db.execute(select(Tenant).where(Tenant.slug == slug))
    return result.scalar_one_or_none()

async def list_tenants(db: AsyncSession) -> list[Tenant]:
    """List all tenants (super-admin only)."""
    result = await db.execute(select(Tenant).order_by(Tenant.created_at.desc()))
    return list(result.scalars().all())

async def update_tenant(db: AsyncSession, tenant: Tenant, data: dict) -> Tenant:
    """Update tenant fields."""
    for key, value in data.items():
        if value is not None and hasattr(tenant, key):
            setattr(tenant, key, value)
    tenant.updated_at = datetime.now(UTC)
    await db.flush()
    return tenant

async def suspend_tenant(db: AsyncSession, tenant: Tenant) -> Tenant:
    """Suspend a tenant — all API calls will return 403."""
    if hasattr(tenant, "is_active"):
        tenant.is_active = False
    if hasattr(tenant, "suspended_at"):
        tenant.suspended_at = datetime.now(UTC)
    tenant.updated_at = datetime.now(UTC)
    await db.flush()
    logger.warning("tenant_suspended", tenant_id=str(tenant.id), slug=tenant.slug)
    return tenant

async def reactivate_tenant(db: AsyncSession, tenant: Tenant) -> Tenant:
    """Reactivate a suspended tenant."""
    if hasattr(tenant, "is_active"):
        tenant.is_active = True
    if hasattr(tenant, "suspended_at"):
        tenant.suspended_at = None
    tenant.updated_at = datetime.now(UTC)
    await db.flush()
    logger.info("tenant_reactivated", tenant_id=str(tenant.id), slug=tenant.slug)
    return tenant

async def get_tenant_usage(db: AsyncSession, tenant_id: uuid.UUID) -> dict:
    """Get usage metrics for a tenant."""
    user_count = (
        await db.execute(
            select(func.count()).select_from(User).where(User.tenant_id == tenant_id, User.is_active == True)  # noqa: E712
        )
    ).scalar() or 0

    agent_count = (
        await db.execute(select(func.count()).select_from(Agent).where(Agent.tenant_id == tenant_id))
    ).scalar() or 0

    alerts_open = (
        await db.execute(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.status == "open",
            )
        )
    ).scalar() or 0

    return {
        "tenant_id": tenant_id,
        "user_count": user_count,
        "agent_count": agent_count,
        "events_today": 0,  # Would query ClickHouse
        "alerts_open": alerts_open,
        "storage_bytes": 0,  # Would query ClickHouse
    }

async def delete_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> bool:
    """
    Delete a tenant and all associated data.
    CASCADE handles most cleanup via FK constraints.
    """
    tenant = await get_tenant(db, tenant_id)
    if tenant is None:
        return False

    # Log before deletion for audit trail
    logger.warning(
        "tenant_deleted",
        tenant_id=str(tenant_id),
        slug=tenant.slug,
        name=tenant.name,
    )

    await db.delete(tenant)
    await db.flush()
    return True
