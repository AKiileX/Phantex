# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Roles & Permissions Router (S4: ABAC).

Endpoints:
  GET    /api/v1/roles                        — List roles for tenant
  POST   /api/v1/roles                        — Create custom role
  GET    /api/v1/roles/{id}                   — Get role with permissions
  PUT    /api/v1/roles/{id}                   — Update role
  DELETE /api/v1/roles/{id}                   — Delete custom role
  GET    /api/v1/permissions                  — List all available permissions
  GET    /api/v1/users/{id}/roles             — Get user's roles + permissions
  POST   /api/v1/users/{id}/roles             — Assign role to user
  DELETE /api/v1/users/{id}/roles/{role_id}   — Remove role from user
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_admin_db
from app.middleware.abac import require_permission
from app.middleware.rate_limit import rate_limit
from app.models.permission import Role, RolePermission
from app.models.user import User
from app.schemas.abac import (
    PermissionResponse,
    RoleCreate,
    RoleResponse,
    RoleSummary,
    RoleUpdate,
    UserRoleAssign,
    UserRolesResponse,
)
from app.schemas.auth import CurrentUser
from app.services.abac_service import (
    assign_role_to_user,
    create_role,
    get_user_permissions,
    get_user_roles,
    invalidate_role_cache,
    list_permissions,
    list_roles,
    remove_role_from_user,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.routers.roles")

router = APIRouter(tags=["roles"], dependencies=[Depends(rate_limit)])

# ── Roles ─────────────────────────────────────────────────────────────────────

@router.get("/api/v1/roles", response_model=list[RoleResponse])
async def list_tenant_roles(
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """List all roles for the current tenant."""
    roles = await list_roles(db, current_user.tenant_id)
    return [RoleResponse.model_validate(r) for r in roles]

@router.post(
    "/api/v1/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_new_role(
    body: RoleCreate,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Create a custom role with permissions."""
    try:
        role = await create_role(
            db,
            tenant_id=current_user.tenant_id,
            name=body.name,
            description=body.description,
            permission_ids=body.permission_ids,
            policy=body.policy,
        )
        await db.commit()
        return RoleResponse.model_validate(role)
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Role with this name already exists")
    except Exception as e:
        logger.error("role_creation_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/api/v1/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Get a role with its permissions."""
    result = await db.execute(select(Role).where(Role.id == role_id, Role.tenant_id == current_user.tenant_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return RoleResponse.model_validate(role)

@router.put("/api/v1/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Update a role. Built-in roles can only have permissions changed, not name."""
    result = await db.execute(select(Role).where(Role.id == role_id, Role.tenant_id == current_user.tenant_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.is_builtin and body.name and body.name != role.name:
        raise HTTPException(status_code=400, detail="Cannot rename built-in roles")

    if body.name:
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    if body.policy is not None:
        role.policy = body.policy

    # Update permissions if provided
    if body.permission_ids is not None:
        # Soft-delete existing
        await db.execute(
            update(RolePermission)
            .where(RolePermission.role_id == role_id, RolePermission.deleted_at.is_(None))
            .values(deleted_at=func.now())
        )
        # Add new
        for perm_id in body.permission_ids:
            db.add(RolePermission(role_id=role_id, permission_id=perm_id))

    await db.flush()
    invalidate_role_cache(role_id)
    await db.commit()

    # Re-fetch
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one()
    return RoleResponse.model_validate(role)

@router.delete("/api/v1/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Delete a custom role. Built-in roles cannot be deleted."""
    result = await db.execute(select(Role).where(Role.id == role_id, Role.tenant_id == current_user.tenant_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in roles")

    role.deleted_at = func.now()
    invalidate_role_cache(role_id)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# ── Permissions ───────────────────────────────────────────────────────────────

@router.get("/api/v1/permissions", response_model=list[PermissionResponse])
async def list_all_permissions(
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """List all available permissions."""
    perms = await list_permissions(db)
    return [PermissionResponse.model_validate(p) for p in perms]

# ── User Role Assignments ────────────────────────────────────────────────────

@router.get("/api/v1/users/{user_id}/roles", response_model=UserRolesResponse)
async def get_user_role_assignments(
    user_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("users.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Get a user's roles and effective permissions."""
    # Verify user exists in same tenant
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    roles = await get_user_roles(db, user_id)
    perms = await get_user_permissions(db, user_id, user.role)

    return UserRolesResponse(
        user_id=user_id,
        roles=[RoleSummary.model_validate(r) for r in roles],
        effective_permissions=sorted(perms),
    )

@router.post(
    "/api/v1/users/{user_id}/roles",
    status_code=status.HTTP_201_CREATED,
)
async def assign_user_role(
    user_id: uuid.UUID,
    body: UserRoleAssign,
    current_user: Annotated[CurrentUser, Depends(require_permission("users.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Assign a role to a user."""
    # Verify user and role exist
    user_result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found")

    role_result = await db.execute(
        select(Role).where(Role.id == body.role_id, Role.tenant_id == current_user.tenant_id)
    )
    if not role_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Role not found")

    try:
        await assign_role_to_user(db, user_id, body.role_id)
        await db.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="Role already assigned")

    return {"message": "Role assigned"}

@router.delete(
    "/api/v1/users/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_user_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("users.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Remove a role from a user."""
    # H-4: Verify user belongs to same tenant (prevent cross-tenant removal)
    user_result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found")

    await remove_role_from_user(db, user_id, role_id)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
