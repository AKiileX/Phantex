# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Tenant Management Router (S5).

Endpoints:
  GET    /api/v1/tenants              — List tenants (super-admin)
  POST   /api/v1/tenants              — Create + onboard tenant (super-admin)
  GET    /api/v1/tenants/{id}         — Get tenant details
  PUT    /api/v1/tenants/{id}         — Update tenant
  POST   /api/v1/tenants/{id}/suspend — Suspend tenant
  POST   /api/v1/tenants/{id}/activate — Reactivate tenant
  GET    /api/v1/tenants/{id}/usage   — Get usage metrics
  DELETE /api/v1/tenants/{id}         — Delete tenant + all data
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_admin_db
from app.middleware.abac import require_permission
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.tenant import (
    TenantCreate,
    TenantResponse,
    TenantUpdate,
    TenantUsageResponse,
)
from app.services.tenant_service import (
    create_tenant,
    delete_tenant,
    get_tenant,
    get_tenant_usage,
    list_tenants,
    onboard_tenant,
    reactivate_tenant,
    suspend_tenant,
    update_tenant,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.routers.tenants")

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"], dependencies=[Depends(rate_limit)])

# H-6: Platform seed tenant — only users from this tenant can manage others.
# This is the bootstrap tenant created during initial deployment.
_PLATFORM_TENANT_ID = uuid.UUID("a0000000-0000-0000-0000-000000000001")

def _require_platform_admin(current_user: CurrentUser, target_tenant_id: uuid.UUID) -> None:
    """
    H-6: Ensure cross-tenant operations are restricted to platform admins.
    Users can always manage their OWN tenant. Cross-tenant requires platform tenant membership.
    """
    if target_tenant_id != current_user.tenant_id and current_user.tenant_id != _PLATFORM_TENANT_ID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant operations require platform admin privileges",
        )

@router.get(
    "",
    response_model=list[TenantResponse],
)
async def list_all_tenants(
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.read"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """List all tenants (super-admin only)."""
    tenants = await list_tenants(db)
    return [TenantResponse.model_validate(t) for t in tenants]

@router.post(
    "",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_new_tenant(
    body: TenantCreate,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Create a new tenant with onboarding (admin user + built-in roles)."""
    try:
        tenant = await create_tenant(
            db,
            name=body.name,
            slug=body.slug,
            plan=body.plan,
            max_users=body.max_users,
            max_agents=body.max_agents,
            max_events_per_day=body.max_events_per_day,
        )

        # Full onboarding: creates admin user + built-in roles
        await onboard_tenant(
            db,
            tenant,
            admin_email=body.admin_email,
            admin_password=body.admin_password,
            admin_name=body.admin_name,
        )

        await db.commit()
        # Re-fetch to get all fields
        tenant = await get_tenant(db, tenant.id)
        return TenantResponse.model_validate(tenant)

    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant_details(
    tenant_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.read"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Get tenant details."""
    _require_platform_admin(current_user, tenant_id)
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)

@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant_details(
    tenant_id: uuid.UUID,
    body: TenantUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Update tenant settings."""
    _require_platform_admin(current_user, tenant_id)
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    updated = await update_tenant(db, tenant, body.model_dump(exclude_unset=True))
    await db.commit()
    return TenantResponse.model_validate(updated)

@router.post("/{tenant_id}/suspend", response_model=TenantResponse)
async def suspend_tenant_endpoint(
    tenant_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Suspend a tenant — all API calls will return 403."""
    _require_platform_admin(current_user, tenant_id)
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    suspended = await suspend_tenant(db, tenant)
    await db.commit()
    return TenantResponse.model_validate(suspended)

@router.post("/{tenant_id}/activate", response_model=TenantResponse)
async def activate_tenant_endpoint(
    tenant_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Reactivate a suspended tenant."""
    _require_platform_admin(current_user, tenant_id)
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    activated = await reactivate_tenant(db, tenant)
    await db.commit()
    return TenantResponse.model_validate(activated)

@router.get("/{tenant_id}/usage", response_model=TenantUsageResponse)
async def get_usage(
    tenant_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.read"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Get usage metrics for a tenant."""
    _require_platform_admin(current_user, tenant_id)
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    usage = await get_tenant_usage(db, tenant_id)
    return TenantUsageResponse(**usage)

@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant_endpoint(
    tenant_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("tenants.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Delete a tenant and all associated data. Irreversible."""
    _require_platform_admin(current_user, tenant_id)
    success = await delete_tenant(db, tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
