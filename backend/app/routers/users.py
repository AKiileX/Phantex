# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Users Router (Admin-only user management + self-service password change).

GET    /api/v1/users           — List users (admin)
POST   /api/v1/users           — Create user (admin)
GET    /api/v1/users/{id}      — Get user (admin)
PATCH  /api/v1/users/{id}      — Update user (admin)
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_user
from app.middleware.rate_limit import rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.schemas.common import CursorPage
from app.schemas.user import UserCreate, UserDetail, UserSummary, UserUpdate
from app.services import audit_service, user_service
from app.utils.password import PasswordValidationError

router = APIRouter(prefix="/api/v1/users", tags=["users"], dependencies=[Depends(rate_limit)])

@router.get(
    "",
    response_model=CursorPage[UserSummary],
    dependencies=[Depends(require_permission("users.manage"))],
    summary="List users in tenant",
)
async def list_users(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """List all users in the current tenant. Admin only."""
    page = await user_service.list_users(db, current_user.tenant_id, cursor, limit)

    items = [UserSummary.model_validate(u) for u in page.items]
    return CursorPage[UserSummary](
        items=items,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )

@router.post(
    "",
    response_model=UserDetail,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("users.manage"))],
    summary="Create a new user",
)
async def create_user(
    body: UserCreate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    request: Request,
):
    """Create a new user in the current tenant. Admin only."""
    try:
        user = await user_service.create_user(
            db,
            tenant_id=current_user.tenant_id,
            email=body.email,
            password=body.password,
            role=body.role,
            name=body.name,
        )
    except PasswordValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Password does not meet requirements", "violations": e.violations},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        details={"email": body.email, "role": body.role},
        ip_address=request.client.host if request.client else None,
    )

    return user

@router.get(
    "/{user_id}",
    response_model=UserDetail,
    dependencies=[Depends(require_permission("users.manage"))],
    summary="Get user details",
)
async def get_user(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get a single user's details. Admin only."""
    user = await user_service.get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

@router.patch(
    "/{user_id}",
    response_model=UserDetail,
    dependencies=[Depends(require_permission("users.manage"))],
    summary="Update user",
)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    request: Request,
):
    """Update a user's role, name, or active status. Admin only."""
    try:
        user = await user_service.update_user(
            db,
            user_id=user_id,
            role=body.role,
            name=body.name,
            is_active=body.is_active,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="user.update",
        resource_type="user",
        resource_id=user_id,
        details=body.model_dump(exclude_none=True),
        ip_address=request.client.host if request.client else None,
    )

    return user
