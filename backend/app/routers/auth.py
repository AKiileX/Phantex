# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Auth Router.

POST /api/v1/auth/login     — Authenticate with email + password, get JWT pair
POST /api/v1/auth/refresh   — Refresh access token using refresh token
POST /api/v1/auth/logout    — Revoke all refresh tokens
POST /api/v1/auth/password  — Change own password
GET  /api/v1/auth/me        — Get current user info
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_admin_db
from app.middleware.auth import get_current_active_user, get_current_user
from app.middleware.rate_limit import auth_rate_limit, rate_limit
from app.schemas.auth import (
    CurrentUser,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserResponse,
)
from app.schemas.common import MessageResponse
from app.schemas.user import PasswordChange
from app.services import audit_service, auth_service, user_service
from app.utils.password import PasswordValidationError

router = APIRouter(prefix="/api/v1/auth", tags=["auth"], dependencies=[Depends(rate_limit)])

@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(auth_rate_limit)],
    summary="Authenticate and get JWT tokens",
)
async def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """
    Authenticate with email + password.
    Returns access_token (15 min) + refresh_token (7 days).
    """
    try:
        user = await auth_service.authenticate_user(db, body.email, body.password)
    except ValueError as e:
        error_code = str(e)
        if error_code == "rate_limited":
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Too many login attempts. Try again in 1 minute.",
                    "code": "rate_limited",
                },
                headers={"Retry-After": "60"},
            )
        raise

    if user is None:
        # Audit the failed login attempt. tenant_id is nullable so this is safe
        # even though we have no authenticated tenant context.
        await audit_service.log_action(
            db,
            tenant_id=None,
            user_id=None,
            action="user.login_failed",
            resource_type="user",
            details={"email": body.email},
            ip_address=request.client.host if request.client else None,
        )
        # Commit audit entry before raising — otherwise the yield-based
        # dependency teardown calls rollback(), losing the audit record.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    tokens = await auth_service.create_token_pair(db, user)

    # Audit log
    await audit_service.log_action(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else None,
    )

    return tokens

@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(auth_rate_limit)],
    summary="Refresh access token",
)
async def refresh(
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """
    Exchange a valid refresh token for a new token pair.
    The old refresh token is revoked (single-use rotation).
    """
    tokens = await auth_service.refresh_token_pair(db, body.refresh_token)
    if tokens is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return tokens

@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all refresh tokens",
)
async def logout(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Revoke all refresh tokens for the current user."""
    await auth_service.revoke_all_refresh_tokens(db, current_user.user_id)

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="user.logout",
        resource_type="user",
        resource_id=current_user.user_id,
    )

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user info",
)
async def get_me(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Return the authenticated user's profile."""
    from sqlalchemy import select

    from app.models.user import User

    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return user

@router.get(
    "/me/permissions",
    summary="Get current user's effective permissions",
)
async def get_my_permissions(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """
    Return the authenticated user's effective permission set.
    Resolves through user_roles → roles → role_permissions, with legacy role fallback.
    Used by the dashboard to drive UI visibility (hide buttons/pages the user can't access).
    """
    from app.services.abac_service import get_user_permissions

    perms = await get_user_permissions(db, current_user.user_id, current_user.role)
    return {"permissions": sorted(perms)}

@router.post(
    "/password",
    response_model=MessageResponse,
    dependencies=[Depends(auth_rate_limit)],
    summary="Change own password",
)
async def change_password(
    body: PasswordChange,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    request: Request,
):
    """
    Change the current user's password.
    Requires current password for verification.
    New password must meet complexity requirements (12+ chars, mixed case, digit, special).
    All refresh tokens are revoked after password change (force re-login).
    """
    try:
        await user_service.change_password(
            db,
            user_id=current_user.user_id,
            current_password=body.current_password,
            new_password=body.new_password,
        )
    except PasswordValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "New password does not meet requirements", "violations": e.violations},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    await audit_service.log_action(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        action="user.password_change",
        resource_type="user",
        resource_id=current_user.user_id,
        ip_address=request.client.host if request.client else None,
    )

    return MessageResponse(message="Password changed successfully. All sessions have been invalidated.")
