# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — JWT Authentication Middleware.

Provides FastAPI dependencies for:
- Extracting and validating JWT access tokens
- Getting the current authenticated user
- Role-based access control
"""

import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_admin_db
from app.models.user import User
from app.schemas.auth import CurrentUser, TokenPayload
from app.services.auth_service import get_effective_jwt_algorithm, get_jwt_verification_key

security_scheme = HTTPBearer(auto_error=False)
settings = get_settings()

async def get_token_payload(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_scheme)],
) -> TokenPayload:
    """
    Extract and validate JWT from Authorization: Bearer header.

    Returns decoded token payload or raises 401.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            get_jwt_verification_key(),
            algorithms=[get_effective_jwt_algorithm()],
            options={"require": ["sub", "tenant_id", "role", "exp", "iat"]},
        )
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Token expired", "code": "token_expired"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid token", "code": "invalid_token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(
    request: Request,
    token: Annotated[TokenPayload, Depends(get_token_payload)],
) -> CurrentUser:
    """
    Build CurrentUser from validated JWT payload.

    This is the primary dependency for authenticated endpoints.
    Enforces must_change_password server-side for all routes
    except password-change, self-info, and logout.
    """
    try:
        user = CurrentUser(
            user_id=uuid.UUID(token.sub),
            tenant_id=uuid.UUID(token.tenant_id),
            role=token.role,
            must_change_password=token.mcp,
        )
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    if user.must_change_password:
        _EXEMPT_PATHS = {"/api/v1/auth/password", "/api/v1/auth/me", "/api/v1/auth/logout"}
        if request.url.path not in _EXEMPT_PATHS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "Password change required before accessing this resource",
                    "code": "must_change_password",
                },
            )
    return user

async def get_current_active_user(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    request: Request,
) -> CurrentUser:
    """
    Verify that the user still exists and is active in the database.
    Adds a DB check on top of JWT validation. Use for sensitive operations.

    Uses admin DB (bypasses RLS) because this check runs before tenant
    context is established — the JWT already authenticates the user.

    Also refreshes must_change_password from DB as defense-in-depth
    (JWT-level enforcement is in get_current_user).
    """
    result = await db.execute(select(User.is_active, User.email, User.must_change_password).where(User.id == current_user.user_id))
    row = result.one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not row.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid credentials",
        )

    current_user.email = row.email
    current_user.must_change_password = row.must_change_password

    # Defense-in-depth: re-check DB state (catches flag set after JWT issued)
    if current_user.must_change_password:
        _EXEMPT_PATHS = {"/api/v1/auth/password", "/api/v1/auth/me", "/api/v1/auth/logout"}
        if request.url.path not in _EXEMPT_PATHS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "message": "Password change required before accessing this resource",
                    "code": "must_change_password",
                },
            )

    return current_user

# ── Role-Based Access Control ─────────────────────────────────────────────────

def require_role(*allowed_roles: str):
    """
    FastAPI dependency factory that enforces role-based access.

    Usage:
        @router.post("/rules", dependencies=[Depends(require_role("admin", "analyst"))])
        async def create_rule(...): ...
    """

    async def _check_role(
        current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    ) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation.",
            )
        return current_user

    return _check_role
