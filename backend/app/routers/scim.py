# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SCIM 2.0 Router (S3: User Provisioning).

Endpoints (RFC 7644 compliant):
  GET    /scim/v2/Users             — List users
  GET    /scim/v2/Users/{id}        — Get user
  POST   /scim/v2/Users             — Create user
  PUT    /scim/v2/Users/{id}        — Replace user
  PATCH  /scim/v2/Users/{id}        — Partial update user
  DELETE /scim/v2/Users/{id}        — Deactivate user (SCIM delete = deactivate)

  POST   /api/v1/scim/tokens        — Create SCIM bearer token (admin)
  GET    /api/v1/scim/tokens        — List SCIM tokens (admin)
  DELETE /api/v1/scim/tokens/{id}   — Revoke SCIM token (admin)

SCIM endpoints use bearer token auth, not JWT.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_admin_db
from app.middleware.abac import require_permission
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.schemas.scim import (
    SCIMListResponse,
    SCIMPatchRequest,
    SCIMTokenCreate,
    SCIMTokenResponse,
    SCIMUser,
    SCIMUserCreate,
)
from app.services.scim_service import (
    _user_to_scim,
    create_scim_token,
    list_scim_tokens,
    revoke_scim_token,
    scim_create_user,
    scim_get_user,
    scim_list_users,
    scim_patch_user,
    scim_update_user,
    validate_scim_token,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.routers.scim")

# ── SCIM 2.0 User Endpoints ──────────────────────────────────────────────────

scim_router = APIRouter(prefix="/scim/v2", tags=["scim"], dependencies=[Depends(rate_limit)])

async def _get_scim_tenant(
    db: AsyncSession,
    authorization: str | None,
) -> uuid.UUID:
    """Extract and validate SCIM bearer token, return tenant_id."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="SCIM bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]  # Strip "Bearer "
    tenant_id = await validate_scim_token(db, token)
    if tenant_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired SCIM token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return tenant_id

@scim_router.get("/Users", response_model=SCIMListResponse)
async def scim_list(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    authorization: Annotated[str | None, Header()] = None,
    startIndex: int = 1,
    count: Annotated[int, Query(ge=1, le=200)] = 100,
    filter: str | None = None,
):
    """List users (SCIM 2.0)."""
    tenant_id = await _get_scim_tenant(db, authorization)
    try:
        users, total = await scim_list_users(db, tenant_id, startIndex, count, filter)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    base_url = str(request.base_url).rstrip("/")
    resources = [_user_to_scim(u, base_url) for u in users]

    return SCIMListResponse(
        totalResults=total,
        startIndex=startIndex,
        itemsPerPage=count,
        Resources=resources,
    )

@scim_router.get("/Users/{user_id}", response_model=SCIMUser)
async def scim_get(
    user_id: uuid.UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    """Get a single user (SCIM 2.0)."""
    tenant_id = await _get_scim_tenant(db, authorization)
    user = await scim_get_user(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    base_url = str(request.base_url).rstrip("/")
    return _user_to_scim(user, base_url)

@scim_router.post("/Users", response_model=SCIMUser, status_code=201)
async def scim_create(
    body: SCIMUserCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    """Create a user (SCIM 2.0)."""
    tenant_id = await _get_scim_tenant(db, authorization)

    try:
        user = await scim_create_user(db, tenant_id, body.model_dump())
        await db.commit()
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    base_url = str(request.base_url).rstrip("/")
    return _user_to_scim(user, base_url)

@scim_router.put("/Users/{user_id}", response_model=SCIMUser)
async def scim_replace(
    user_id: uuid.UUID,
    body: SCIMUserCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    """Replace a user (SCIM 2.0 PUT)."""
    tenant_id = await _get_scim_tenant(db, authorization)
    user = await scim_get_user(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user = await scim_update_user(db, user, body.model_dump(exclude_unset=True))
    await db.commit()

    base_url = str(request.base_url).rstrip("/")
    return _user_to_scim(user, base_url)

@scim_router.patch("/Users/{user_id}", response_model=SCIMUser)
async def scim_patch(
    user_id: uuid.UUID,
    body: SCIMPatchRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    """Partial update a user (SCIM 2.0 PATCH)."""
    tenant_id = await _get_scim_tenant(db, authorization)
    user = await scim_get_user(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    operations = [op.model_dump() for op in body.Operations]
    user = await scim_patch_user(db, user, operations)
    await db.commit()

    base_url = str(request.base_url).rstrip("/")
    return _user_to_scim(user, base_url)

@scim_router.delete("/Users/{user_id}", status_code=204)
async def scim_delete(
    user_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_admin_db)],
    authorization: Annotated[str | None, Header()] = None,
):
    """Deactivate user (SCIM 2.0 DELETE = soft-delete)."""
    tenant_id = await _get_scim_tenant(db, authorization)
    user = await scim_get_user(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.commit()
    return Response(status_code=204)

# ── SCIM Token Management (admin JWT auth) ────────────────────────────────────

token_router = APIRouter(prefix="/api/v1/scim", tags=["scim"])

@token_router.post(
    "/tokens",
    response_model=SCIMTokenResponse,
    status_code=201,
)
async def create_token(
    body: SCIMTokenCreate,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Create a SCIM bearer token for the tenant."""
    db_token, raw_token = await create_scim_token(db, current_user.tenant_id, body.description, body.expires_in_days)
    await db.commit()

    return SCIMTokenResponse(
        id=db_token.id,
        tenant_id=db_token.tenant_id,
        description=db_token.description,
        is_active=db_token.is_active,
        created_at=db_token.created_at,
        expires_at=db_token.expires_at,
        token=raw_token,  # Only returned once
    )

@token_router.get(
    "/tokens",
    response_model=list[SCIMTokenResponse],
)
async def list_tokens(
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """List SCIM tokens for the tenant."""
    tokens = await list_scim_tokens(db, current_user.tenant_id)
    return [
        SCIMTokenResponse(
            id=t.id,
            tenant_id=t.tenant_id,
            description=t.description,
            is_active=t.is_active,
            created_at=t.created_at,
            expires_at=t.expires_at,
        )
        for t in tokens
    ]

@token_router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: uuid.UUID,
    current_user: Annotated[CurrentUser, Depends(require_permission("auth.manage"))],
    db: Annotated[AsyncSession, Depends(get_admin_db)],
):
    """Revoke a SCIM token."""
    success = await revoke_scim_token(db, token_id, tenant_id=current_user.tenant_id)
    if not success:
        raise HTTPException(status_code=404, detail="Token not found")
    await db.commit()
    return Response(status_code=204)
