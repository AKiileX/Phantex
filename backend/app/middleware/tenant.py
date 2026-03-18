# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Tenant Isolation Middleware.

Sets PostgreSQL session variable `app.current_tenant` for RLS enforcement.
This is the defense-in-depth layer — even if service code forgets a WHERE clause,
RLS prevents cross-tenant data access at the database level.
"""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, set_tenant_context
from app.middleware.auth import get_current_user
from app.schemas.auth import CurrentUser

async def enforce_tenant_isolation(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AsyncSession:
    """
    FastAPI dependency that sets the PostgreSQL tenant context for RLS.

    Returns the session with tenant context applied, so routers can use it
    directly for queries with automatic RLS filtering.

    Usage:
        @router.get("/agents")
        async def list_agents(
            db: AsyncSession = Depends(enforce_tenant_isolation),
            user: CurrentUser = Depends(get_current_user),
        ): ...
    """
    await set_tenant_context(db, str(current_user.tenant_id))
    return db
