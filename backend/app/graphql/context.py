# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex GraphQL — Request Context.

Provides authenticated user + RLS-enabled DB session to every resolver
via Strawberry's ``Info.context`` dict.

Security:
- JWT validated identically to REST middleware (same validation path)
- RLS tenant context set on every DB session
- ABAC permission helper for resolver-level checks
- Unauthenticated requests raise 401 before any resolver runs
- Session auto-closed via Strawberry extension (no leak)
"""

from __future__ import annotations

import contextlib
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from strawberry.fastapi.context import BaseContext

from app.config import get_settings
from app.database import async_session_factory, get_admin_db, set_tenant_context
from app.schemas.auth import CurrentUser, TokenPayload
from app.services.auth_service import get_effective_jwt_algorithm, get_jwt_verification_key
from app.utils.logging import get_logger

_settings = get_settings()
_logger = get_logger("phantex.graphql.context")

@dataclass
class GraphQLContext(BaseContext):
    """Typed context available in every resolver via ``info.context``."""

    request: Request
    user: CurrentUser
    db: AsyncSession
    _owns_session: bool = field(default=True, repr=False)

    async def close(self) -> None:
        """Commit and close the session when the request is done."""
        if self._owns_session and self.db is not None:
            try:
                await self.db.commit()
            except Exception:
                await self.db.rollback()
                raise
            finally:
                await self.db.close()

    # ── ABAC helper ───────────────────────────────────────────────────

    async def require_permission(self, *permissions: str) -> None:
        """Check ABAC permissions — raises PermissionError on deny.

        Mirrors ``app.middleware.abac.require_permission`` but callable
        from any resolver without FastAPI Depends().
        """
        from app.services.abac_service import check_permission

        # ABAC needs admin DB (bypasses RLS for permission lookups)
        admin_gen = get_admin_db()
        admin_db = await admin_gen.__anext__()
        try:
            context = {
                "client_ip": self.request.client.host if self.request.client else "unknown",
                "method": "POST",  # GraphQL is always POST
                "path": "/graphql",
            }
            for perm in permissions:
                has_perm = await check_permission(
                    db=admin_db,
                    user_id=self.user.user_id,
                    required_permission=perm,
                    legacy_role=self.user.role,
                    context=context,
                )
                if has_perm:
                    return
        finally:
            with contextlib.suppress(Exception):
                await admin_gen.aclose()

        _logger.warning(
            "graphql_permission_denied",
            user_id=str(self.user.user_id),
            required=list(permissions),
            role=self.user.role,
        )
        raise PermissionError(f"Insufficient permissions: {', '.join(permissions)}")

    # ── Audit helper ──────────────────────────────────────────────────

    async def audit(
        self,
        action: str,
        resource_type: str | None = None,
        resource_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit log entry — mirrors REST router audit calls."""
        from app.services import audit_service

        await audit_service.log_action(
            self.db,
            tenant_id=self.user.tenant_id,
            user_id=self.user.user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=self.request.client.host if self.request.client else None,
        )

def _extract_user(request: Request) -> CurrentUser:
    """Extract and validate JWT from the request, returning CurrentUser.

    Mirrors the logic in ``app.middleware.auth`` so GraphQL has identical
    auth semantics to the REST layer.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise PermissionError("Not authenticated")

    token_str = auth_header[7:]  # strip "Bearer "
    try:
        payload = jwt.decode(
            token_str,
            get_jwt_verification_key(),
            algorithms=[get_effective_jwt_algorithm()],
            options={"require": ["sub", "tenant_id", "role", "exp", "iat"]},
        )
        tp = TokenPayload(**payload)
        return CurrentUser(
            user_id=uuid.UUID(tp.sub),
            tenant_id=uuid.UUID(tp.tenant_id),
            role=tp.role,
        )
    except jwt.ExpiredSignatureError:
        raise PermissionError("Token expired")
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise PermissionError("Invalid token")

async def get_graphql_context(request: Request) -> GraphQLContext:
    """Strawberry context-getter wired into the GraphQL router.

    1. Validates JWT  →  ``CurrentUser``
    2. Opens an async DB session
    3. Sets RLS tenant context
    4. Returns ``GraphQLContext`` for resolvers
    """
    user = _extract_user(request)

    session = async_session_factory()
    await set_tenant_context(session, str(user.tenant_id))

    return GraphQLContext(request=request, user=user, db=session)
