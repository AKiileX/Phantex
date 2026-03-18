# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ABAC Middleware.

Provides FastAPI dependency factories for attribute-based access control.
Wraps the existing JWT auth chain and adds permission evaluation.

Usage:
    @router.get("/alerts", dependencies=[Depends(require_permission("alerts.read"))])
    async def list_alerts(...): ...

Backward compatible: `require_role("admin")` still works (delegates to ABAC).
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_admin_db
from app.middleware.auth import get_current_active_user
from app.schemas.auth import CurrentUser
from app.services.abac_service import check_permission
from app.utils.logging import get_logger

logger = get_logger("phantex.middleware.abac")

# H-3: Only trust X-Forwarded-For from known reverse proxies
# Docker internal networks + loopback. Extend via env/config as needed.
_TRUSTED_PROXIES: set[str] = {
    "127.0.0.1",
    "::1",
    # Docker bridge & compose default gateways
    "172.16.0.0/12",
    "10.0.0.0/8",
    "192.168.0.0/16",
}

def _is_trusted_proxy(ip: str) -> bool:
    """Check if an IP is a known reverse proxy."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        # Check exact matches first
        if ip in _TRUSTED_PROXIES:
            return True
        # Check CIDR ranges
        for network_str in _TRUSTED_PROXIES:
            if "/" in network_str and addr in ipaddress.ip_network(network_str, strict=False):
                return True
        return False
    except ValueError:
        return False

def require_permission(*permissions: str):
    """
    FastAPI dependency factory that enforces ABAC permission checks.

    Accepts one or more permission strings (OR logic — user needs ANY ONE).
    Format: "resource.action" (e.g. "alerts.read", "rules.write")

    Example:
        @router.post("/rules", dependencies=[Depends(require_permission("rules.write"))])
        async def create_rule(...): ...

        # Multiple permissions (user needs at least one):
        @router.get("/data", dependencies=[Depends(require_permission("events.read", "alerts.read"))])
    """

    async def _check_permission(
        request: Request,
        current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
        db: Annotated[AsyncSession, Depends(get_admin_db)],
    ) -> CurrentUser:
        # Build ABAC context from request
        context = {
            "client_ip": _get_client_ip(request),
            "method": request.method,
            "path": request.url.path,
        }

        # Check each permission (OR logic)
        for perm in permissions:
            has_perm = await check_permission(
                db=db,
                user_id=current_user.user_id,
                required_permission=perm,
                legacy_role=current_user.role,
                context=context,
            )
            if has_perm:
                return current_user

        # Log denied access
        logger.warning(
            "permission_denied",
            user_id=str(current_user.user_id),
            required=list(permissions),
            role=current_user.role,
            path=request.url.path,
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Insufficient permissions",
                "required": list(permissions),
                "code": "permission_denied",
            },
        )

    return _check_permission

def _get_client_ip(request: Request) -> str:
    """
    Extract client IP, respecting X-Forwarded-For only from trusted proxies.
    H-3: Prevents IP spoofing for ABAC ip_range conditions.
    L-1: Returns None-safe fallback that won't match permissive ranges.
    """
    peer_ip = request.client.host if request.client else None

    if peer_ip and _is_trusted_proxy(peer_ip):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return peer_ip or "0.0.0.0"
