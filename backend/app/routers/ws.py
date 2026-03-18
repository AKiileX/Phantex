# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — WebSocket Alert Endpoint.

Provides real-time alert streaming to dashboard clients.

Connection flow (ticket-based):
1. Client POSTs to /api/v1/ws/ticket with JWT in Authorization header
2. Server returns { "ticket": "<single-use-ticket>" }
3. Client connects to /ws/alerts?ticket=<ticket>
4. Server validates + consumes ticket, extracts tenant_id
5. Normal WebSocket session proceeds

Legacy flow (deprecated):
    /ws/alerts?token=<JWT> — still works but logs a deprecation warning.

Authentication:
    Ticket-based auth avoids passing JWTs in URLs (which get logged).
    Tickets are single-use, 30-second TTL.
"""

from __future__ import annotations

import jwt
import structlog
from fastapi import APIRouter, Depends, Query, WebSocket, status

from app.config import get_settings
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import _rate_limiter, _redis_rate_limiter, rate_limit
from app.services.auth_service import get_effective_jwt_algorithm, get_jwt_verification_key
from app.services.ws_ticket import WSTicketStore

logger = structlog.get_logger("phantex.ws.alerts")

# NOTE: Router-level dependencies=[Depends(rate_limit)] ALSO run for
# @router.websocket() endpoints in modern FastAPI, but rate_limit()
# requires a Request object (not WebSocket).  We therefore apply the
# dependency only on the REST endpoints below instead of the router.
router = APIRouter(tags=["websocket"])
settings = get_settings()

# ── Singleton references (set during app startup) ────────────────────────────
_ws_manager = None
_ticket_store = WSTicketStore()

def set_ws_manager(manager) -> None:
    """Set the WebSocket manager singleton. Called from main.py lifespan."""
    global _ws_manager
    _ws_manager = manager

def get_ws_manager():
    """Get the WebSocket manager singleton."""
    return _ws_manager

def get_ticket_store() -> WSTicketStore:
    """Get the ticket store singleton."""
    return _ticket_store

# ── WebSocket Auth ────────────────────────────────────────────────────────────

def authenticate_ws_token(token: str) -> dict:
    """
    Validate a JWT token for WebSocket connections.

    Returns decoded payload dict with sub, tenant_id, role.
    Raises ValueError if token is invalid.
    """
    try:
        payload = jwt.decode(
            token,
            get_jwt_verification_key(),
            algorithms=[get_effective_jwt_algorithm()],
            options={"require": ["sub", "tenant_id", "role", "exp", "iat"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

# ── WebSocket Endpoint ────────────────────────────────────────────────────────

@router.websocket("/ws/alerts")
async def ws_alerts(
    websocket: WebSocket,
    ticket: str | None = Query(None, description="Single-use WS ticket"),
    token: str | None = Query(None, description="JWT access token (deprecated)"),
):
    """
    WebSocket endpoint for real-time alert streaming.

    Connect with:
        Preferred: ws://host:port/ws/alerts?ticket=<ticket>
        Legacy:    ws://host:port/ws/alerts?token=<JWT>

    Messages sent to client:
        { "type": "connected", "connection_id": "...", "tenant_id": "..." }
        { "type": "alert", "data": { alert payload } }
        { "type": "heartbeat" }
        { "type": "pong" }

    Messages client can send:
        { "type": "ping" }

    Disconnection:
        Close the WebSocket normally. Server cleans up automatically.
    """
    # 0) Rate limit — router-level dependencies don't run for WebSocket endpoints
    client_ip = websocket.client.host if websocket.client else "unknown"
    ws_key = f"ws:{client_ip}"
    if _redis_rate_limiter is not None:
        allowed = await _redis_rate_limiter.allow(ws_key)
    else:
        allowed = _rate_limiter.allow(ws_key)
    if not allowed:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Rate limit exceeded",
        )
        return

    # 1) Authenticate via ticket (preferred) or legacy token
    tenant_id = None
    user_id = None

    if ticket:
        # Ticket-based auth
        ws_ticket = _ticket_store.consume_ticket(ticket)
        if ws_ticket is None:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Invalid or expired ticket",
            )
            return
        tenant_id = ws_ticket.tenant_id
        user_id = ws_ticket.user_id
    elif token:
        # Legacy JWT auth (deprecated)
        if not settings.ws_legacy_token_enabled:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Legacy token auth is disabled",
            )
            return
        logger.warning("ws_legacy_token_auth", client_ip=client_ip)
        try:
            payload = authenticate_ws_token(token)
        except ValueError as e:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=str(e))
            return
        tenant_id = payload.get("tenant_id")
        user_id = payload.get("sub")
    else:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Missing ticket or token parameter",
        )
        return

    if not tenant_id:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Missing tenant_id in token",
        )
        return

    # 2) Check manager is available
    manager = get_ws_manager()
    if manager is None:
        logger.error("ws_manager_not_initialized")
        await websocket.close(
            code=status.WS_1011_UNEXPECTED_CONDITION,
            reason="WebSocket service unavailable",
        )
        return

    # 3) Handle the connection lifecycle
    logger.info(
        "ws_alert_connection",
        tenant_id=tenant_id,
        user_id=user_id,
    )

    await manager.handle_connection(websocket, tenant_id, user_id)

# ── Ticket Endpoint ──────────────────────────────────────────────────────────

@router.post("/api/v1/ws/ticket", tags=["websocket"], dependencies=[Depends(rate_limit)])
async def create_ws_ticket(
    current_user=Depends(get_current_active_user),
):
    """
    Generate a single-use WebSocket authentication ticket.

    Requires a valid JWT in the Authorization header.
    Returns a ticket that can be used once within 30 seconds
    to establish a WebSocket connection.
    """
    tenant_id = getattr(current_user, "tenant_id", None)
    user_id = str(getattr(current_user, "user_id", ""))
    role = getattr(current_user, "role", "viewer")

    if not tenant_id:
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail="Missing tenant_id")

    try:
        ticket = _ticket_store.create_ticket(
            tenant_id=str(tenant_id),
            user_id=user_id,
            role=str(role),
        )
    except RuntimeError as e:
        from fastapi import HTTPException

        raise HTTPException(status_code=429, detail=str(e))

    return {
        "ticket": ticket,
        "expires_in": 30,
    }

# ── Health Check (REST) ──────────────────────────────────────────────────────

@router.get("/api/v1/ws/status", tags=["websocket"], dependencies=[Depends(rate_limit)])
async def ws_status(
    current_user=Depends(get_current_active_user),
):
    """WebSocket subsystem status (authenticated, scoped to caller's tenant)."""
    manager = get_ws_manager()
    if manager is None:
        return {
            "status": "not_initialized",
            "active_connections": 0,
        }
    # Only expose connection count for the calling user's tenant
    tenant_id = getattr(current_user, "tenant_id", None)
    tenant_connections = 0
    if hasattr(manager, "connections"):
        tenant_connections = sum(
            1 for conn in manager.connections.values() if getattr(conn, "tenant_id", None) == tenant_id
        )
    return {
        "status": "active",
        "tenant_active_connections": tenant_connections,
    }
