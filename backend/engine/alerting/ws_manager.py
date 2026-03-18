# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
WebSocket Alert Manager — manages connections and pushes alerts to dashboards.

Each WebSocket client connects to /ws/alerts with a JWT token for
authentication. The manager:
1. Validates the token and extracts tenant_id
2. Registers the connection with the AlertBroadcaster
3. Sends a heartbeat every 30 seconds to keep the connection alive
4. Forwards alerts from the AlertBroadcaster to the client
5. Cleans up on disconnect

This is the server-side WebSocket handler — the dashboard (React) connects
to this endpoint and receives real-time alert notifications.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from typing import Any

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from engine.alerting.publisher import AlertBroadcaster

logger = structlog.get_logger("phantex.alerting.ws_manager")

class WebSocketAlertManager:
    """
    Manages WebSocket connections for real-time alert streaming.

    One instance per application. Each connected client is registered
    with the AlertBroadcaster for their tenant.
    """

    # Default max connections per tenant (prevents flood/resource exhaustion)
    DEFAULT_MAX_CONNECTIONS_PER_TENANT = 50

    def __init__(
        self,
        broadcaster: AlertBroadcaster,
        max_connections_per_tenant: int = DEFAULT_MAX_CONNECTIONS_PER_TENANT,
    ) -> None:
        self._broadcaster = broadcaster
        self._max_connections_per_tenant = max_connections_per_tenant
        # connection_id → WebSocket
        self._connections: dict[str, WebSocket] = {}
        # connection_id → tenant_id
        self._connection_tenants: dict[str, str] = {}
        # Metrics
        self._total_connections: int = 0
        self._total_messages_sent: int = 0
        self._total_rejected: int = 0

    async def connect(
        self,
        websocket: WebSocket,
        tenant_id: str,
        user_id: str | None = None,
    ) -> str:
        """
        Accept a WebSocket connection and register for alert broadcasts.
        Returns the connection ID.

        Raises ConnectionRefusedError if the tenant has hit the connection limit.
        """
        # ── Per-tenant connection limit ──────────────────────────────────
        tenant_count = sum(1 for tid in self._connection_tenants.values() if tid == tenant_id)
        if tenant_count >= self._max_connections_per_tenant:
            self._total_rejected += 1
            logger.warning(
                "ws_connection_limit_reached",
                tenant_id=tenant_id,
                current=tenant_count,
                limit=self._max_connections_per_tenant,
            )
            await websocket.close(
                code=1008,  # Policy Violation
                reason=f"Connection limit reached ({self._max_connections_per_tenant} per tenant)",
            )
            raise ConnectionRefusedError(f"Tenant {tenant_id} at connection limit ({self._max_connections_per_tenant})")

        await websocket.accept()

        connection_id = str(uuid.uuid4())
        self._connections[connection_id] = websocket
        self._connection_tenants[connection_id] = tenant_id
        self._total_connections += 1

        # Create the callback that sends alerts to this specific WebSocket
        async def send_alert(alert_payload: dict[str, Any]) -> None:
            await self._send_json(
                connection_id,
                {
                    "type": "alert",
                    "data": alert_payload,
                },
            )

        # Register with broadcaster
        self._broadcaster.subscribe(tenant_id, connection_id, send_alert)

        logger.info(
            "ws_connected",
            connection_id=connection_id,
            tenant_id=tenant_id,
            user_id=user_id,
            active_connections=len(self._connections),
        )

        # Send welcome message
        await self._send_json(
            connection_id,
            {
                "type": "connected",
                "connection_id": connection_id,
                "tenant_id": tenant_id,
            },
        )

        return connection_id

    async def disconnect(self, connection_id: str) -> None:
        """Clean up a disconnected WebSocket."""
        tenant_id = self._connection_tenants.pop(connection_id, None)
        self._connections.pop(connection_id, None)

        if tenant_id:
            self._broadcaster.unsubscribe(tenant_id, connection_id)

        logger.info(
            "ws_disconnected",
            connection_id=connection_id,
            tenant_id=tenant_id,
            active_connections=len(self._connections),
        )

    async def handle_connection(
        self,
        websocket: WebSocket,
        tenant_id: str,
        user_id: str | None = None,
    ) -> None:
        """
        Full lifecycle handler for a WebSocket connection.

        Accepts, registers, listens for messages (ping/pong), and cleans up.
        This runs for the lifetime of the connection.
        """
        try:
            connection_id = await self.connect(websocket, tenant_id, user_id)
        except ConnectionRefusedError:
            return  # Already closed with policy violation code

        try:
            # Start heartbeat task
            heartbeat_task = asyncio.create_task(
                self._heartbeat(connection_id),
            )

            try:
                while True:
                    # Listen for client messages (ping, subscribe filters, etc.)
                    data = await websocket.receive_text()
                    await self._handle_client_message(connection_id, data)
            except WebSocketDisconnect:
                pass
            finally:
                heartbeat_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat_task
        finally:
            await self.disconnect(connection_id)

    async def _handle_client_message(
        self,
        connection_id: str,
        raw: str,
    ) -> None:
        """Handle a message from the client (ping, filter, etc.)."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return

        msg_type = msg.get("type", "")

        if msg_type == "ping":
            await self._send_json(connection_id, {"type": "pong"})
        elif msg_type == "subscribe_filter":
            # Future: per-severity or per-agent filter
            logger.debug(
                "ws_filter_requested",
                connection_id=connection_id,
                filter=msg.get("filter"),
            )
        else:
            logger.debug(
                "ws_unknown_message",
                connection_id=connection_id,
                msg_type=msg_type,
            )

    async def _heartbeat(self, connection_id: str, interval: float = 30.0) -> None:
        """Send periodic heartbeat to keep the connection alive."""
        while connection_id in self._connections:
            await asyncio.sleep(interval)
            if connection_id in self._connections:
                try:
                    await self._send_json(connection_id, {"type": "heartbeat"})
                except Exception:
                    break

    async def _send_json(self, connection_id: str, data: dict[str, Any]) -> None:
        """Send a JSON message to a specific connection."""
        websocket = self._connections.get(connection_id)
        if not websocket:
            return

        try:
            await websocket.send_json(data)
            self._total_messages_sent += 1
        except Exception as e:
            logger.warning(
                "ws_send_failed",
                connection_id=connection_id,
                error=str(e),
            )
            # Connection is dead — clean up
            await self.disconnect(connection_id)

    @property
    def active_connections(self) -> int:
        return len(self._connections)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "active_connections": len(self._connections),
            "total_connections": self._total_connections,
            "total_messages_sent": self._total_messages_sent,
            "total_rejected": self._total_rejected,
            "max_per_tenant": self._max_connections_per_tenant,
            "tenants_connected": len(set(self._connection_tenants.values())),
        }
