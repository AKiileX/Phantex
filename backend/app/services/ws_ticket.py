# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — WebSocket Ticket Service.

Implements single-use, time-limited tickets for WebSocket authentication.
This replaces passing JWTs as query parameters (which get logged in URLs).

Flow:
1. Client POSTs to /api/v1/ws/ticket with a valid JWT (Authorization header)
2. Server generates a random ticket, stores it with tenant/user metadata
3. Client connects to ws://host/ws/alerts?ticket=<ticket>
4. Server validates + consumes the ticket (single-use)
5. Normal WebSocket session proceeds

Storage:
    Phase 2: In-memory dict (single-process). Upgrade to Redis in I1.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from threading import Lock

import structlog

logger = structlog.get_logger("phantex.services.ws_ticket")

# Ticket TTL: 30 seconds (client must connect within 30s of getting the ticket)
TICKET_TTL_SECONDS = 30

# Max pending tickets (prevent memory exhaustion attacks)
MAX_PENDING_TICKETS = 10_000

@dataclass
class WSTicket:
    """A single-use WebSocket authentication ticket."""

    ticket: str
    tenant_id: str
    user_id: str
    role: str
    created_at: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > TICKET_TTL_SECONDS

class WSTicketStore:
    """
    In-memory store for WebSocket auth tickets.

    Thread-safe. Single-use: tickets are deleted on consumption.
    Auto-purges expired tickets on each operation.
    """

    def __init__(self) -> None:
        self._tickets: dict[str, WSTicket] = {}
        self._lock = Lock()

    def create_ticket(
        self,
        tenant_id: str,
        user_id: str,
        role: str,
    ) -> str:
        """
        Create a new single-use ticket.

        Args:
            tenant_id: Tenant UUID
            user_id: User UUID
            role: User role

        Returns:
            Ticket string (URL-safe, 48 chars)

        Raises:
            RuntimeError: If too many pending tickets
        """
        with self._lock:
            self._purge_expired()

            if len(self._tickets) >= MAX_PENDING_TICKETS:
                raise RuntimeError("Too many pending WebSocket tickets")

            ticket_str = secrets.token_urlsafe(36)  # 48 chars
            self._tickets[ticket_str] = WSTicket(
                ticket=ticket_str,
                tenant_id=tenant_id,
                user_id=user_id,
                role=role,
            )

            logger.debug(
                "ws_ticket_created",
                tenant_id=tenant_id,
                user_id=user_id,
                pending=len(self._tickets),
            )

            return ticket_str

    def consume_ticket(self, ticket_str: str) -> WSTicket | None:
        """
        Validate and consume a ticket (single-use).

        Args:
            ticket_str: The ticket string from the client

        Returns:
            WSTicket if valid, None if invalid/expired/already-used
        """
        with self._lock:
            self._purge_expired()

            ticket = self._tickets.pop(ticket_str, None)
            if ticket is None:
                logger.warning("ws_ticket_invalid_or_consumed")
                return None

            if ticket.is_expired:
                logger.warning(
                    "ws_ticket_expired",
                    tenant_id=ticket.tenant_id,
                    age_seconds=time.time() - ticket.created_at,
                )
                return None

            logger.debug(
                "ws_ticket_consumed",
                tenant_id=ticket.tenant_id,
                user_id=ticket.user_id,
            )
            return ticket

    def pending_count(self) -> int:
        """Number of pending (non-expired) tickets."""
        with self._lock:
            self._purge_expired()
            return len(self._tickets)

    def _purge_expired(self) -> None:
        """Remove expired tickets (called under lock)."""
        now = time.time()
        expired = [k for k, v in self._tickets.items() if now - v.created_at > TICKET_TTL_SECONDS]
        for k in expired:
            del self._tickets[k]
