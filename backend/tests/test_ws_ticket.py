# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for backend/app/services/ws_ticket.py

Covers:
  - WSTicket: creation, is_expired property
  - WSTicketStore: create_ticket, consume_ticket (single-use),
    max_pending enforcement, expired ticket rejection,
    auto-purge, thread safety, pending_count
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from app.services.ws_ticket import (
    MAX_PENDING_TICKETS,
    TICKET_TTL_SECONDS,
    WSTicket,
    WSTicketStore,
)

# ── WSTicket ─────────────────────────────────────────────────────────────────

class TestWSTicket:
    def test_fresh_ticket_not_expired(self):
        t = WSTicket(ticket="abc", tenant_id="t-1", user_id="u-1", role="admin")
        assert t.is_expired is False

    def test_expired_ticket(self):
        t = WSTicket(
            ticket="abc",
            tenant_id="t-1",
            user_id="u-1",
            role="admin",
            created_at=time.time() - TICKET_TTL_SECONDS - 1,
        )
        assert t.is_expired is True

    def test_ticket_fields(self):
        t = WSTicket(ticket="xyz", tenant_id="t-2", user_id="u-2", role="viewer")
        assert t.ticket == "xyz"
        assert t.tenant_id == "t-2"
        assert t.user_id == "u-2"
        assert t.role == "viewer"

# ── WSTicketStore ────────────────────────────────────────────────────────────

class TestWSTicketStore:
    def test_create_and_consume(self):
        store = WSTicketStore()
        ticket_str = store.create_ticket("tenant-1", "user-1", "admin")

        assert isinstance(ticket_str, str)
        assert len(ticket_str) > 0

        result = store.consume_ticket(ticket_str)
        assert result is not None
        assert result.tenant_id == "tenant-1"
        assert result.user_id == "user-1"
        assert result.role == "admin"

    def test_consume_is_single_use(self):
        store = WSTicketStore()
        ticket_str = store.create_ticket("tenant-1", "user-1", "admin")

        first = store.consume_ticket(ticket_str)
        second = store.consume_ticket(ticket_str)

        assert first is not None
        assert second is None

    def test_consume_invalid_ticket(self):
        store = WSTicketStore()
        assert store.consume_ticket("nonexistent-ticket") is None

    def test_consume_expired_ticket(self):
        store = WSTicketStore()
        ticket_str = store.create_ticket("tenant-1", "user-1", "admin")

        # Manually expire the ticket
        store._tickets[ticket_str].created_at = time.time() - TICKET_TTL_SECONDS - 1

        result = store.consume_ticket(ticket_str)
        assert result is None

    def test_max_pending_enforcement(self):
        store = WSTicketStore()

        # Fill up to MAX_PENDING_TICKETS
        with patch("app.services.ws_ticket.MAX_PENDING_TICKETS", 3):
            # Monkey-patch: WSTicketStore reads the constant at call time
            # We need to test the store's own check
            pass

        # Direct test: fill the store to its limit
        store._tickets = {
            f"ticket-{i}": WSTicket(
                ticket=f"ticket-{i}",
                tenant_id="t",
                user_id="u",
                role="admin",
            )
            for i in range(MAX_PENDING_TICKETS)
        }

        with pytest.raises(RuntimeError, match="Too many pending"):
            store.create_ticket("tenant-1", "user-1", "admin")

    def test_pending_count(self):
        store = WSTicketStore()
        assert store.pending_count() == 0

        store.create_ticket("t-1", "u-1", "admin")
        assert store.pending_count() == 1

        store.create_ticket("t-1", "u-2", "viewer")
        assert store.pending_count() == 2

    def test_pending_count_excludes_expired(self):
        store = WSTicketStore()
        ticket_str = store.create_ticket("t-1", "u-1", "admin")

        # Expire the ticket
        store._tickets[ticket_str].created_at = time.time() - TICKET_TTL_SECONDS - 1

        assert store.pending_count() == 0  # purged by pending_count()

    def test_purge_expired_removes_old_tickets(self):
        store = WSTicketStore()
        t1 = store.create_ticket("t-1", "u-1", "admin")
        t2 = store.create_ticket("t-1", "u-2", "viewer")

        # Expire t1
        store._tickets[t1].created_at = time.time() - TICKET_TTL_SECONDS - 1

        # t2 should still be valid
        assert store.consume_ticket(t2) is not None
        # t1 is gone (purged during consume operation)
        assert t1 not in store._tickets

    def test_tickets_are_unique(self):
        store = WSTicketStore()
        tickets = set()
        for _ in range(100):
            t = store.create_ticket("t-1", "u-1", "admin")
            tickets.add(t)
        assert len(tickets) == 100  # all unique

    def test_thread_safety(self):
        """Verify the store handles concurrent access (basic)."""
        import concurrent.futures

        store = WSTicketStore()

        def create_and_consume():
            t = store.create_ticket("t-1", "u-1", "admin")
            result = store.consume_ticket(t)
            return result is not None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_and_consume) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert all(results)
        assert store.pending_count() == 0
