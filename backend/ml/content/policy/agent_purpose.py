# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Agent Purpose Model.

Defines ``AgentPurpose`` (what an agent is allowed to do) and
``PurposeStore`` (tenant-isolated, in-memory registry of purposes).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

@dataclass(frozen=True)
class AgentPurpose:
    """Declaration of what a specific agent is hired to do.

    This is the single source of truth for tool/MCP/data-scope policy
    evaluation.  It is registered by the admin (not self-modifiable by
    the agent) and keyed by ``(tenant_id, agent_id)``.
    """

    agent_id: str  # Phantex Agent ID (PAID)
    tenant_id: str
    role: str  # e.g. "document_summarizer"
    allowed_tools: tuple[str, ...] = ()  # Whitelist
    denied_tools: tuple[str, ...] = ()  # Blacklist (overrides allowed)
    allowed_mcp_servers: tuple[str, ...] = ()  # Known MCP server IDs / URL patterns
    data_scope: tuple[str, ...] = ()  # Data types agent may handle
    max_delegation_depth: int = 1  # Max agent → agent hops
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

class PurposeStore:
    """Thread-safe, tenant-isolated registry of AgentPurpose objects.

    Keyed by ``(tenant_id, agent_id)`` for strict isolation.
    Bounded to *max_entries* entries; oldest evicted on overflow.
    """

    __slots__ = ("_lock", "_store", "_max_entries")

    def __init__(self, max_entries: int = 50_000) -> None:
        self._lock = threading.Lock()
        self._store: dict[tuple[str, str], AgentPurpose] = {}
        self._max_entries = max_entries

    # ── CRUD ─────────────────────────────────────────────────────────

    def register(self, purpose: AgentPurpose) -> None:
        """Register or replace a purpose declaration.

        Replacement is intentional (purpose update flow).
        Evicts oldest entry if store exceeds *max_entries*.
        """
        key = (purpose.tenant_id, purpose.agent_id)
        with self._lock:
            self._store[key] = purpose
            if len(self._store) > self._max_entries:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]

    def get(self, tenant_id: str, agent_id: str) -> AgentPurpose | None:
        """Return the purpose for *agent_id* within *tenant_id*, or ``None``."""
        with self._lock:
            return self._store.get((tenant_id, agent_id))

    def remove(self, tenant_id: str, agent_id: str) -> bool:
        """Remove a purpose.  Returns True if it existed."""
        with self._lock:
            return self._store.pop((tenant_id, agent_id), None) is not None

    def list_for_tenant(self, tenant_id: str) -> list[AgentPurpose]:
        """Return all purposes for a given tenant."""
        with self._lock:
            return [p for k, p in self._store.items() if k[0] == tenant_id]

    # ── Introspection ────────────────────────────────────────────────

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def __contains__(self, key: tuple[str, str]) -> bool:
        with self._lock:
            return key in self._store

    def __repr__(self) -> str:
        with self._lock:
            return f"PurposeStore({len(self._store)} entries)"
