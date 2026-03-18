# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — MCP Server Registry (JB2).

Tracks MCP server trust levels and provides lookup for policy evaluation.
Trust levels: verified → known → unknown → suspicious → blocked.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class MCPTrustLevel(StrEnum):
    """Trust level for an MCP server."""

    VERIFIED = "verified"  # In Phantex registry, hash matches, behavior profiled
    KNOWN = "known"  # Seen before, no anomalies
    UNKNOWN = "unknown"  # First contact, never registered
    SUSPICIOUS = "suspicious"  # Behavioral anomaly detected
    BLOCKED = "blocked"  # Known malicious or admin-blocked

@dataclass(frozen=True)
class MCPServerEntry:
    """Registry entry for a known MCP server."""

    server_id: str  # Unique identifier or URL
    tenant_id: str
    trust_level: MCPTrustLevel = MCPTrustLevel.UNKNOWN
    display_name: str = ""
    description: str = ""
    content_hash: str = ""  # Hash of server manifest/config
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    connection_count: int = 0
    anomaly_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

class MCPServerRegistry:
    """Thread-safe, tenant-isolated registry of MCP server trust levels.

    Keyed by ``(tenant_id, server_id)``.
    """

    __slots__ = ("_lock", "_store", "_default_trust", "_max_entries")

    def __init__(
        self,
        default_trust: MCPTrustLevel = MCPTrustLevel.UNKNOWN,
        max_entries: int = 50_000,
    ) -> None:
        self._lock = threading.Lock()
        self._store: dict[tuple[str, str], MCPServerEntry] = {}
        self._default_trust = default_trust
        self._max_entries = max_entries

    # ── Registration ─────────────────────────────────────────────────

    def register(self, entry: MCPServerEntry) -> None:
        """Register or update an MCP server entry.

        Evicts oldest entry if store exceeds *max_entries*.
        """
        key = (entry.tenant_id, entry.server_id)
        with self._lock:
            self._store[key] = entry
            if len(self._store) > self._max_entries:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]

    def remove(self, tenant_id: str, server_id: str) -> bool:
        """Remove a server.  Returns True if it existed."""
        with self._lock:
            return self._store.pop((tenant_id, server_id), None) is not None

    # ── Lookup ───────────────────────────────────────────────────────

    def get(self, tenant_id: str, server_id: str) -> MCPServerEntry | None:
        """Return the entry for *server_id* within *tenant_id*, or ``None``."""
        with self._lock:
            return self._store.get((tenant_id, server_id))

    def trust_level(self, tenant_id: str, server_id: str) -> MCPTrustLevel:
        """Return trust level (defaults to ``UNKNOWN`` if not registered)."""
        entry = self.get(tenant_id, server_id)
        return entry.trust_level if entry else self._default_trust

    def list_for_tenant(self, tenant_id: str) -> list[MCPServerEntry]:
        """Return all server entries for a given tenant."""
        with self._lock:
            return [e for k, e in self._store.items() if k[0] == tenant_id]

    # ── Trust management ─────────────────────────────────────────────

    def set_trust_level(
        self,
        tenant_id: str,
        server_id: str,
        level: MCPTrustLevel,
    ) -> bool:
        """Update trust level for an existing entry.  Returns False if not found."""
        with self._lock:
            entry = self._store.get((tenant_id, server_id))
            if entry is None:
                return False
            # Frozen dataclass → replace
            updated = MCPServerEntry(
                server_id=entry.server_id,
                tenant_id=entry.tenant_id,
                trust_level=level,
                display_name=entry.display_name,
                description=entry.description,
                content_hash=entry.content_hash,
                first_seen=entry.first_seen,
                last_seen=datetime.now(UTC),
                connection_count=entry.connection_count,
                anomaly_count=entry.anomaly_count,
                metadata=entry.metadata,
            )
            self._store[(tenant_id, server_id)] = updated
            return True

    def block(self, tenant_id: str, server_id: str) -> bool:
        """Convenience: set trust to BLOCKED."""
        return self.set_trust_level(tenant_id, server_id, MCPTrustLevel.BLOCKED)

    def mark_suspicious(self, tenant_id: str, server_id: str) -> bool:
        """Convenience: set trust to SUSPICIOUS."""
        return self.set_trust_level(tenant_id, server_id, MCPTrustLevel.SUSPICIOUS)

    # ── Introspection ────────────────────────────────────────────────

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def __repr__(self) -> str:
        with self._lock:
            return f"MCPServerRegistry({len(self._store)} servers)"
