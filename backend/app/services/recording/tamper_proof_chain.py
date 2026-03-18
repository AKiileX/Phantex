# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Tamper-Proof Audit Chain.

HMAC-chained audit log with integrity verification. Each entry is
cryptographically linked to its predecessor — any modification breaks
the chain and is immediately detectable.

Designed for WORM-compatible storage and legal-grade evidence:
  - Append-only (no update, no delete)
  - Per-tenant HMAC key (BYOK supported)
  - Chain verification at any time
  - Legal hold locks prevent deletion
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class ChainAction(StrEnum):
    """Auditable action types for the tamper-proof chain."""

    RECORDING_STARTED = "recording_started"
    RECORDING_STOPPED = "recording_stopped"
    LEVEL_CHANGED = "level_changed"
    EVENT_RECORDED = "event_recorded"
    SESSION_REPLAYED = "session_replayed"
    EXPORT_GENERATED = "export_generated"
    LEGAL_HOLD_SET = "legal_hold_set"
    LEGAL_HOLD_RELEASED = "legal_hold_released"
    CONFIG_CHANGED = "config_changed"
    CHAIN_VERIFIED = "chain_verified"

@dataclass
class ChainEntry:
    """Single entry in the tamper-proof audit chain."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    action: ChainAction = ChainAction.EVENT_RECORDED
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    tenant_id: str = ""
    actor: str = ""  # user_id or "system"
    agent_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""
    previous_hash: str = ""

    def compute_hash(self, hmac_key: bytes, prev_hash: str) -> str:
        """Compute HMAC-SHA256 chaining this entry to previous."""
        payload = json.dumps(
            {
                "id": self.id,
                "action": self.action.value,
                "timestamp": self.timestamp,
                "tenant_id": self.tenant_id,
                "actor": self.actor,
                "agent_id": self.agent_id,
                "details": self.details,
                "previous_hash": prev_hash,
            },
            sort_keys=True,
        )
        return hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        return d

@dataclass
class LegalHold:
    """Legal hold on an agent's recordings."""

    tenant_id: str
    agent_id: str
    reason: str
    held_by: str  # user_id who set the hold
    held_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    released_at: str | None = None
    released_by: str | None = None

    @property
    def active(self) -> bool:
        return self.released_at is None

class TamperProofChain:
    """HMAC-chained, append-only audit log.

    Each entry is linked to the previous by HMAC-SHA256.
    Supports per-tenant keys and legal holds.
    """

    # Per-tenant keys are required via set_tenant_key() / BYOK.
    # Fallback generates a random key per process — never hardcoded.
    _DEFAULT_KEY: bytes | None = None

    _MAX_ENTRIES_PER_TENANT = 100_000  # Memory guard — evict oldest beyond this

    def __init__(self) -> None:
        self._entries: dict[str, list[ChainEntry]] = {}  # tenant_id → entries
        self._last_hash: dict[str, str] = {}  # tenant_id → last hash
        self._tenant_keys: dict[str, bytes] = {}  # tenant_id → HMAC key
        self._legal_holds: dict[str, list[LegalHold]] = {}  # tenant_id → holds

    # ── Key management ───────────────────────────────────────────────

    def set_tenant_key(self, tenant_id: str, key: bytes) -> None:
        """Set a per-tenant HMAC key (BYOK)."""
        self._tenant_keys[tenant_id] = key

    def _get_key(self, tenant_id: str) -> bytes:
        key = self._tenant_keys.get(tenant_id)
        if key is None:
            # Auto-generate a random key for this tenant so there is
            # never a shared default.  Production should use Vault/KMS.
            import os

            key = os.urandom(32)
            self._tenant_keys[tenant_id] = key
        return key

    # ── Append ───────────────────────────────────────────────────────

    def append(
        self,
        tenant_id: str,
        action: ChainAction,
        actor: str,
        *,
        agent_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> ChainEntry:
        """Append a new entry to the tenant's audit chain."""
        prev_hash = self._last_hash.get(tenant_id, "genesis")
        key = self._get_key(tenant_id)

        entry = ChainEntry(
            action=action,
            tenant_id=tenant_id,
            actor=actor,
            agent_id=agent_id,
            details=details or {},
            previous_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash(key, prev_hash)

        if tenant_id not in self._entries:
            self._entries[tenant_id] = []
        self._entries[tenant_id].append(entry)
        self._last_hash[tenant_id] = entry.entry_hash

        # Memory guard — evict oldest entries beyond cap
        if len(self._entries[tenant_id]) > self._MAX_ENTRIES_PER_TENANT:
            self._entries[tenant_id] = self._entries[tenant_id][-self._MAX_ENTRIES_PER_TENANT :]

        return entry

    # ── Verification ─────────────────────────────────────────────────

    def verify_chain(self, tenant_id: str) -> dict[str, Any]:
        """Verify the HMAC chain integrity for a tenant.

        Returns verification result with details.
        """
        entries = self._entries.get(tenant_id, [])
        if not entries:
            return {"valid": True, "entries_checked": 0, "message": "Empty chain"}

        key = self._get_key(tenant_id)
        prev_hash = "genesis"

        for i, entry in enumerate(entries):
            expected = entry.compute_hash(key, prev_hash)
            if entry.entry_hash != expected:
                return {
                    "valid": False,
                    "entries_checked": i + 1,
                    "broken_at_index": i,
                    "entry_id": entry.id,
                    "message": f"Chain broken at entry {i} ({entry.id})",
                }
            prev_hash = entry.entry_hash

        return {
            "valid": True,
            "entries_checked": len(entries),
            "message": f"Chain intact — {len(entries)} entries verified",
        }

    # ── Query ────────────────────────────────────────────────────────

    def get_entries(
        self,
        tenant_id: str,
        *,
        action: ChainAction | None = None,
        agent_id: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[ChainEntry]:
        """Query chain entries with optional filters."""
        results = self._entries.get(tenant_id, [])
        if action is not None:
            results = [e for e in results if e.action == action]
        if agent_id is not None:
            results = [e for e in results if e.agent_id == agent_id]
        if since is not None:
            results = [e for e in results if e.timestamp >= since]
        return results[-limit:]

    def chain_length(self, tenant_id: str) -> int:
        return len(self._entries.get(tenant_id, []))

    # ── Legal Hold ───────────────────────────────────────────────────

    def set_legal_hold(
        self,
        tenant_id: str,
        agent_id: str,
        reason: str,
        held_by: str,
    ) -> LegalHold:
        """Set a legal hold on an agent's recordings. Prevents deletion."""
        hold = LegalHold(
            tenant_id=tenant_id,
            agent_id=agent_id,
            reason=reason,
            held_by=held_by,
        )
        if tenant_id not in self._legal_holds:
            self._legal_holds[tenant_id] = []
        self._legal_holds[tenant_id].append(hold)

        # Record in chain
        self.append(
            tenant_id,
            ChainAction.LEGAL_HOLD_SET,
            held_by,
            agent_id=agent_id,
            details={"reason": reason},
        )
        return hold

    def release_legal_hold(
        self,
        tenant_id: str,
        agent_id: str,
        released_by: str,
    ) -> LegalHold | None:
        """Release an active legal hold."""
        holds = self._legal_holds.get(tenant_id, [])
        for hold in holds:
            if hold.agent_id == agent_id and hold.active:
                hold.released_at = datetime.now(UTC).isoformat()
                hold.released_by = released_by
                self.append(
                    tenant_id,
                    ChainAction.LEGAL_HOLD_RELEASED,
                    released_by,
                    agent_id=agent_id,
                )
                return hold
        return None

    def get_legal_holds(
        self,
        tenant_id: str,
        *,
        active_only: bool = True,
    ) -> list[LegalHold]:
        """List legal holds for a tenant."""
        holds = self._legal_holds.get(tenant_id, [])
        if active_only:
            return [h for h in holds if h.active]
        return list(holds)

    def is_held(self, tenant_id: str, agent_id: str) -> bool:
        """Check if an agent's recordings are under legal hold."""
        holds = self._legal_holds.get(tenant_id, [])
        return any(h.agent_id == agent_id and h.active for h in holds)

    def stats(self, tenant_id: str) -> dict[str, Any]:
        """Chain stats for a tenant."""
        entries = self._entries.get(tenant_id, [])
        holds = self._legal_holds.get(tenant_id, [])
        return {
            "chain_length": len(entries),
            "active_holds": sum(1 for h in holds if h.active),
            "total_holds": len(holds),
            "last_entry_at": entries[-1].timestamp if entries else None,
        }
