# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Agent Identity Hierarchy Service.

Management API for Level 0–4 identity hierarchy per agent.
Supports upgrade/downgrade paths and integrates with trust scoring (AS5).

Identity Levels:
  0 — None:      No identity binding
  1 — Software:  Software key in file
  2 — OS:        OS keystore (Keychain, CNG)
  3 — Hardware:  TPM / Secure Enclave backed
  4 — Attested:  Hardware + remote attestation verified
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Validation ────────────────────────────────────────────────────────────────

_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9_.:\-]{1,256}$")
_TENANT_ID_RE = re.compile(r"^[a-zA-Z0-9_.:\-]{1,128}$")

def _validate_agent_id(agent_id: str) -> str:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(f"Invalid agent_id format: {agent_id!r}")
    return agent_id

def _validate_tenant_id(tenant_id: str) -> str:
    if not _TENANT_ID_RE.match(tenant_id):
        raise ValueError(f"Invalid tenant_id format: {tenant_id!r}")
    return tenant_id

# ── Identity Level ────────────────────────────────────────────────────────────

class IdentityLevel(IntEnum):
    NONE = 0
    SOFTWARE = 1
    OS = 2
    HARDWARE = 3
    ATTESTED = 4

# Trust score boost per identity level (AS5)
_LEVEL_TRUST_BOOST: dict[IdentityLevel, float] = {
    IdentityLevel.NONE: 0.0,
    IdentityLevel.SOFTWARE: 0.05,
    IdentityLevel.OS: 0.10,
    IdentityLevel.HARDWARE: 0.20,
    IdentityLevel.ATTESTED: 0.30,
}

# Upgrade paths: allowed transitions (from → set of valid targets)
_UPGRADE_PATHS: dict[IdentityLevel, set[IdentityLevel]] = {
    IdentityLevel.NONE: {IdentityLevel.SOFTWARE, IdentityLevel.OS, IdentityLevel.HARDWARE},
    IdentityLevel.SOFTWARE: {IdentityLevel.OS, IdentityLevel.HARDWARE},
    IdentityLevel.OS: {IdentityLevel.HARDWARE},
    IdentityLevel.HARDWARE: {IdentityLevel.ATTESTED},
    IdentityLevel.ATTESTED: set(),  # already maximum
}

# Downgrade always allowed to any lower level

# ── Agent Identity Record ─────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    """Identity record for a single agent."""

    agent_id: str
    tenant_id: str
    level: IdentityLevel = IdentityLevel.NONE
    backend: str = ""  # "tpm2", "enclave", "software", ""
    public_key_hex: str = ""
    attestation_time: str | None = None
    last_verified: str | None = None
    created_at: str = ""
    updated_at: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def trust_boost(self) -> float:
        return _LEVEL_TRUST_BOOST.get(self.level, 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "level": self.level.value,
            "level_name": self.level.name.lower(),
            "backend": self.backend,
            "public_key_hex": self.public_key_hex[:32] + "..."
            if len(self.public_key_hex) > 32
            else self.public_key_hex,
            "trust_boost": self.trust_boost,
            "attestation_time": self.attestation_time,
            "last_verified": self.last_verified,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

# ── Identity Store (in-memory, per-tenant) ────────────────────────────────────

_store: dict[str, dict[str, AgentIdentity]] = {}

def _tenant_store(tenant_id: str) -> dict[str, AgentIdentity]:
    if tenant_id not in _store:
        _store[tenant_id] = {}
    return _store[tenant_id]

def clear_store() -> None:
    """Clear entire store (for testing only)."""
    _store.clear()

# ── CRUD operations ───────────────────────────────────────────────────────────

def register_agent(
    tenant_id: str,
    agent_id: str,
    level: IdentityLevel = IdentityLevel.NONE,
    backend: str = "",
    public_key_hex: str = "",
) -> AgentIdentity:
    """Register a new agent identity or update an existing one."""
    tenant_id = _validate_tenant_id(tenant_id)
    agent_id = _validate_agent_id(agent_id)
    now = datetime.now(UTC).isoformat()

    store = _tenant_store(tenant_id)
    existing = store.get(agent_id)
    if existing is not None:
        existing.level = level
        existing.backend = backend
        existing.public_key_hex = public_key_hex
        existing.updated_at = now
        existing.history.append({"action": "re-register", "level": level.value, "at": now})
        logger.info("agent_identity_updated", agent_id=agent_id, level=level.value)
        return existing

    ident = AgentIdentity(
        agent_id=agent_id,
        tenant_id=tenant_id,
        level=level,
        backend=backend,
        public_key_hex=public_key_hex,
        created_at=now,
        updated_at=now,
    )
    ident.history.append({"action": "register", "level": level.value, "at": now})
    store[agent_id] = ident
    logger.info("agent_identity_registered", agent_id=agent_id, level=level.value)
    return ident

def get_identity(tenant_id: str, agent_id: str) -> AgentIdentity | None:
    """Get the identity record for an agent."""
    tenant_id = _validate_tenant_id(tenant_id)
    agent_id = _validate_agent_id(agent_id)
    return _tenant_store(tenant_id).get(agent_id)

def list_identities(tenant_id: str) -> list[AgentIdentity]:
    """List all agent identities for a tenant."""
    tenant_id = _validate_tenant_id(tenant_id)
    return list(_tenant_store(tenant_id).values())

def delete_identity(tenant_id: str, agent_id: str) -> bool:
    """Remove an agent identity."""
    tenant_id = _validate_tenant_id(tenant_id)
    agent_id = _validate_agent_id(agent_id)
    store = _tenant_store(tenant_id)
    if agent_id in store:
        del store[agent_id]
        logger.info("agent_identity_deleted", agent_id=agent_id)
        return True
    return False

# ── Upgrade / Downgrade ───────────────────────────────────────────────────────

def upgrade_identity(
    tenant_id: str,
    agent_id: str,
    target_level: IdentityLevel,
    backend: str = "",
    public_key_hex: str = "",
) -> AgentIdentity:
    """Upgrade an agent's identity level.

    Raises ValueError if the transition is not in the allowed upgrade path.
    """
    tenant_id = _validate_tenant_id(tenant_id)
    agent_id = _validate_agent_id(agent_id)
    ident = _tenant_store(tenant_id).get(agent_id)
    if ident is None:
        raise ValueError(f"Agent {agent_id} not registered")

    if target_level <= ident.level:
        raise ValueError(f"Cannot upgrade from {ident.level.name} to {target_level.name} (target must be higher)")

    allowed = _UPGRADE_PATHS.get(ident.level, set())
    if target_level not in allowed:
        raise ValueError(
            f"Upgrade from {ident.level.name} to {target_level.name} not allowed. "
            f"Allowed targets: {sorted(l.name for l in allowed)}"
        )

    now = datetime.now(UTC).isoformat()
    old_level = ident.level
    ident.level = target_level
    if backend:
        ident.backend = backend
    if public_key_hex:
        ident.public_key_hex = public_key_hex
    if target_level == IdentityLevel.ATTESTED:
        ident.attestation_time = now
    ident.updated_at = now
    ident.history.append(
        {
            "action": "upgrade",
            "from": old_level.value,
            "to": target_level.value,
            "at": now,
        }
    )

    logger.info(
        "agent_identity_upgraded",
        agent_id=agent_id,
        from_level=old_level.value,
        to_level=target_level.value,
    )
    return ident

def downgrade_identity(
    tenant_id: str,
    agent_id: str,
    target_level: IdentityLevel,
    reason: str = "",
) -> AgentIdentity:
    """Downgrade an agent's identity level (always allowed to lower levels)."""
    tenant_id = _validate_tenant_id(tenant_id)
    agent_id = _validate_agent_id(agent_id)
    ident = _tenant_store(tenant_id).get(agent_id)
    if ident is None:
        raise ValueError(f"Agent {agent_id} not registered")

    if target_level >= ident.level:
        raise ValueError(f"Cannot downgrade from {ident.level.name} to {target_level.name} (target must be lower)")

    now = datetime.now(UTC).isoformat()
    old_level = ident.level
    ident.level = target_level
    if target_level < IdentityLevel.ATTESTED:
        ident.attestation_time = None
    ident.updated_at = now
    ident.history.append(
        {
            "action": "downgrade",
            "from": old_level.value,
            "to": target_level.value,
            "reason": reason,
            "at": now,
        }
    )

    logger.info(
        "agent_identity_downgraded",
        agent_id=agent_id,
        from_level=old_level.value,
        to_level=target_level.value,
        reason=reason,
    )
    return ident

def record_verification(tenant_id: str, agent_id: str) -> AgentIdentity | None:
    """Record a successful attestation verification timestamp."""
    tenant_id = _validate_tenant_id(tenant_id)
    agent_id = _validate_agent_id(agent_id)
    ident = _tenant_store(tenant_id).get(agent_id)
    if ident is None:
        return None
    ident.last_verified = datetime.now(UTC).isoformat()
    return ident

# ── Trust scoring integration (AS5) ──────────────────────────────────────────

def get_trust_boost(tenant_id: str, agent_id: str) -> float:
    """Get the trust score boost for an agent based on its identity level.

    Returns 0.0 if agent is not registered.
    Used by the ML trust scoring pipeline to incorporate hardware identity.
    """
    try:
        ident = get_identity(tenant_id, agent_id)
    except ValueError:
        return 0.0
    if ident is None:
        return 0.0
    return ident.trust_boost

def compute_identity_features(tenant_id: str, agent_id: str) -> dict[str, float]:
    """Compute identity-related features for the ML pipeline.

    Returns feature dict compatible with the trust feature registry.
    """
    try:
        ident = get_identity(tenant_id, agent_id)
    except ValueError:
        ident = None

    if ident is None:
        return {
            "identity_level": 0.0,
            "identity_is_hardware": 0.0,
            "identity_is_attested": 0.0,
            "identity_trust_boost": 0.0,
        }

    return {
        "identity_level": float(ident.level.value),
        "identity_is_hardware": 1.0 if ident.level >= IdentityLevel.HARDWARE else 0.0,
        "identity_is_attested": 1.0 if ident.level == IdentityLevel.ATTESTED else 0.0,
        "identity_trust_boost": ident.trust_boost,
    }
