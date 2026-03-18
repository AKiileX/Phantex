# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — A2A Agent Card Registry.

Stores and validates Google A2A Agent Cards.  An Agent Card is the
JSON metadata a remote agent publishes so others can discover its
capabilities, endpoint URL, and authentication requirements.

Features:
  - Register / update / revoke agent cards (tenant-scoped)
  - Validate card schema (name, url, capabilities, auth)
  - Detect capability changes (drift alerting)
  - Lookup by capability for delegation routing
  - Track verification status (verified / unverified / revoked)
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.a2a.registry")

class CardStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    REVOKED = "revoked"

_REQUIRED_CARD_FIELDS = {"name", "url", "capabilities"}

# Capabilities that require extra scrutiny
_SENSITIVE_CAPABILITIES = frozenset(
    {
        "admin",
        "database",
        "payment",
        "credentials",
        "file_write",
        "code_execution",
        "network_access",
        "secret_management",
        "user_management",
        "deployment",
        "infrastructure",
    }
)

@dataclass
class AgentCard:
    """Representation of an A2A Agent Card."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: str  # A2A agent identifier (from the card)
    name: str
    url: str  # Agent endpoint URL
    capabilities: list[str]
    auth_type: str = "none"  # none, bearer, mtls, oauth2
    description: str = ""
    version: str = "1.0"
    status: CardStatus = CardStatus.UNVERIFIED
    fingerprint: str = ""  # SHA-256 of canonical card JSON
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class CardValidationResult:
    """Result of validating an agent card."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sensitive_capabilities: list[str] = field(default_factory=list)

class AgentCardRegistry:
    """In-memory A2A Agent Card registry (tenant-isolated).

    Production: backed by PostgreSQL ``a2a_agent_cards`` table.
    """

    def __init__(self) -> None:
        # {tenant_id: {card_id: AgentCard}}
        self._cards: dict[uuid.UUID, dict[uuid.UUID, AgentCard]] = {}

    # ── Validation ────────────────────────────────────────────────────

    @staticmethod
    def validate_card(card_data: dict[str, Any]) -> CardValidationResult:
        """Validate an incoming Agent Card payload."""
        errors: list[str] = []
        warnings: list[str] = []

        # Required fields
        for f in _REQUIRED_CARD_FIELDS:
            if not card_data.get(f):
                errors.append(f"Missing required field: {f}")

        # URL format
        url = card_data.get("url", "")
        if url and not (url.startswith("https://") or url.startswith("http://localhost")):
            warnings.append("Agent URL should use HTTPS in production")

        # Capabilities
        caps = card_data.get("capabilities", [])
        if not isinstance(caps, list):
            errors.append("capabilities must be a list")
            caps = []

        if len(caps) == 0:
            warnings.append("Agent card declares no capabilities")

        if len(caps) > 50:
            errors.append("Too many capabilities declared (max 50)")

        sensitive = [c for c in caps if c in _SENSITIVE_CAPABILITIES]
        if sensitive:
            warnings.append(f"Sensitive capabilities declared: {sensitive}")

        # Auth
        auth = card_data.get("auth_type", "none")
        if auth == "none":
            warnings.append("No authentication configured — card is open")

        return CardValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sensitive_capabilities=sensitive,
        )

    # ── Registration ──────────────────────────────────────────────────

    def register(
        self,
        tenant_id: uuid.UUID,
        card_data: dict[str, Any],
        *,
        auto_verify: bool = False,
    ) -> tuple[AgentCard, CardValidationResult]:
        """Register a new agent card.  Returns (card, validation)."""
        validation = self.validate_card(card_data)
        if not validation.valid:
            raise ValueError(f"Invalid agent card: {validation.errors}")

        fingerprint = _compute_fingerprint(card_data)

        # Check for duplicate by agent_id within tenant
        existing = self._find_by_agent_id(tenant_id, card_data["name"])
        if existing:
            return self._update_existing(existing, card_data, fingerprint, validation)

        card = AgentCard(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            agent_id=card_data.get("agent_id", card_data["name"]),
            name=card_data["name"],
            url=card_data["url"],
            capabilities=card_data["capabilities"],
            auth_type=card_data.get("auth_type", "none"),
            description=card_data.get("description", ""),
            version=card_data.get("version", "1.0"),
            status=CardStatus.VERIFIED if auto_verify else CardStatus.UNVERIFIED,
            fingerprint=fingerprint,
            metadata=card_data.get("metadata", {}),
        )

        self._cards.setdefault(tenant_id, {})[card.id] = card
        logger.info(
            "a2a_card_registered",
            tenant_id=str(tenant_id),
            card_id=str(card.id),
            agent_id=card.agent_id,
            capabilities=card.capabilities,
            status=card.status.value,
        )
        return card, validation

    def _update_existing(
        self,
        existing: AgentCard,
        card_data: dict[str, Any],
        fingerprint: str,
        validation: CardValidationResult,
    ) -> tuple[AgentCard, CardValidationResult]:
        """Update an existing card, detecting capability drift."""
        old_caps = set(existing.capabilities)
        new_caps = set(card_data["capabilities"])
        added = new_caps - old_caps
        removed = old_caps - new_caps

        if added or removed:
            logger.warning(
                "a2a_card_capability_drift",
                card_id=str(existing.id),
                agent_id=existing.agent_id,
                added=list(added),
                removed=list(removed),
            )
            validation.warnings.append(f"Capability drift: added={list(added)}, removed={list(removed)}")

        if fingerprint != existing.fingerprint:
            existing.status = CardStatus.UNVERIFIED
            validation.warnings.append("Card content changed — status reset to unverified")

        existing.url = card_data["url"]
        existing.capabilities = card_data["capabilities"]
        existing.auth_type = card_data.get("auth_type", existing.auth_type)
        existing.description = card_data.get("description", existing.description)
        existing.version = card_data.get("version", existing.version)
        existing.fingerprint = fingerprint
        existing.updated_at = datetime.now(UTC)

        return existing, validation

    # ── Lookups ───────────────────────────────────────────────────────

    def get(self, tenant_id: uuid.UUID, card_id: uuid.UUID) -> AgentCard | None:
        return self._cards.get(tenant_id, {}).get(card_id)

    def get_by_agent_id(self, tenant_id: uuid.UUID, agent_id: str) -> AgentCard | None:
        return self._find_by_agent_id(tenant_id, agent_id)

    def list_cards(
        self,
        tenant_id: uuid.UUID,
        *,
        status: CardStatus | None = None,
        capability: str | None = None,
    ) -> list[AgentCard]:
        """List cards, optionally filtered by status or capability."""
        cards = list(self._cards.get(tenant_id, {}).values())
        if status:
            cards = [c for c in cards if c.status == status]
        if capability:
            cards = [c for c in cards if capability in c.capabilities]
        return cards

    def is_verified(self, tenant_id: uuid.UUID, agent_id: str) -> bool:
        """Check if an agent is in the verified registry."""
        card = self._find_by_agent_id(tenant_id, agent_id)
        return card is not None and card.status == CardStatus.VERIFIED

    # ── Status management ─────────────────────────────────────────────

    def verify(self, tenant_id: uuid.UUID, card_id: uuid.UUID) -> bool:
        card = self.get(tenant_id, card_id)
        if card and card.status != CardStatus.REVOKED:
            card.status = CardStatus.VERIFIED
            logger.info("a2a_card_verified", card_id=str(card_id))
            return True
        return False

    def revoke(self, tenant_id: uuid.UUID, card_id: uuid.UUID, reason: str = "") -> bool:
        card = self.get(tenant_id, card_id)
        if card:
            card.status = CardStatus.REVOKED
            logger.warning(
                "a2a_card_revoked",
                card_id=str(card_id),
                agent_id=card.agent_id,
                reason=reason,
            )
            return True
        return False

    # ── Stats ─────────────────────────────────────────────────────────

    def stats(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        cards = list(self._cards.get(tenant_id, {}).values())
        return {
            "total": len(cards),
            "verified": sum(1 for c in cards if c.status == CardStatus.VERIFIED),
            "unverified": sum(1 for c in cards if c.status == CardStatus.UNVERIFIED),
            "revoked": sum(1 for c in cards if c.status == CardStatus.REVOKED),
            "sensitive_count": sum(1 for c in cards if any(cap in _SENSITIVE_CAPABILITIES for cap in c.capabilities)),
        }

    # ── Internal ──────────────────────────────────────────────────────

    def _find_by_agent_id(self, tenant_id: uuid.UUID, agent_id: str) -> AgentCard | None:
        for card in self._cards.get(tenant_id, {}).values():
            if card.agent_id == agent_id or card.name == agent_id:
                return card
        return None

def _compute_fingerprint(card_data: dict[str, Any]) -> str:
    """SHA-256 of canonical card fields for drift detection."""
    import json

    canonical = json.dumps(
        {k: card_data.get(k) for k in sorted(_REQUIRED_CARD_FIELDS | {"auth_type", "version"})},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
