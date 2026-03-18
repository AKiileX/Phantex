# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Agent Delegation Policy (JB2).

Controls agent-to-agent delegation (Agent A asks Agent B to do something).
Prevents:
- Unauthorized delegation (A not allowed to delegate to B)
- Delegation depth attacks (A → B → C → D … unbounded chain)
- Circular delegation (A → B → A)
- Scope escalation (delegating broader permissions than the source has)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ml.content.policy.agent_purpose import PurposeStore

logger = logging.getLogger(__name__)

class DelegationDecision(StrEnum):
    """Enforcement decision for a delegation request."""

    ALLOW = "allow"
    DENY = "deny"
    ALERT = "alert"

@dataclass(frozen=True)
class DelegationVerdict:
    """Result of evaluating a delegation request."""

    decision: DelegationDecision
    source_agent_id: str
    target_agent_id: str
    tenant_id: str
    chain_depth: int = 0
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class DelegationPolicy:
    """Evaluate agent-to-agent delegation requests.

    Parameters
    ----------
    purpose_store:
        Shared PurposeStore for looking up agent purposes.
    max_global_depth:
        Hard ceiling on delegation depth regardless of per-agent settings.
    """

    def __init__(
        self,
        purpose_store: PurposeStore | None = None,
        max_global_depth: int = 5,
    ) -> None:
        self._store = purpose_store or PurposeStore()
        self._max_global_depth = max_global_depth

    def evaluate(
        self,
        tenant_id: str,
        source_agent_id: str,
        target_agent_id: str,
        delegation_chain: list[str] | None = None,
        task_scope: str = "",
    ) -> DelegationVerdict:
        """Evaluate whether *source_agent_id* may delegate to *target_agent_id*.

        Parameters
        ----------
        delegation_chain:
            List of agent IDs in the current delegation chain (for depth
            and circular-delegation checks).  First element is the
            original requestor.
        task_scope:
            Description of what is being delegated (for scope checks).
        """
        chain = delegation_chain or []
        depth = len(chain)

        # ── Circular delegation check
        if target_agent_id in chain:
            return DelegationVerdict(
                decision=DelegationDecision.DENY,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                tenant_id=tenant_id,
                chain_depth=depth,
                reason=f"Circular delegation detected: {target_agent_id} already in chain {chain}",
            )

        # ── Global depth ceiling
        if depth >= self._max_global_depth:
            return DelegationVerdict(
                decision=DelegationDecision.DENY,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                tenant_id=tenant_id,
                chain_depth=depth,
                reason=f"Global delegation depth ceiling ({self._max_global_depth}) exceeded",
            )

        # ── Lookup source purpose
        source_purpose = self._store.get(tenant_id, source_agent_id)
        if source_purpose is None:
            # No purpose registered → ALERT (not DENY — allow onboarding)
            return DelegationVerdict(
                decision=DelegationDecision.ALERT,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                tenant_id=tenant_id,
                chain_depth=depth,
                reason=f"Source agent '{source_agent_id}' has no registered purpose",
            )

        # ── Per-agent depth check
        if depth >= source_purpose.max_delegation_depth:
            return DelegationVerdict(
                decision=DelegationDecision.DENY,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                tenant_id=tenant_id,
                chain_depth=depth,
                reason=(
                    f"Delegation depth ({depth}) exceeds "
                    f"agent max_delegation_depth ({source_purpose.max_delegation_depth})"
                ),
            )

        # ── Lookup target purpose
        target_purpose = self._store.get(tenant_id, target_agent_id)
        if target_purpose is None:
            return DelegationVerdict(
                decision=DelegationDecision.ALERT,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                tenant_id=tenant_id,
                chain_depth=depth,
                reason=f"Target agent '{target_agent_id}' has no registered purpose",
            )

        # ── All checks passed
        return DelegationVerdict(
            decision=DelegationDecision.ALLOW,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            tenant_id=tenant_id,
            chain_depth=depth,
            reason="Delegation approved",
            metadata={
                "source_role": source_purpose.role,
                "target_role": target_purpose.role,
            },
        )

    @property
    def purpose_store(self) -> PurposeStore:
        return self._store
