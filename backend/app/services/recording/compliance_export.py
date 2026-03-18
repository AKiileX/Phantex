# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Compliance Export.

Generates evidence packages for compliance frameworks:
  - ISO 27001 — information security management controls
  - SOC 2 — Trust Services Criteria
  - HIPAA — PHI access logging and safeguards
  - FedRAMP — federal risk authorization

Each export includes:
  - Chain integrity verification result
  - Filtered audit entries for the requested period
  - Recording configuration at time of export
  - Legal hold status
  - Summary statistics
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.services.recording.session_recorder import SessionRecorder
from app.services.recording.tamper_proof_chain import ChainAction, TamperProofChain

class ComplianceFramework(StrEnum):
    """Supported compliance frameworks."""

    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    FEDRAMP = "fedramp"

# Mapping: framework → relevant chain actions to include in export
_FRAMEWORK_ACTIONS: dict[ComplianceFramework, list[ChainAction] | None] = {
    ComplianceFramework.ISO_27001: None,  # All actions relevant
    ComplianceFramework.SOC2: None,
    ComplianceFramework.HIPAA: [
        ChainAction.EVENT_RECORDED,
        ChainAction.LEGAL_HOLD_SET,
        ChainAction.LEGAL_HOLD_RELEASED,
        ChainAction.EXPORT_GENERATED,
    ],
    ComplianceFramework.FEDRAMP: None,
}

@dataclass
class ExportPackage:
    """A compliance evidence package."""

    export_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tenant_id: str = ""
    framework: ComplianceFramework = ComplianceFramework.ISO_27001
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    generated_by: str = ""
    period_start: str | None = None
    period_end: str | None = None

    chain_verification: dict[str, Any] = field(default_factory=dict)
    recording_configs: list[dict[str, Any]] = field(default_factory=list)
    legal_holds: list[dict[str, Any]] = field(default_factory=list)
    audit_entries: list[dict[str, Any]] = field(default_factory=list)
    recording_stats: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "export_id": self.export_id,
            "tenant_id": self.tenant_id,
            "framework": self.framework.value,
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "chain_verification": self.chain_verification,
            "recording_configs": self.recording_configs,
            "legal_holds": self.legal_holds,
            "audit_entry_count": len(self.audit_entries),
            "recording_stats": self.recording_stats,
            "summary": self.summary,
        }

    def to_json(self) -> str:
        """Full JSON export including all entries."""
        full = self.to_dict()
        full["audit_entries"] = self.audit_entries
        return json.dumps(full, indent=2, default=str)

class ComplianceExporter:
    """Generates compliance evidence packages from audit data.

    Combines chain verification, recording configs, legal holds,
    and filtered audit entries into framework-specific exports.
    """

    def __init__(
        self,
        chain: TamperProofChain,
        recorder: SessionRecorder,
    ) -> None:
        self._chain = chain
        self._recorder = recorder
        self._exports: list[ExportPackage] = []
        self._max_exports = 5_000  # Memory guard

    def generate(
        self,
        tenant_id: str,
        framework: ComplianceFramework,
        generated_by: str,
        *,
        period_start: str | None = None,
        period_end: str | None = None,
    ) -> ExportPackage:
        """Generate a compliance evidence package.

        Args:
            tenant_id: Tenant to export for.
            framework: Target compliance framework.
            generated_by: User ID who triggered the export.
            period_start: ISO timestamp — filter entries from this time.
            period_end: ISO timestamp — filter entries until this time.
        """
        # 1. Verify chain integrity
        verification = self._chain.verify_chain(tenant_id)

        # 2. Get recording configs
        configs = self._recorder.get_configs(tenant_id)
        config_dicts = [
            {
                "tenant_id": c.tenant_id,
                "agent_id": c.agent_id,
                "level": c.level.value,
                "enabled": c.enabled,
            }
            for c in configs
        ]

        # 3. Get legal holds (all — active and released)
        holds = self._chain.get_legal_holds(tenant_id, active_only=False)
        hold_dicts = [
            {
                "agent_id": h.agent_id,
                "reason": h.reason,
                "held_by": h.held_by,
                "held_at": h.held_at,
                "released_at": h.released_at,
                "released_by": h.released_by,
                "active": h.active,
            }
            for h in holds
        ]

        # 4. Get audit entries (framework-filtered, capped at 5000)
        allowed_actions = _FRAMEWORK_ACTIONS.get(framework)
        entries = self._chain.get_entries(
            tenant_id,
            since=period_start,
            limit=5000,
        )
        if period_end:
            entries = [e for e in entries if e.timestamp <= period_end]
        if allowed_actions:
            entries = [e for e in entries if e.action in allowed_actions]

        entry_dicts = [e.to_dict() for e in entries]

        # 5. Get recording stats
        rec_stats = self._recorder.stats(tenant_id)
        chain_stats = self._chain.stats(tenant_id)

        # 6. Build summary
        summary = {
            "framework": framework.value,
            "chain_intact": verification.get("valid", False),
            "entries_in_period": len(entry_dicts),
            "active_legal_holds": sum(1 for h in holds if h.active),
            "recording_configs": len(config_dicts),
            "total_recorded_events": rec_stats.get("total_events", 0),
            "chain_length": chain_stats.get("chain_length", 0),
        }

        # 7. Record the export in the chain
        self._chain.append(
            tenant_id,
            ChainAction.EXPORT_GENERATED,
            generated_by,
            details={
                "framework": framework.value,
                "period_start": period_start,
                "period_end": period_end,
                "entries_exported": len(entry_dicts),
            },
        )

        package = ExportPackage(
            tenant_id=tenant_id,
            framework=framework,
            generated_at=datetime.now(UTC).isoformat(),
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
            chain_verification=verification,
            recording_configs=config_dicts,
            legal_holds=hold_dicts,
            audit_entries=entry_dicts,
            recording_stats=rec_stats,
            summary=summary,
        )
        self._exports.append(package)

        # Memory guard — evict oldest exports beyond cap
        if len(self._exports) > self._max_exports:
            self._exports = self._exports[-self._max_exports :]

        return package

    def list_exports(self, tenant_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """List generated exports for a tenant (metadata only)."""
        return [e.to_dict() for e in self._exports if e.tenant_id == tenant_id][-limit:]
