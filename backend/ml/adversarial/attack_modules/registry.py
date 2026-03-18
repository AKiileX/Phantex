# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Attack Module Registry.

Central registry that maps attack class numbers (1-14) to their
module implementations and enables batch execution.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from ml.adversarial.attack_modules.base import (
    BaseAttackModule,
    ModuleReport,
)
from ml.adversarial.attack_modules.m01_direct_prompt_injection import DirectPromptInjection
from ml.adversarial.attack_modules.m02_indirect_prompt_injection import IndirectPromptInjection
from ml.adversarial.attack_modules.m03_lateral_movement import AgentLateralMovement
from ml.adversarial.attack_modules.m04_tool_poisoning import ToolPoisoning
from ml.adversarial.attack_modules.m05_mcp_supply_chain import MCPSupplyChain
from ml.adversarial.attack_modules.m06_data_exfiltration import DataExfiltration
from ml.adversarial.attack_modules.m07_agent_impersonation import AgentImpersonation
from ml.adversarial.attack_modules.m08_privilege_escalation import PrivilegeEscalation
from ml.adversarial.attack_modules.m09_memory_poisoning import MemoryPoisoning
from ml.adversarial.attack_modules.m10_model_extraction import ModelExtraction
from ml.adversarial.attack_modules.m11_denial_of_service import DenialOfService
from ml.adversarial.attack_modules.m12_compliance_violation import ComplianceViolation
from ml.adversarial.attack_modules.m13_credential_theft import CredentialTheft
from ml.adversarial.attack_modules.m14_supply_chain_deps import SupplyChainDeps

logger = structlog.get_logger(__name__)

_ALL_MODULES: list[type[BaseAttackModule]] = [
    DirectPromptInjection,  # 1
    IndirectPromptInjection,  # 2
    AgentLateralMovement,  # 3
    ToolPoisoning,  # 4
    MCPSupplyChain,  # 5
    DataExfiltration,  # 6
    AgentImpersonation,  # 7
    PrivilegeEscalation,  # 8
    MemoryPoisoning,  # 9
    ModelExtraction,  # 10
    DenialOfService,  # 11
    ComplianceViolation,  # 12
    CredentialTheft,  # 13
    SupplyChainDeps,  # 14
]

@dataclass
class CampaignReport:
    """Full red-team campaign report covering all 14 attack classes."""

    campaign_id: str
    tenant_id: str
    agent_id: str
    started_at: str = ""
    completed_at: str = ""
    duration_ms: float = 0.0
    module_reports: list[ModuleReport] = field(default_factory=list)

    @property
    def overall_score(self) -> float:
        if not self.module_reports:
            return 100.0
        return sum(r.score for r in self.module_reports) / len(self.module_reports)

    @property
    def overall_detection_rate(self) -> float:
        total = sum(r.total_payloads for r in self.module_reports)
        if total == 0:
            return 0.0
        detected = sum(r.detected + r.blocked for r in self.module_reports)
        return detected / total

    @property
    def grade(self) -> str:
        s = self.overall_score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 50:
            return "C"
        if s >= 25:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": round(self.duration_ms, 2),
            "overall_score": round(self.overall_score, 1),
            "overall_detection_rate": round(self.overall_detection_rate, 4),
            "grade": self.grade,
            "module_reports": [r.to_dict() for r in self.module_reports],
        }

class AttackModuleRegistry:
    """Registry of all 14 attack modules with batch execution."""

    def __init__(self) -> None:
        self._modules: dict[int, BaseAttackModule] = {}
        for cls in _ALL_MODULES:
            inst = cls()
            self._modules[inst.attack_class] = inst

    def get_module(self, attack_class: int) -> BaseAttackModule | None:
        return self._modules.get(attack_class)

    def list_modules(self) -> list[dict[str, Any]]:
        return [
            {
                "attack_class": m.attack_class,
                "name": m.attack_class_name,
                "description": m.description,
            }
            for m in sorted(self._modules.values(), key=lambda m: m.attack_class)
        ]

    async def run_single(
        self,
        attack_class: int,
        tenant_id: str,
        agent_id: str,
        config: dict[str, Any] | None = None,
    ) -> ModuleReport:
        module = self._modules.get(attack_class)
        if module is None:
            raise ValueError(f"Unknown attack class: {attack_class}")
        payloads = module.generate_payloads(agent_id, config or {})
        return await module.execute(tenant_id, agent_id, payloads)

    async def run_all(
        self,
        tenant_id: str,
        agent_id: str,
        config: dict[str, Any] | None = None,
        classes: list[int] | None = None,
    ) -> CampaignReport:
        """Run all (or selected) attack classes and return a campaign report."""
        import uuid

        target = classes or sorted(self._modules.keys())
        report = CampaignReport(
            campaign_id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            agent_id=agent_id,
            started_at=datetime.now(UTC).isoformat(),
        )

        t0 = time.monotonic()
        for cls_id in target:
            try:
                mr = await self.run_single(cls_id, tenant_id, agent_id, config)
                report.module_reports.append(mr)
            except Exception:
                logger.exception("attack_module_failed", attack_class=cls_id)

        report.duration_ms = (time.monotonic() - t0) * 1000
        report.completed_at = datetime.now(UTC).isoformat()
        return report
