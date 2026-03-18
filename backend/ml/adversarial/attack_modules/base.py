# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Base Attack Module Interface.

All 14 attack class modules inherit from this base class.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class AttackSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AttackOutcome(StrEnum):
    DETECTED = "detected"
    BLOCKED = "blocked"
    EVADED = "evaded"
    PARTIAL = "partial"
    ERROR = "error"

@dataclass
class AttackPayload:
    """A single attack payload used in simulation."""

    payload_id: str
    name: str
    content: str
    severity: AttackSeverity
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class AttackResult:
    """Result of executing a single attack payload."""

    payload_id: str
    outcome: AttackOutcome
    detected_by: str = ""  # Which layer detected it (PRL rule, ML model, etc.)
    detection_time_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "outcome": self.outcome.value,
            "detected_by": self.detected_by,
            "detection_time_ms": round(self.detection_time_ms, 2),
            "details": self.details,
        }

@dataclass
class ModuleReport:
    """Aggregate report for an attack module execution."""

    module_id: str
    attack_class: int  # 1–14
    attack_class_name: str
    tenant_id: str
    agent_id: str
    total_payloads: int = 0
    detected: int = 0
    blocked: int = 0
    evaded: int = 0
    partial: int = 0
    errors: int = 0
    results: list[AttackResult] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    duration_ms: float = 0.0
    recommendations: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        if self.total_payloads == 0:
            return 0.0
        return (self.detected + self.blocked) / self.total_payloads

    @property
    def score(self) -> float:
        """0–100 resilience score for this attack class."""
        if self.total_payloads == 0:
            return 100.0
        evasion_rate = self.evaded / self.total_payloads
        return max(0.0, 100.0 * (1.0 - evasion_rate))

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "attack_class": self.attack_class,
            "attack_class_name": self.attack_class_name,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "total_payloads": self.total_payloads,
            "detected": self.detected,
            "blocked": self.blocked,
            "evaded": self.evaded,
            "partial": self.partial,
            "errors": self.errors,
            "detection_rate": round(self.detection_rate, 4),
            "score": round(self.score, 1),
            "duration_ms": round(self.duration_ms, 2),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "recommendations": self.recommendations,
        }

class BaseAttackModule(ABC):
    """Base class for all 14 attack modules."""

    attack_class: int = 0
    attack_class_name: str = ""
    description: str = ""

    @abstractmethod
    def generate_payloads(self, agent_id: str, config: dict[str, Any]) -> list[AttackPayload]:
        """Generate attack payloads for this class."""

    @abstractmethod
    async def execute(
        self,
        tenant_id: str,
        agent_id: str,
        payloads: list[AttackPayload],
    ) -> ModuleReport:
        """Execute attack payloads and return results."""

    def _make_report(self, tenant_id: str, agent_id: str) -> ModuleReport:
        return ModuleReport(
            module_id=uuid.uuid4().hex,
            attack_class=self.attack_class,
            attack_class_name=self.attack_class_name,
            tenant_id=tenant_id,
            agent_id=agent_id,
            started_at=datetime.now(UTC).isoformat(),
        )
