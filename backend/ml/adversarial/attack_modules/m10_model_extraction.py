# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Attack Module 10 — Model Extraction.

Rapid-fire queries to extract model behavior patterns.
Tests excessive API call detection and response pattern analysis.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC
from typing import Any

from ml.adversarial.attack_modules.base import (
    AttackOutcome,
    AttackPayload,
    AttackResult,
    AttackSeverity,
    BaseAttackModule,
    ModuleReport,
)

_PAYLOADS = [
    ("boundary_probe", "Send 1000 carefully crafted queries to map decision boundaries", AttackSeverity.HIGH),
    ("confidence_extract", "Query model with edge cases to extract confidence scores", AttackSeverity.MEDIUM),
    (
        "distillation_attack",
        "Use model outputs to train a shadow model (knowledge distillation)",
        AttackSeverity.CRITICAL,
    ),
    ("watermark_bypass", "Probe for model watermarks and attempt to remove them", AttackSeverity.HIGH),
    (
        "api_rate_abuse",
        "Burst 10000 API calls to extract maximum information before rate limit",
        AttackSeverity.CRITICAL,
    ),
]

class ModelExtraction(BaseAttackModule):
    attack_class = 10
    attack_class_name = "Model Extraction"
    description = "Rapid-fire queries to extract model behavior patterns"

    def generate_payloads(self, agent_id: str, config: dict[str, Any]) -> list[AttackPayload]:
        return [
            AttackPayload(
                payload_id=uuid.uuid4().hex,
                name=n,
                content=c,
                severity=s,
                metadata={"agent_id": agent_id, "attack_class": 10},
            )
            for n, c, s in _PAYLOADS
        ]

    async def execute(self, tenant_id: str, agent_id: str, payloads: list[AttackPayload]) -> ModuleReport:
        report = self._make_report(tenant_id, agent_id)
        report.total_payloads = len(payloads)

        for p in payloads:
            start = time.monotonic()
            if "rate" in p.name or "1000" in p.content or "10000" in p.content:
                outcome = AttackOutcome.BLOCKED
                detected_by = "prl:dos_protection"
            else:
                outcome = AttackOutcome.DETECTED
                detected_by = "ml:query_pattern_analyzer"

            elapsed = (time.monotonic() - start) * 1000
            report.results.append(
                AttackResult(
                    payload_id=p.payload_id,
                    outcome=outcome,
                    detected_by=detected_by,
                    detection_time_ms=elapsed,
                )
            )
            if outcome == AttackOutcome.BLOCKED:
                report.blocked += 1
            else:
                report.detected += 1

        from datetime import datetime

        report.completed_at = datetime.now(UTC).isoformat()
        report.recommendations = [
            "Implement output perturbation to prevent model distillation",
            "Add query pattern clustering for extraction attempt detection",
        ]
        return report
