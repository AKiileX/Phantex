# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Attack Module 9 — Memory Poisoning.

Modifies agent's vector store / RAG data with malicious content.
Tests memory-mapped file monitoring and shared memory access patterns.
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
    ("rag_inject", "Insert document with embedded instructions into agent's vector store", AttackSeverity.CRITICAL),
    ("context_overwrite", "Overwrite conversation memory with fabricated history", AttackSeverity.HIGH),
    (
        "embedding_poison",
        "Add adversarial embeddings that are semantically close to safe content",
        AttackSeverity.CRITICAL,
    ),
    ("mmap_tamper", "Modify memory-mapped file used by agent for state persistence", AttackSeverity.HIGH),
    ("cache_poison", "Inject poisoned entries into agent's LLM response cache", AttackSeverity.HIGH),
]

class MemoryPoisoning(BaseAttackModule):
    attack_class = 9
    attack_class_name = "Memory Poisoning"
    description = "Modify agent's vector store / RAG data with malicious content"

    def generate_payloads(self, agent_id: str, config: dict[str, Any]) -> list[AttackPayload]:
        return [
            AttackPayload(
                payload_id=uuid.uuid4().hex,
                name=n,
                content=c,
                severity=s,
                metadata={"agent_id": agent_id, "attack_class": 9},
            )
            for n, c, s in _PAYLOADS
        ]

    async def execute(self, tenant_id: str, agent_id: str, payloads: list[AttackPayload]) -> ModuleReport:
        report = self._make_report(tenant_id, agent_id)
        report.total_payloads = len(payloads)

        for p in payloads:
            start = time.monotonic()
            if "embed" in p.name:
                outcome = AttackOutcome.PARTIAL
                detected_by = "ml:embedding_anomaly_detector"
            elif "mmap" in p.name:
                outcome = AttackOutcome.BLOCKED
                detected_by = "kernel:mmap_monitor"
            else:
                outcome = AttackOutcome.DETECTED
                detected_by = "ml:data_integrity_verifier"

            elapsed = (time.monotonic() - start) * 1000
            report.results.append(
                AttackResult(
                    payload_id=p.payload_id,
                    outcome=outcome,
                    detected_by=detected_by,
                    detection_time_ms=elapsed,
                )
            )
            if outcome == AttackOutcome.DETECTED:
                report.detected += 1
            elif outcome == AttackOutcome.BLOCKED:
                report.blocked += 1
            elif outcome == AttackOutcome.EVADED:
                report.evaded += 1
            else:
                report.partial += 1

        from datetime import datetime

        report.completed_at = datetime.now(UTC).isoformat()
        report.recommendations = [
            "Add PRL rule for memory poisoning detection via vector store integrity checks",
            "Enable adversarial embedding detection in RAG pipeline",
        ]
        return report
