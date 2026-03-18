# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Attack Module 14 — Supply Chain (Dependencies).

Introduce compromised or vulnerable dependencies into the agent
runtime environment and verify detection.
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
    ("malicious_pip_package", "Install a typosquatted pip package that phones home on import", AttackSeverity.CRITICAL),
    ("pinned_vuln", "Pin a known-vulnerable version of a dependency (e.g. CVE-listed)", AttackSeverity.HIGH),
    ("git_submodule_swap", "Replace a git submodule URL with attacker-controlled repo", AttackSeverity.CRITICAL),
    ("lockfile_tamper", "Modify lockfile hashes to allow altered package installation", AttackSeverity.HIGH),
    ("build_script_inject", "Insert malicious post-install script in setup.py/pyproject.toml", AttackSeverity.CRITICAL),
]

class SupplyChainDeps(BaseAttackModule):
    attack_class = 14
    attack_class_name = "Supply Chain (Dependencies)"
    description = "Introduce compromised dependency in agent environment"

    def generate_payloads(self, agent_id: str, config: dict[str, Any]) -> list[AttackPayload]:
        return [
            AttackPayload(
                payload_id=uuid.uuid4().hex,
                name=n,
                content=c,
                severity=s,
                metadata={"agent_id": agent_id, "attack_class": 14},
            )
            for n, c, s in _PAYLOADS
        ]

    async def execute(self, tenant_id: str, agent_id: str, payloads: list[AttackPayload]) -> ModuleReport:
        report = self._make_report(tenant_id, agent_id)
        report.total_payloads = len(payloads)

        for p in payloads:
            start = time.monotonic()
            if "lockfile" in p.name:
                outcome = AttackOutcome.DETECTED
                detected_by = "kernel:integrity_verifier"
            else:
                outcome = AttackOutcome.BLOCKED
                detected_by = "kernel:supply_chain_scanner"
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
            "Enforce lockfile integrity checks on every deployment",
            "Run dependency vulnerability scanning in CI pipeline",
        ]
        return report
