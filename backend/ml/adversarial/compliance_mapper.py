# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Compliance Gap Mapper.

Maps red team simulation gaps to compliance framework requirements.
"Gap X means you fail NIST AI RMF control Y."

Supported frameworks:
  - NIST AI RMF  (AI 100-1)
  - NIST SP 800-53 Rev 5
  - SOC 2 Type II
  - ISO 27001:2022
  - EU AI Act (Article 9)
  - FedRAMP High
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Attack-class → compliance control mapping ─────────────────────────────────

@dataclass(frozen=True)
class ControlMapping:
    """A single compliance control affected by an attack class gap."""

    framework: str
    control_id: str
    control_name: str
    impact: str  # brief impact description

# Each attack class (1-14) maps to the controls it jeopardises when the
# detection rate is below threshold.  Curated from public framework docs.

_MAPPINGS: dict[int, list[ControlMapping]] = {
    1: [  # Direct Prompt Injection
        ControlMapping(
            "NIST AI RMF",
            "MAP 1.6",
            "Context-aware risk identification",
            "Undetected prompt injection undermines input validation",
        ),
        ControlMapping(
            "NIST 800-53", "SI-10", "Information Input Validation", "System accepts malicious prompt as valid input"
        ),
        ControlMapping(
            "EU AI Act",
            "Art.9(7)",
            "Robustness against adversarial input",
            "High-risk AI system fails robustness requirement",
        ),
        ControlMapping(
            "SOC 2", "CC6.1", "Logical Access Controls", "Input boundary bypass violates access control criteria"
        ),
    ],
    2: [  # Indirect Prompt Injection
        ControlMapping(
            "NIST AI RMF", "MEASURE 2.6", "Evaluation of AI system resilience", "Indirect vectors bypass input controls"
        ),
        ControlMapping(
            "NIST 800-53", "SI-3", "Malicious Code Protection", "Hidden instructions in data act as malicious code"
        ),
        ControlMapping("ISO 27001", "A.8.12", "Data Leakage Prevention", "Tool responses used as injection channel"),
    ],
    3: [  # Lateral Movement
        ControlMapping(
            "NIST 800-53",
            "AC-4",
            "Information Flow Enforcement",
            "Cross-agent movement violates information flow policy",
        ),
        ControlMapping("NIST 800-53", "SC-7", "Boundary Protection", "Agent-to-agent boundary not enforced"),
        ControlMapping("FedRAMP", "SC-7(5)", "Deny by Default", "Default-allow policy between agents"),
        ControlMapping("ISO 27001", "A.8.22", "Segregation of Networks", "Agent namespace not isolated"),
    ],
    4: [  # Tool Poisoning
        ControlMapping(
            "NIST AI RMF", "MANAGE 2.4", "Mechanisms to track identified risks", "Poisoned tool responses go undetected"
        ),
        ControlMapping(
            "NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity", "Tool output integrity not verified"
        ),
        ControlMapping("SOC 2", "CC7.2", "System Monitoring", "Tampered tool responses not flagged"),
    ],
    5: [  # MCP Supply Chain
        ControlMapping("NIST 800-53", "SR-3", "Supply Chain Controls", "MCP server provenance not verified"),
        ControlMapping("NIST 800-53", "SR-11", "Component Authenticity", "Rogue MCP server accepted as legitimate"),
        ControlMapping("FedRAMP", "SA-12", "Supply Chain Protection", "Third-party MCP tools bypass verification"),
        ControlMapping("ISO 27001", "A.5.21", "Managing ICT Supply Chain Security", "MCP supply chain uncontrolled"),
    ],
    6: [  # Data Exfiltration
        ControlMapping("NIST 800-53", "SC-7", "Boundary Protection", "Exfiltration channels not blocked at boundary"),
        ControlMapping("NIST 800-53", "SI-4", "System Monitoring", "Outbound data patterns not detected"),
        ControlMapping("ISO 27001", "A.8.12", "Data Leakage Prevention", "Agent leaks data via encoding channels"),
        ControlMapping("EU AI Act", "Art.10(5)", "Data governance", "Training/operational data exfiltrated"),
    ],
    7: [  # Agent Impersonation
        ControlMapping(
            "NIST 800-53",
            "IA-3",
            "Device Identification and Authentication",
            "Agent identity not cryptographically verified",
        ),
        ControlMapping(
            "NIST 800-53", "IA-8", "Identification & Authentication (Non-Org Users)", "Forged agent identity accepted"
        ),
        ControlMapping("SOC 2", "CC6.1", "Logical Access Controls", "Impersonation bypasses identity controls"),
        ControlMapping(
            "FedRAMP", "IA-3", "Device Identification and Authentication", "Hardware-backed identity not enforced"
        ),
    ],
    8: [  # Privilege Escalation
        ControlMapping("NIST 800-53", "AC-6", "Least Privilege", "Agent exceeds authorised tool scope"),
        ControlMapping(
            "NIST 800-53",
            "AC-6(1)",
            "Authorize Access to Security Functions",
            "Privilege boundary crossed without authorisation",
        ),
        ControlMapping("SOC 2", "CC6.3", "Role-Based Access", "Agent role escalated without approval"),
        ControlMapping("ISO 27001", "A.8.2", "Privileged Access Rights", "Escalation not detected by access controls"),
    ],
    9: [  # Memory Poisoning
        ControlMapping(
            "NIST AI RMF", "MAP 2.3", "Scientific integrity of AI system", "Poisoned memory degrades model integrity"
        ),
        ControlMapping(
            "NIST 800-53",
            "SI-7",
            "Software, Firmware, and Information Integrity",
            "Embedding store integrity compromised",
        ),
        ControlMapping("EU AI Act", "Art.10(3)", "Data quality for training", "Memory/RAG data quality not maintained"),
    ],
    10: [  # Model Extraction
        ControlMapping(
            "NIST AI RMF",
            "GOVERN 1.7",
            "Intellectual property protections",
            "Model behaviour extractable via API probing",
        ),
        ControlMapping(
            "NIST 800-53", "SC-28", "Protection of Information at Rest", "Model weights effectively exfiltrated"
        ),
        ControlMapping("ISO 27001", "A.5.33", "Protection of records", "Proprietary model copied without detection"),
    ],
    11: [  # Denial of Service
        ControlMapping(
            "NIST 800-53", "SC-5", "Denial-of-Service Protection", "Agent compute/token exhaustion unmitigated"
        ),
        ControlMapping("FedRAMP", "SC-5", "Denial-of-Service Protection", "No rate-limiting or circuit-breaker"),
        ControlMapping("SOC 2", "A1.2", "Environmental Safeguards", "Availability impacted by resource exhaustion"),
    ],
    12: [  # Compliance Violation
        ControlMapping("EU AI Act", "Art.14", "Human oversight", "Agent makes autonomous regulated decision"),
        ControlMapping(
            "NIST AI RMF", "GOVERN 2.1", "Roles and responsibilities", "No human-in-the-loop for regulated actions"
        ),
        ControlMapping("SOC 2", "CC3.2", "Risk Assessment Process", "Data sovereignty breach undetected"),
        ControlMapping("ISO 27001", "A.5.34", "Privacy and PII Protection", "PII processed without valid consent"),
    ],
    13: [  # Credential Theft
        ControlMapping("NIST 800-53", "IA-5", "Authenticator Management", "Credentials exposed in agent outputs"),
        ControlMapping(
            "NIST 800-53", "SC-28", "Protection of Information at Rest", "Secrets in environment variables leaked"
        ),
        ControlMapping("SOC 2", "CC6.1", "Logical Access Controls", "API keys visible in error traces"),
        ControlMapping("FedRAMP", "IA-5(1)", "Password-Based Authentication", "Credential material in output channel"),
    ],
    14: [  # Supply Chain (Dependencies)
        ControlMapping("NIST 800-53", "SR-3", "Supply Chain Controls", "Compromised dependency installed"),
        ControlMapping("NIST 800-53", "SR-4", "Provenance", "Package integrity hashes not verified"),
        ControlMapping("FedRAMP", "SA-12(14)", "Identity and Traceability", "Build artefact origin unverifiable"),
        ControlMapping("ISO 27001", "A.5.21", "Managing ICT Supply Chain Security", "Lockfile tamper undetected"),
    ],
}

# ── Gap analysis ──────────────────────────────────────────────────────────────

@dataclass
class ComplianceGap:
    """A single compliance gap identified from red team results."""

    attack_class: int
    attack_class_name: str
    detection_rate: float
    controls_affected: list[ControlMapping]
    severity: str  # critical / high / medium

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_class": self.attack_class,
            "attack_class_name": self.attack_class_name,
            "detection_rate": round(self.detection_rate, 4),
            "severity": self.severity,
            "controls_affected": [
                {
                    "framework": c.framework,
                    "control_id": c.control_id,
                    "control_name": c.control_name,
                    "impact": c.impact,
                }
                for c in self.controls_affected
            ],
        }

@dataclass
class ComplianceReport:
    """Full compliance-gap report from a red team campaign."""

    tenant_id: str
    gaps: list[ComplianceGap] = field(default_factory=list)
    frameworks_affected: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "total_gaps": len(self.gaps),
            "frameworks_affected": self.frameworks_affected,
            "summary": self.summary,
            "gaps": [g.to_dict() for g in self.gaps],
        }

# ── Threshold ─────────────────────────────────────────────────────────────────

_DETECTION_THRESHOLD = 0.95  # gap if detection < 95%

_SEVERITY_MAP = {
    (0.0, 0.50): "critical",
    (0.50, 0.80): "high",
    (0.80, 0.95): "medium",
}

def _classify_severity(detection_rate: float) -> str:
    for (lo, hi), sev in _SEVERITY_MAP.items():
        if lo <= detection_rate < hi:
            return sev
    return "medium"

def map_gaps(
    tenant_id: str,
    class_detection_rates: dict[int, tuple[str, float]],
) -> ComplianceReport:
    """Map attack-class detection rates to compliance gaps.

    Args:
        tenant_id: Tenant identifier.
        class_detection_rates: ``{attack_class: (class_name, detection_rate)}``
            where detection_rate ∈ [0.0, 1.0].

    Returns:
        ComplianceReport with all identified gaps.
    """
    gaps: list[ComplianceGap] = []
    frameworks_hit: set[str] = set()

    for cls_id, (cls_name, rate) in sorted(class_detection_rates.items()):
        if rate >= _DETECTION_THRESHOLD:
            continue
        controls = _MAPPINGS.get(cls_id, [])
        if not controls:
            continue
        severity = _classify_severity(rate)
        gap = ComplianceGap(
            attack_class=cls_id,
            attack_class_name=cls_name,
            detection_rate=rate,
            controls_affected=controls,
            severity=severity,
        )
        gaps.append(gap)
        for c in controls:
            frameworks_hit.add(c.framework)

    summary = (
        f"{len(gaps)} compliance gap(s) found across {len(frameworks_hit)} framework(s)."
        if gaps
        else "No compliance gaps detected. All attack classes meet 95% detection threshold."
    )

    report = ComplianceReport(
        tenant_id=tenant_id,
        gaps=gaps,
        frameworks_affected=sorted(frameworks_hit),
        summary=summary,
    )

    logger.info(
        "compliance_mapping_complete",
        tenant_id=tenant_id,
        total_gaps=len(gaps),
        frameworks=sorted(frameworks_hit),
    )
    return report

def map_from_campaign(
    tenant_id: str,
    campaign_report: Any,
) -> ComplianceReport:
    """Convenience: build compliance report directly from a CampaignReport."""
    rates: dict[int, tuple[str, float]] = {}
    for mr in campaign_report.module_reports:
        rates[mr.attack_class] = (mr.attack_class_name, mr.detection_rate)
    return map_gaps(tenant_id, rates)
