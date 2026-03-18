# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Red Team Security Scorecard.

Generates a security resilience scorecard from campaign results, grading the
ML pipeline across multiple attack categories and producing an aggregate
health score (0–100).

Grade thresholds:
  A  = 90–100  (evasion < 3%)
  B  = 75–89   (evasion < 8%)
  C  = 50–74   (evasion < 15%)
  D  = 25–49   (evasion < 25%)
  F  = 0–24    (evasion ≥ 25%)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.red_team.simulator import CampaignResult, CampaignStatus

logger = structlog.get_logger("phantex.red_team.scorecard")

# ── Grade thresholds ──────────────────────────────────────────────────────────

def _letter_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"

# ── Scorecard data classes ────────────────────────────────────────────────────

@dataclass
class CategoryScore:
    """Score for a single attack category."""

    category: str
    score: float
    grade: str
    attacks_run: int
    avg_evasion_rate: float
    worst_evasion_rate: float
    details: dict[str, Any] = field(default_factory=dict)

@dataclass
class Scorecard:
    """Aggregate security scorecard for a tenant."""

    tenant_id: str
    generated_at: str
    overall_score: float
    overall_grade: str
    campaigns_analyzed: int
    categories: list[CategoryScore]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at,
            "overall_score": round(self.overall_score, 1),
            "overall_grade": self.overall_grade,
            "campaigns_analyzed": self.campaigns_analyzed,
            "categories": [
                {
                    "category": c.category,
                    "score": round(c.score, 1),
                    "grade": c.grade,
                    "attacks_run": c.attacks_run,
                    "avg_evasion_rate": round(c.avg_evasion_rate, 4),
                    "worst_evasion_rate": round(c.worst_evasion_rate, 4),
                }
                for c in self.categories
            ],
            "recommendations": self.recommendations,
        }

# ── Scorecard generation ─────────────────────────────────────────────────────

def generate_scorecard(
    tenant_id: str,
    campaigns: list[CampaignResult],
) -> Scorecard:
    """Build a scorecard from completed campaigns.

    Groups attack runs by attack_class and computes per-category and
    aggregate scores.
    """
    completed = [c for c in campaigns if c.status == CampaignStatus.COMPLETED.value]
    if not completed:
        return Scorecard(
            tenant_id=tenant_id,
            generated_at=datetime.now(UTC).isoformat(),
            overall_score=0.0,
            overall_grade="N/A",
            campaigns_analyzed=0,
            categories=[],
            recommendations=["Run at least one red team campaign to generate a scorecard."],
        )

    # Group attack runs by class
    by_class: dict[str, list[dict[str, float]]] = {}
    for campaign in completed:
        for run in campaign.attack_runs:
            cls = run.attack_class
            if cls not in by_class:
                by_class[cls] = []
            by_class[cls].append(
                {
                    "evasion_rate": run.evasion_rate,
                    "samples_tested": run.samples_tested,
                }
            )

    categories: list[CategoryScore] = []
    for cls, runs in sorted(by_class.items()):
        evasion_rates = [r["evasion_rate"] for r in runs]
        avg_evasion = sum(evasion_rates) / len(evasion_rates) if evasion_rates else 0.0
        worst_evasion = max(evasion_rates) if evasion_rates else 0.0
        score = max(0.0, (1.0 - avg_evasion) * 100)
        categories.append(
            CategoryScore(
                category=cls,
                score=score,
                grade=_letter_grade(score),
                attacks_run=len(runs),
                avg_evasion_rate=avg_evasion,
                worst_evasion_rate=worst_evasion,
            )
        )

    overall = sum(c.score for c in categories) / len(categories) if categories else 0.0

    # Generate recommendations
    recommendations = _build_recommendations(categories)

    scorecard = Scorecard(
        tenant_id=tenant_id,
        generated_at=datetime.now(UTC).isoformat(),
        overall_score=overall,
        overall_grade=_letter_grade(overall),
        campaigns_analyzed=len(completed),
        categories=categories,
        recommendations=recommendations,
    )

    logger.info(
        "scorecard_generated",
        tenant_id=tenant_id,
        overall_score=round(overall, 1),
        grade=scorecard.overall_grade,
    )
    return scorecard

def _build_recommendations(categories: list[CategoryScore]) -> list[str]:
    """Generate actionable recommendations from category scores."""
    recs: list[str] = []
    for cat in categories:
        if cat.grade in ("D", "F"):
            recs.append(
                f"CRITICAL: {cat.category} evasion rate is {cat.avg_evasion_rate:.0%}. "
                f"Retrain with adversarial augmentation targeting this attack class."
            )
        elif cat.grade == "C":
            recs.append(
                f"WARNING: {cat.category} score is {cat.score:.0f}/100. "
                f"Consider increasing training robustness for this vector."
            )

    if not recs:
        recs.append("All attack categories within acceptable thresholds. Continue regular testing.")

    # General recommendations
    if len(categories) < 3:
        recs.append("Expand test coverage: run campaigns across more attack types.")

    return recs

# ── 14-class scorecard extension ─────────────────────────────────

# PRL rules that mitigate each attack class
_PRL_MITIGATIONS: dict[int, list[str]] = {
    1: ["R-PROMPT-01 (input sanitisation)", "R-PROMPT-02 (delimiter check)"],
    2: ["R-PROMPT-03 (tool response validation)", "R-PROMPT-04 (RAG content filter)"],
    3: ["R-LATERAL-01 (cross-agent boundary)", "R-SANDBOX-03 (namespace isolation)"],
    4: ["R-TOOL-01 (response integrity)", "R-TOOL-02 (schema validation)"],
    5: ["R-MCP-01 (server allowlist)", "R-MCP-02 (manifest hash verification)"],
    6: ["R-EXFIL-01 (outbound content scan)", "R-EXFIL-02 (encoding detector)"],
    7: ["R-IDENT-01 (cryptographic identity)", "R-IDENT-02 (attestation check)"],
    8: ["R-PRIV-01 (least-privilege enforcement)", "R-PRIV-02 (scope boundary check)"],
    9: ["R-MEM-01 (embedding integrity)", "R-MEM-02 (RAG write validation)"],
    10: ["R-MODEL-01 (query rate limiting)", "R-MODEL-02 (output perturbation)"],
    11: ["R-DOS-01 (token budget)", "R-DOS-02 (circuit breaker)"],
    12: ["R-COMP-01 (human-in-the-loop gate)", "R-COMP-02 (data residency check)"],
    13: ["R-CRED-01 (secret filter)", "R-CRED-02 (output scrubbing)"],
    14: ["R-SUPPLY-01 (lockfile integrity)", "R-SUPPLY-02 (package provenance)"],
}

_ALL_14_CLASSES = {
    1: "Direct Prompt Injection",
    2: "Indirect Prompt Injection",
    3: "Agent Lateral Movement",
    4: "Tool Poisoning",
    5: "MCP Supply Chain Attack",
    6: "Data Exfiltration",
    7: "Agent Impersonation",
    8: "Privilege Escalation",
    9: "Memory Poisoning",
    10: "Model Extraction",
    11: "Denial of Service",
    12: "Compliance Violation",
    13: "Credential Theft",
    14: "Supply Chain (Dependencies)",
}

@dataclass
class GapAnalysis:
    """Gap analysis entry for a single attack class."""

    attack_class: int
    attack_class_name: str
    score: float
    grade: str
    detection_rate: float
    prl_rules_to_close: list[str]
    compliance_frameworks_affected: list[str]

@dataclass
class FullScorecard:
    """Extended scorecard with 14-class coverage, gap analysis, and compliance."""

    tenant_id: str
    generated_at: str
    overall_score: float
    overall_grade: str
    classes_tested: int
    classes_total: int
    class_scores: list[CategoryScore]
    gap_analysis: list[GapAnalysis]
    coverage_pct: float
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at,
            "overall_score": round(self.overall_score, 1),
            "overall_grade": self.overall_grade,
            "classes_tested": self.classes_tested,
            "classes_total": self.classes_total,
            "coverage_pct": round(self.coverage_pct, 1),
            "class_scores": [
                {
                    "attack_class": i + 1,
                    "attack_class_name": _ALL_14_CLASSES.get(i + 1, c.category),
                    "score": round(c.score, 1),
                    "grade": c.grade,
                    "attacks_run": c.attacks_run,
                    "avg_evasion_rate": round(c.avg_evasion_rate, 4),
                }
                for i, c in enumerate(self.class_scores)
            ],
            "gap_analysis": [
                {
                    "attack_class": g.attack_class,
                    "attack_class_name": g.attack_class_name,
                    "score": round(g.score, 1),
                    "grade": g.grade,
                    "detection_rate": round(g.detection_rate, 4),
                    "prl_rules_to_close": g.prl_rules_to_close,
                    "compliance_frameworks_affected": g.compliance_frameworks_affected,
                }
                for g in self.gap_analysis
            ],
            "recommendations": self.recommendations,
        }

def generate_full_scorecard(
    tenant_id: str,
    module_reports: list[Any],
) -> FullScorecard:
    """Build a 14-class scorecard from attack module reports.

    Args:
        tenant_id: Tenant identifier.
        module_reports: List of ``ModuleReport`` objects from registry execution.
    """
    from ml.adversarial.compliance_mapper import map_gaps

    now = datetime.now(UTC).isoformat()
    by_class: dict[int, Any] = {}
    for mr in module_reports:
        by_class[mr.attack_class] = mr

    class_scores: list[CategoryScore] = []
    gap_entries: list[GapAnalysis] = []
    detection_rates: dict[int, tuple[str, float]] = {}

    for cls_id in sorted(_ALL_14_CLASSES.keys()):
        cls_name = _ALL_14_CLASSES[cls_id]
        mr = by_class.get(cls_id)
        if mr is None:
            class_scores.append(
                CategoryScore(
                    category=cls_name,
                    score=0.0,
                    grade="N/A",
                    attacks_run=0,
                    avg_evasion_rate=0.0,
                    worst_evasion_rate=0.0,
                )
            )
            gap_entries.append(
                GapAnalysis(
                    attack_class=cls_id,
                    attack_class_name=cls_name,
                    score=0.0,
                    grade="N/A",
                    detection_rate=0.0,
                    prl_rules_to_close=_PRL_MITIGATIONS.get(cls_id, []),
                    compliance_frameworks_affected=["Not tested — cannot assess"],
                )
            )
            continue

        evasion = mr.evaded / mr.total_payloads if mr.total_payloads else 0.0
        score = mr.score
        grade = _letter_grade(score)
        det_rate = mr.detection_rate
        detection_rates[cls_id] = (cls_name, det_rate)

        class_scores.append(
            CategoryScore(
                category=cls_name,
                score=score,
                grade=grade,
                attacks_run=mr.total_payloads,
                avg_evasion_rate=evasion,
                worst_evasion_rate=evasion,
            )
        )

        if grade in ("C", "D", "F"):
            gap_entries.append(
                GapAnalysis(
                    attack_class=cls_id,
                    attack_class_name=cls_name,
                    score=score,
                    grade=grade,
                    detection_rate=det_rate,
                    prl_rules_to_close=_PRL_MITIGATIONS.get(cls_id, []),
                    compliance_frameworks_affected=[],  # filled below
                )
            )

    # compliance mapping for gaps
    if detection_rates:
        compliance_report = map_gaps(tenant_id, detection_rates)
        fw_by_class: dict[int, list[str]] = {}
        for gap in compliance_report.gaps:
            fws = list({c.framework for c in gap.controls_affected})
            fw_by_class[gap.attack_class] = sorted(fws)
        for g in gap_entries:
            if g.attack_class in fw_by_class:
                g.compliance_frameworks_affected = fw_by_class[g.attack_class]

    tested = sum(1 for cs in class_scores if cs.grade != "N/A")
    scored = [cs.score for cs in class_scores if cs.grade != "N/A"]
    overall = sum(scored) / len(scored) if scored else 0.0

    recs = _build_recommendations(class_scores)
    for g in gap_entries:
        if g.prl_rules_to_close:
            recs.append(
                f"Close class {g.attack_class} ({g.attack_class_name}) gap: "
                f"deploy PRL rules {', '.join(g.prl_rules_to_close)}"
            )

    return FullScorecard(
        tenant_id=tenant_id,
        generated_at=now,
        overall_score=overall,
        overall_grade=_letter_grade(overall),
        classes_tested=tested,
        classes_total=14,
        class_scores=class_scores,
        gap_analysis=gap_entries,
        coverage_pct=(tested / 14) * 100,
        recommendations=recs,
    )
