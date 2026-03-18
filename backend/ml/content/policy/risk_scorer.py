# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Block V4 — MCP Supply Chain Risk Scorer.

Composite 0-100 risk score for MCP servers combining:
  - Trust level baseline (from MCPServerRegistry)
  - Behavioral profile anomalies (from MCPBehavioralProfiler)
  - Package scan results (from PackageReputationScanner)
  - Protocol analysis findings (from MCPProtocolAnalyzer)

Configurable weights, auto-block threshold, historical trend tracking.
Thread-safe singleton per application.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class RiskLevel(StrEnum):
    """Discrete risk level derived from the 0-100 score."""

    CRITICAL = "critical"  # 80-100
    HIGH = "high"  # 60-79
    MEDIUM = "medium"  # 40-59
    LOW = "low"  # 20-39
    MINIMAL = "minimal"  # 0-19

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 20:
            return cls.LOW
        return cls.MINIMAL

class RiskAction(StrEnum):
    """Recommended action based on risk level."""

    BLOCK = "block"
    QUARANTINE = "quarantine"
    MONITOR = "monitor"
    ALLOW = "allow"

@dataclass(frozen=True)
class RiskBreakdown:
    """Detailed breakdown of how the score was computed."""

    trust_score: float  # 0-100 contribution from trust level
    behavior_score: float  # 0-100 contribution from behavioral anomalies
    package_score: float  # 0-100 contribution from package scan
    protocol_score: float  # 0-100 contribution from protocol analysis

    trust_weight: float
    behavior_weight: float
    package_weight: float
    protocol_weight: float

    trust_details: str = ""
    behavior_details: str = ""
    package_details: str = ""
    protocol_details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "components": {
                "trust": {
                    "score": round(self.trust_score, 1),
                    "weight": self.trust_weight,
                    "weighted": round(self.trust_score * self.trust_weight, 1),
                    "details": self.trust_details,
                },
                "behavior": {
                    "score": round(self.behavior_score, 1),
                    "weight": self.behavior_weight,
                    "weighted": round(self.behavior_score * self.behavior_weight, 1),
                    "details": self.behavior_details,
                },
                "package": {
                    "score": round(self.package_score, 1),
                    "weight": self.package_weight,
                    "weighted": round(self.package_score * self.package_weight, 1),
                    "details": self.package_details,
                },
                "protocol": {
                    "score": round(self.protocol_score, 1),
                    "weight": self.protocol_weight,
                    "weighted": round(self.protocol_score * self.protocol_weight, 1),
                    "details": self.protocol_details,
                },
            },
        }

@dataclass(frozen=True)
class RiskAssessment:
    """Complete risk assessment for an MCP server."""

    server_id: str
    tenant_id: str
    score: float  # 0-100
    level: RiskLevel
    action: RiskAction
    breakdown: RiskBreakdown
    assessed_at: datetime
    trend: str = "stable"  # "rising", "falling", "stable"
    auto_blocked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "tenant_id": self.tenant_id,
            "score": round(self.score, 1),
            "level": self.level.value,
            "action": self.action.value,
            "breakdown": self.breakdown.to_dict(),
            "assessed_at": self.assessed_at.isoformat(),
            "trend": self.trend,
            "auto_blocked": self.auto_blocked,
        }

# ── Historical entry ───────────────────────────────────────────────────

@dataclass
class _ScoreHistoryEntry:
    score: float
    timestamp: datetime

# ── Trust level → base risk mapping ────────────────────────────────────

TRUST_LEVEL_RISK: dict[str, float] = {
    "verified": 5.0,
    "known": 20.0,
    "unknown": 50.0,
    "suspicious": 75.0,
    "blocked": 100.0,
}

class MCPRiskScorer:
    """Thread-safe composite MCP risk scorer.

    Usage:
        scorer = MCPRiskScorer()
        assessment = scorer.assess(
            server_id="srv-1",
            tenant_id="t42",
            trust_level="known",
            anomaly_count=2,
            anomaly_types=["latency_spike", "capability_change"],
            package_vulns=1,
            typosquat_matches=0,
            package_reputation=0.85,
            protocol_violations=["injection_pattern"],
        )
        if assessment.action == RiskAction.BLOCK:
            ...
    """

    __slots__ = (
        "_lock",
        "_history",
        "_max_history",
        "_trust_weight",
        "_behavior_weight",
        "_package_weight",
        "_protocol_weight",
        "_auto_block_threshold",
        "_quarantine_threshold",
    )

    def __init__(
        self,
        trust_weight: float = 0.25,
        behavior_weight: float = 0.25,
        package_weight: float = 0.30,
        protocol_weight: float = 0.20,
        auto_block_threshold: float = 85.0,
        quarantine_threshold: float = 65.0,
        max_history: int = 50,
    ) -> None:
        total = trust_weight + behavior_weight + package_weight + protocol_weight
        if abs(total - 1.0) >= 0.01:
            raise ValueError(f"Weights must sum to 1.0, got {total:.4f}")

        self._trust_weight = trust_weight
        self._behavior_weight = behavior_weight
        self._package_weight = package_weight
        self._protocol_weight = protocol_weight
        self._auto_block_threshold = auto_block_threshold
        self._quarantine_threshold = quarantine_threshold
        self._max_history = max_history
        self._lock = threading.Lock()
        self._history: dict[tuple[str, str], deque[_ScoreHistoryEntry]] = {}

    def assess(
        self,
        server_id: str,
        tenant_id: str,
        # Trust inputs
        trust_level: str = "unknown",
        # Behavioral inputs
        anomaly_count: int = 0,
        anomaly_types: list[str] | None = None,
        calls_total: int = 0,
        error_rate: float = 0.0,
        # Package inputs
        package_vulns: int = 0,
        typosquat_matches: int = 0,
        malicious_packages: int = 0,
        package_reputation: float = 1.0,  # 0.0 = bad, 1.0 = clean
        # Protocol inputs
        protocol_violations: list[str] | None = None,
    ) -> RiskAssessment:
        """Compute total risk assessment for an MCP server."""
        now = datetime.now(UTC)

        # ── Component scores ─────────────────────────────────
        trust_score, trust_detail = self._score_trust(trust_level)
        behavior_score, behavior_detail = self._score_behavior(
            anomaly_count, anomaly_types or [], calls_total, error_rate
        )
        package_score, package_detail = self._score_packages(
            package_vulns, typosquat_matches, malicious_packages, package_reputation
        )
        protocol_score, protocol_detail = self._score_protocol(protocol_violations or [])

        # ── Weighted composite ───────────────────────────────
        composite = (
            trust_score * self._trust_weight
            + behavior_score * self._behavior_weight
            + package_score * self._package_weight
            + protocol_score * self._protocol_weight
        )
        composite = max(0.0, min(100.0, composite))

        level = RiskLevel.from_score(composite)
        action = self._recommend_action(composite)
        auto_blocked = composite >= self._auto_block_threshold

        # ── Trend ────────────────────────────────────────────
        trend = self._update_history(tenant_id, server_id, composite, now)

        breakdown = RiskBreakdown(
            trust_score=trust_score,
            behavior_score=behavior_score,
            package_score=package_score,
            protocol_score=protocol_score,
            trust_weight=self._trust_weight,
            behavior_weight=self._behavior_weight,
            package_weight=self._package_weight,
            protocol_weight=self._protocol_weight,
            trust_details=trust_detail,
            behavior_details=behavior_detail,
            package_details=package_detail,
            protocol_details=protocol_detail,
        )

        return RiskAssessment(
            server_id=server_id,
            tenant_id=tenant_id,
            score=composite,
            level=level,
            action=action,
            breakdown=breakdown,
            assessed_at=now,
            trend=trend,
            auto_blocked=auto_blocked,
        )

    def get_history(self, tenant_id: str, server_id: str) -> list[dict[str, Any]]:
        """Return score history for a server."""
        with self._lock:
            entries = self._history.get((tenant_id, server_id), deque())
            return [{"score": round(e.score, 1), "ts": e.timestamp.isoformat()} for e in entries]

    # ── Component scorers ───────────────────────────────────────────

    @staticmethod
    def _score_trust(trust_level: str) -> tuple[float, str]:
        """Map trust level to 0-100 risk score."""
        level = trust_level.lower().strip()
        score = TRUST_LEVEL_RISK.get(level, 50.0)
        return score, f"Trust level '{level}' → base risk {score}"

    @staticmethod
    def _score_behavior(
        anomaly_count: int,
        anomaly_types: list[str],
        calls_total: int,
        error_rate: float,
    ) -> tuple[float, str]:
        """Score behavioral risk from profiler output."""
        score = 0.0
        parts: list[str] = []

        # Base from anomaly count (diminishing returns)
        if anomaly_count > 0:
            anomaly_component = min(50.0, anomaly_count * 8.0)
            score += anomaly_component
            parts.append(f"{anomaly_count} anomalies → +{anomaly_component:.0f}")

        # Severity bumps for specific anomaly types
        high_severity_types = {"capability_change", "new_tool_added", "tool_removed", "content_drift"}
        severe = [t for t in anomaly_types if t in high_severity_types]
        if severe:
            bump = len(severe) * 10.0
            score += bump
            parts.append(f"severe types {severe} → +{bump:.0f}")

        # Error rate contribution
        if error_rate > 0.1:
            err_comp = min(30.0, error_rate * 60.0)
            score += err_comp
            parts.append(f"error_rate {error_rate:.0%} → +{err_comp:.0f}")

        # Low call count = uncertain (slight bump)
        if calls_total < 10 and calls_total > 0:
            score += 5.0
            parts.append("low sample count → +5")

        return min(100.0, score), "; ".join(parts) if parts else "clean"

    @staticmethod
    def _score_packages(
        vulns: int,
        typosquat: int,
        malicious: int,
        reputation: float,
    ) -> tuple[float, str]:
        """Score package supply chain risk."""
        score = 0.0
        parts: list[str] = []

        # Malicious packages are instant critical
        if malicious > 0:
            score += min(100.0, malicious * 50.0)
            parts.append(f"{malicious} malicious → +{min(100, malicious * 50)}")

        # Typosquatting is high risk
        if typosquat > 0:
            ts_comp = min(40.0, typosquat * 20.0)
            score += ts_comp
            parts.append(f"{typosquat} typosquat → +{ts_comp:.0f}")

        # Known vulnerabilities
        if vulns > 0:
            vuln_comp = min(30.0, vulns * 10.0)
            score += vuln_comp
            parts.append(f"{vulns} CVEs → +{vuln_comp:.0f}")

        # Reputation (1.0=clean, lower=riskier)
        if reputation < 0.8:
            rep_comp = (1.0 - reputation) * 40.0
            score += rep_comp
            parts.append(f"reputation {reputation:.2f} → +{rep_comp:.0f}")

        return min(100.0, score), "; ".join(parts) if parts else "clean"

    @staticmethod
    def _score_protocol(violations: list[str]) -> tuple[float, str]:
        """Score protocol analysis risk."""
        if not violations:
            return 0.0, "clean"

        # Severity weights per violation type
        weights: dict[str, float] = {
            "injection_pattern": 40.0,
            "malformed_message": 15.0,
            "invalid_jsonrpc": 10.0,
            "unexpected_method": 15.0,
            "tool_list_change": 25.0,
            "response_size_anomaly": 20.0,
            "timing_anomaly": 10.0,
            "version_downgrade": 20.0,
            "unauthorized_resource": 30.0,
            "excessive_error_rate": 10.0,
        }

        score = 0.0
        parts: list[str] = []
        for v in violations:
            w = weights.get(v, 10.0)
            score += w
            parts.append(f"{v} → +{w:.0f}")

        return min(100.0, score), "; ".join(parts)

    def _recommend_action(self, score: float) -> RiskAction:
        """Map composite score → recommended action."""
        if score >= self._auto_block_threshold:
            return RiskAction.BLOCK
        if score >= self._quarantine_threshold:
            return RiskAction.QUARANTINE
        if score >= 30.0:
            return RiskAction.MONITOR
        return RiskAction.ALLOW

    def _update_history(
        self,
        tenant_id: str,
        server_id: str,
        score: float,
        now: datetime,
    ) -> str:
        """Record score + compute trend. Must be called outside lock or caller handles."""
        with self._lock:
            key = (tenant_id, server_id)
            if key not in self._history:
                self._history[key] = deque(maxlen=self._max_history)

            history = self._history[key]
            history.append(_ScoreHistoryEntry(score=score, timestamp=now))

            if len(history) < 3:
                return "stable"

            # Compare avg of last 3 scores to avg of 3 before that
            recent = [h.score for h in list(history)[-3:]]
            older = [h.score for h in list(history)[-6:-3]]
            if not older:
                return "stable"

            avg_recent = sum(recent) / len(recent)
            avg_older = sum(older) / len(older)
            delta = avg_recent - avg_older

            if delta > 5.0:
                return "rising"
            if delta < -5.0:
                return "falling"
            return "stable"
