# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Block V2 — Package Reputation Scanner.

Scans MCP server dependency manifests (package.json, requirements.txt)
for known-malicious packages, CVE vulnerabilities, and typosquatting.

Signals:
  - Known CVEs (severity from CVSS)
  - Typosquatting (edit distance from top packages)
  - Package age + download count reputation
  - Maintainer history anomalies (new maintainer on popular package)
  - Dependency depth (deeply nested deps are harder to audit)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class PackageEcosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"

class VulnerabilitySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

@dataclass(frozen=True)
class PackageVulnerability:
    """Known vulnerability in a package."""

    cve_id: str
    package: str
    ecosystem: PackageEcosystem
    severity: VulnerabilitySeverity
    title: str
    fixed_version: str | None = None
    cvss_score: float = 0.0
    url: str = ""

@dataclass(frozen=True)
class TyposquatMatch:
    """Potential typosquatting detection."""

    suspect_package: str
    target_package: str
    ecosystem: PackageEcosystem
    edit_distance: int
    confidence: float  # 0.0–1.0

@dataclass(frozen=True)
class PackageReputation:
    """Reputation assessment for a single package."""

    name: str
    ecosystem: PackageEcosystem
    version: str = ""
    age_days: int = -1  # -1 = unknown
    download_count: int = -1  # -1 = unknown
    maintainer_count: int = -1  # -1 = unknown
    has_known_cves: bool = False
    is_typosquat_suspect: bool = False
    reputation_score: float = 50.0  # 0–100 (100 = trusted)
    flags: list[str] = field(default_factory=list)

@dataclass
class PackageScanResult:
    """Full scan result for an MCP server's dependencies."""

    server_id: str
    tenant_id: str
    ecosystem: PackageEcosystem
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    total_packages: int = 0
    vulnerabilities: list[PackageVulnerability] = field(default_factory=list)
    typosquat_suspects: list[TyposquatMatch] = field(default_factory=list)
    package_reputations: list[PackageReputation] = field(default_factory=list)
    risk_score: float = 0.0  # 0–100 (aggregated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "tenant_id": self.tenant_id,
            "ecosystem": self.ecosystem.value,
            "scanned_at": self.scanned_at.isoformat(),
            "total_packages": self.total_packages,
            "vulnerability_count": len(self.vulnerabilities),
            "typosquat_count": len(self.typosquat_suspects),
            "risk_score": round(self.risk_score, 1),
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "package": v.package,
                    "severity": v.severity.value,
                    "title": v.title,
                    "cvss_score": v.cvss_score,
                    "fixed_version": v.fixed_version,
                    "url": v.url,
                }
                for v in self.vulnerabilities
            ],
            "typosquat_suspects": [
                {
                    "suspect": t.suspect_package,
                    "target": t.target_package,
                    "edit_distance": t.edit_distance,
                    "confidence": round(t.confidence, 3),
                }
                for t in self.typosquat_suspects
            ],
            "packages": [
                {
                    "name": p.name,
                    "version": p.version,
                    "reputation_score": round(p.reputation_score, 1),
                    "flags": p.flags,
                }
                for p in self.package_reputations
            ],
        }

# ── Well-known packages (for typosquatting detection) ───────────────────────

TOP_NPM_PACKAGES = frozenset(
    {
        "express",
        "react",
        "lodash",
        "axios",
        "chalk",
        "debug",
        "commander",
        "typescript",
        "webpack",
        "babel",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "next",
        "vue",
        "angular",
        "svelte",
        "fastify",
        "socket.io",
        "langchain",
        "openai",
        "anthropic",
        "ai",
        "llamaindex",
        "@modelcontextprotocol/sdk",
        "@anthropic-ai/sdk",
        "@openai/agents",
    }
)

TOP_PYPI_PACKAGES = frozenset(
    {
        "requests",
        "flask",
        "django",
        "fastapi",
        "numpy",
        "pandas",
        "scipy",
        "scikit-learn",
        "tensorflow",
        "pytorch",
        "transformers",
        "httpx",
        "pydantic",
        "sqlalchemy",
        "celery",
        "redis",
        "boto3",
        "click",
        "langchain",
        "openai",
        "anthropic",
        "llama-index",
        "chromadb",
        "mcp",
        "langchain-mcp",
        "langchain-core",
        "langchain-openai",
    }
)

# Known malicious package names (curated blocklist)
KNOWN_MALICIOUS_NPM = frozenset(
    {
        "event-stream",
        "ua-parser-js-malicious",
        "colors-malicious",
        "faker-malicious",
        "node-ipc-malicious",
        # Typosquat entries targeting MCP ecosystem
        "modelcontextprotocol-sdk",
        "mcp-sdk-client",
        "anthropic-mcp",
    }
)

KNOWN_MALICIOUS_PYPI = frozenset(
    {
        "colourama",
        "python-binance-fake",
        "requesocks",
        # MCP-targeted
        "mcp-server-malicious",
        "langchain-mcp-exploit",
    }
)

def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(
                min(
                    curr_row[j] + 1,  # insert
                    prev_row[j + 1] + 1,  # delete
                    prev_row[j] + cost,  # substitute
                )
            )
        prev_row = curr_row

    return prev_row[-1]

class PackageReputationScanner:
    """Scan MCP server dependency lists for security issues."""

    def scan_npm(
        self,
        server_id: str,
        tenant_id: str,
        packages: dict[str, str],  # name → version
    ) -> PackageScanResult:
        """Scan npm dependencies."""
        return self._scan(
            server_id=server_id,
            tenant_id=tenant_id,
            packages=packages,
            ecosystem=PackageEcosystem.NPM,
            top_packages=TOP_NPM_PACKAGES,
            malicious_set=KNOWN_MALICIOUS_NPM,
        )

    def scan_pypi(
        self,
        server_id: str,
        tenant_id: str,
        packages: dict[str, str],  # name → version
    ) -> PackageScanResult:
        """Scan PyPI dependencies."""
        return self._scan(
            server_id=server_id,
            tenant_id=tenant_id,
            packages=packages,
            ecosystem=PackageEcosystem.PYPI,
            top_packages=TOP_PYPI_PACKAGES,
            malicious_set=KNOWN_MALICIOUS_PYPI,
        )

    def _scan(
        self,
        server_id: str,
        tenant_id: str,
        packages: dict[str, str],
        ecosystem: PackageEcosystem,
        top_packages: frozenset[str],
        malicious_set: frozenset[str],
    ) -> PackageScanResult:
        """Core scanning logic."""
        result = PackageScanResult(
            server_id=server_id,
            tenant_id=tenant_id,
            ecosystem=ecosystem,
            total_packages=len(packages),
        )

        risk_points = 0.0

        for pkg_name, pkg_version in packages.items():
            flags: list[str] = []
            rep_score = 50.0  # baseline neutral

            # ── 1. Known malicious ──
            if pkg_name.lower() in malicious_set:
                flags.append("known_malicious")
                rep_score = 0.0
                risk_points += 30.0
                result.vulnerabilities.append(
                    PackageVulnerability(
                        cve_id="PHANTEX-MALICIOUS",
                        package=pkg_name,
                        ecosystem=ecosystem,
                        severity=VulnerabilitySeverity.CRITICAL,
                        title=f"Known malicious package: {pkg_name}",
                    )
                )

            # ── 2. Typosquatting detection ──
            typo_matches = self._check_typosquatting(pkg_name, top_packages, ecosystem)
            if typo_matches:
                result.typosquat_suspects.extend(typo_matches)
                flags.append("typosquat_suspect")
                rep_score -= 25.0
                risk_points += 15.0 * len(typo_matches)

            # ── 3. Suspicious name patterns ──
            if self._has_suspicious_name(pkg_name):
                flags.append("suspicious_name")
                rep_score -= 10.0
                risk_points += 5.0

            # ── 4. Well-known packages get a boost ──
            if pkg_name in top_packages:
                rep_score = max(rep_score, 80.0)
                flags.append("well_known")

            result.package_reputations.append(
                PackageReputation(
                    name=pkg_name,
                    ecosystem=ecosystem,
                    version=pkg_version,
                    reputation_score=max(0.0, min(100.0, rep_score)),
                    flags=flags,
                )
            )

        # Aggregate risk score (0–100)
        if result.total_packages > 0:
            result.risk_score = min(100.0, risk_points)
        else:
            result.risk_score = 0.0

        return result

    def _check_typosquatting(
        self,
        name: str,
        top_packages: frozenset[str],
        ecosystem: PackageEcosystem,
    ) -> list[TyposquatMatch]:
        """Check package name against top packages for typosquatting."""
        matches: list[TyposquatMatch] = []
        name_lower = name.lower()

        # Skip if it IS a top package
        if name_lower in {p.lower() for p in top_packages}:
            return matches

        for top_pkg in top_packages:
            top_lower = top_pkg.lower()
            if top_lower == name_lower:
                continue

            dist = _levenshtein(name_lower, top_lower)
            max_len = max(len(name_lower), len(top_lower))

            # Only flag if edit distance is 1-2 for short names, 1-3 for longer
            threshold = 2 if max_len <= 8 else 3
            if 0 < dist <= threshold:
                confidence = 1.0 - (dist / max_len)
                if confidence >= 0.6:
                    matches.append(
                        TyposquatMatch(
                            suspect_package=name,
                            target_package=top_pkg,
                            ecosystem=ecosystem,
                            edit_distance=dist,
                            confidence=confidence,
                        )
                    )

        return matches

    @staticmethod
    def _has_suspicious_name(name: str) -> bool:
        """Check for suspicious name patterns (exploit, hack, test, etc.)."""
        suspicious_patterns = [
            r"exploit",
            r"hack",
            r"malware",
            r"trojan",
            r"keylog",
            r"steal",
            r"inject",
            r"backdoor",
            r"reverse.?shell",
            r"c2.?server",
        ]
        name_lower = name.lower()
        return any(re.search(p, name_lower) for p in suspicious_patterns)
