# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — MCP Supply Chain API Schemas.

Pydantic models for MCP server inventory, scan results, anomalies,
and risk assessments.  Used by ``routers/mcp_supply_chain.py``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

# ── MCP Server ──────────────────────────────────────────────────────────

class MCPServerResponse(BaseModel):
    id: str
    server_id: str
    name: str | None = None
    trust_level: str = "unknown"
    risk_score: float = 0.0
    risk_level: str = "minimal"
    content_hash: str | None = None
    protocol_version: str | None = None
    capabilities: list[Any] = []
    metadata: dict[str, Any] = {}
    connection_count: int = 0
    anomaly_count: int = 0
    error_rate: float = 0.0
    last_seen: str | None = None
    first_seen: str | None = None
    blocked_at: str | None = None
    blocked_reason: str | None = None

    model_config = {"from_attributes": True}

class MCPServerListResponse(BaseModel):
    items: list[MCPServerResponse] = []
    total: int = 0

class MCPServerBlockRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)

class MCPServerUnblockRequest(BaseModel):
    pass

# ── Scan Results ────────────────────────────────────────────────────────

class MCPScanResultResponse(BaseModel):
    id: str
    server_id: str
    scan_type: str = "package"
    ecosystem: str | None = None
    total_packages: int = 0
    clean_packages: int = 0
    vulnerable: int = 0
    malicious: int = 0
    typosquat: int = 0
    reputation_avg: float = 1.0
    findings: list[Any] = []
    scanned_at: str | None = None

    model_config = {"from_attributes": True}

class MCPScanListResponse(BaseModel):
    items: list[MCPScanResultResponse] = []
    total: int = 0

class MCPScanRequest(BaseModel):
    """Request to trigger a package scan on an MCP server."""

    ecosystem: str = Field(default="npm", pattern="^(npm|pypi)$")
    packages: list[str] = Field(min_length=1, max_length=500)

    @field_validator("packages")
    @classmethod
    def validate_package_names(cls, v: list[str]) -> list[str]:
        for name in v:
            if len(name) > 256:
                raise ValueError(f"Package name exceeds 256 chars: {name[:32]}…")
            if not name.strip():
                raise ValueError("Empty package name")
        return v

# ── Anomalies ───────────────────────────────────────────────────────────

class MCPAnomalyResponse(BaseModel):
    id: str
    server_id: str
    anomaly_type: str
    severity: str = "medium"
    detail: str
    raw_evidence: str | None = None
    detected_at: str | None = None

    model_config = {"from_attributes": True}

class MCPAnomalyListResponse(BaseModel):
    items: list[MCPAnomalyResponse] = []
    total: int = 0

# ── Risk Assessment ─────────────────────────────────────────────────────

class RiskBreakdownComponent(BaseModel):
    score: float
    weight: float
    weighted: float
    details: str = ""

class RiskBreakdownResponse(BaseModel):
    components: dict[str, RiskBreakdownComponent] = {}

class MCPRiskAssessmentResponse(BaseModel):
    server_id: str
    tenant_id: str
    score: float
    level: str
    action: str
    breakdown: RiskBreakdownResponse
    assessed_at: str
    trend: str = "stable"
    auto_blocked: bool = False

# ── Supply Chain Dashboard Stats ────────────────────────────────────────

class MCPSupplyChainStatsResponse(BaseModel):
    total_servers: int = 0
    by_trust_level: dict[str, int] = {}
    by_risk_level: dict[str, int] = {}
    total_anomalies: int = 0
    critical_anomalies: int = 0
    total_scans: int = 0
    servers_blocked: int = 0
    avg_risk_score: float = 0.0
