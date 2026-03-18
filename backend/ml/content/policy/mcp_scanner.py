# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — MCP Response Scanner (JB2).

Scans MCP server responses through the JB1 ``ContentAnalyzer`` to detect
indirect prompt injection embedded in tool/MCP responses.

This is critical because MCP is the primary supply-chain vector for AI
agent attacks — a compromised MCP server can inject payloads into every
agent that consumes its responses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ml.content.analyzer import ContentAnalyzer
from ml.content.policy.mcp_registry import MCPServerRegistry, MCPTrustLevel
from ml.content.verdict import ContentVerdict, Decision

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class MCPScanResult:
    """Result of scanning an MCP response."""

    server_id: str
    tenant_id: str
    trust_level: MCPTrustLevel
    content_verdict: ContentVerdict
    should_block: bool = False
    should_alert: bool = False
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

class MCPResponseScanner:
    """Scan MCP server responses for injection payloads.

    Parameters
    ----------
    analyzer:
        The shared ContentAnalyzer instance (JB1).
    registry:
        The MCP server registry for trust-level lookup.
    """

    def __init__(
        self,
        analyzer: ContentAnalyzer | None = None,
        registry: MCPServerRegistry | None = None,
    ) -> None:
        self._analyzer = analyzer or ContentAnalyzer()
        self._registry = registry or MCPServerRegistry()

    def scan(
        self,
        tenant_id: str,
        server_id: str,
        response_text: str,
        metadata: dict[str, Any] | None = None,
    ) -> MCPScanResult:
        """Scan an MCP response and return a result.

        Policy interaction with trust level:
        - ``BLOCKED`` servers → result.should_block = True (no content scan needed)
        - ``SUSPICIOUS`` servers → lower threshold for alerting
        - ``VERIFIED`` servers → alert only on high-confidence detections
        """
        trust = self._registry.trust_level(tenant_id, server_id)

        # ── Blocked server → immediate block
        if trust == MCPTrustLevel.BLOCKED:
            return MCPScanResult(
                server_id=server_id,
                tenant_id=tenant_id,
                trust_level=trust,
                content_verdict=ContentVerdict.benign(
                    classifier_name="mcp_scanner",
                ),
                should_block=True,
                should_alert=True,
                reason=f"MCP server '{server_id}' is BLOCKED",
            )

        # ── Content scan
        verdict = self._analyzer.analyze(
            response_text,
            metadata={"source": "mcp_response", "server_id": server_id, **(metadata or {})},
        )

        # ── Policy decision based on trust + content verdict
        should_block = False
        should_alert = False
        reason = ""

        if trust == MCPTrustLevel.SUSPICIOUS:
            # Lower bar: any non-benign content → alert
            if verdict.score > 0.2:
                should_alert = True
                reason = f"Suspicious MCP server '{server_id}' with content score {verdict.score:.2f}"
            if verdict.decision == Decision.BLOCK:
                should_block = True
                reason = f"Suspicious MCP server '{server_id}' with BLOCK-level content"

        elif trust == MCPTrustLevel.UNKNOWN:
            # Medium bar
            if verdict.score > 0.3:
                should_alert = True
                reason = f"Unknown MCP server '{server_id}' with elevated content score {verdict.score:.2f}"
            if verdict.decision == Decision.BLOCK:
                should_block = True

        elif trust in (MCPTrustLevel.VERIFIED, MCPTrustLevel.KNOWN):
            # Higher bar: only alert on strong signals
            if verdict.decision in (Decision.ALERT, Decision.BLOCK):
                should_alert = True
                reason = f"Trusted MCP server '{server_id}' returned suspicious content"
            if verdict.decision == Decision.BLOCK:
                should_block = True

        return MCPScanResult(
            server_id=server_id,
            tenant_id=tenant_id,
            trust_level=trust,
            content_verdict=verdict,
            should_block=should_block,
            should_alert=should_alert,
            reason=reason,
        )

    @property
    def analyzer(self) -> ContentAnalyzer:
        return self._analyzer

    @property
    def registry(self) -> MCPServerRegistry:
        return self._registry
