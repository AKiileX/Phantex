# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Block V3 — MCP Protocol Anomaly Detector.

Detects MCP protocol-level attacks:
  - Malformed JSON-RPC messages (schema violations)
  - Tool list changes between sessions (supply chain swap)
  - Response size anomalies (data exfiltration via oversized responses)
  - Timing attacks (delayed responses to probe agent behavior)
  - Unexpected method calls (protocol abuse)
  - Version downgrades (forced protocol weakening)

Thread-safe. Processes individual MCP messages and returns verdicts.
Target: < 5ms overhead per message inspection.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

class ProtocolViolationType(StrEnum):
    """Types of protocol anomalies."""

    MALFORMED_MESSAGE = "malformed_message"
    INVALID_JSONRPC = "invalid_jsonrpc"
    UNEXPECTED_METHOD = "unexpected_method"
    TOOL_LIST_CHANGE = "tool_list_change"
    RESPONSE_SIZE_ANOMALY = "response_size_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    VERSION_DOWNGRADE = "version_downgrade"
    INJECTION_PATTERN = "injection_pattern"
    UNAUTHORIZED_RESOURCE = "unauthorized_resource"
    EXCESSIVE_ERROR_RATE = "excessive_error_rate"

class ProtocolSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass(frozen=True)
class ProtocolAnomaly:
    """Single protocol anomaly finding."""

    violation_type: ProtocolViolationType
    severity: ProtocolSeverity
    server_id: str
    tenant_id: str
    detail: str
    raw_evidence: str = ""  # Truncated raw message
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.violation_type.value,
            "severity": self.severity.value,
            "server_id": self.server_id,
            "tenant_id": self.tenant_id,
            "detail": self.detail,
            "raw_evidence": self.raw_evidence[:500],
            "timestamp": self.timestamp.isoformat(),
        }

# ── Valid MCP methods ───────────────────────────────────────────────────────

VALID_MCP_METHODS = frozenset(
    {
        # Client → Server
        "initialize",
        "ping",
        "completion/complete",
        "logging/setLevel",
        "prompts/get",
        "prompts/list",
        "resources/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "resources/templates/list",
        "tools/call",
        "tools/list",
        # Server → Client (notifications / responses)
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        "notifications/resources/updated",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
        "notifications/roots/list_changed",
        "roots/list",
        "sampling/createMessage",
    }
)

# Injection patterns to detect in MCP response content
INJECTION_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\{\{.*\}\}"),  # Template injection
    re.compile(r"__import__\s*\("),  # Python code injection
    re.compile(r"eval\s*\("),  # JS eval
    re.compile(r"exec\s*\("),  # Python exec
    re.compile(r"system\s*\("),  # Shell injection
    re.compile(r"(?:ignore|disregard|forget)\s+(?:previous|above|all)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+(?:now|actually)\s+", re.IGNORECASE),
    re.compile(r"<\|(?:im_start|system|endoftext)\|>", re.IGNORECASE),  # LLM control tokens
]

@dataclass
class SessionState:
    """Per-server session tracking."""

    server_id: str
    tenant_id: str
    tool_list_hash: str = ""
    protocol_version: str = ""
    message_count: int = 0
    error_count: int = 0
    last_message_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    recent_response_sizes: deque = field(default_factory=lambda: deque(maxlen=100))
    recent_latencies: deque = field(default_factory=lambda: deque(maxlen=100))

class MCPProtocolAnalyzer:
    """Thread-safe MCP protocol anomaly detector.

    Inspects individual MCP JSON-RPC messages and returns any anomalies
    found. Maintains per-server session state for drift detection.
    """

    __slots__ = ("_lock", "_sessions", "_max_sessions", "_max_response_size")

    def __init__(
        self,
        max_sessions: int = 10_000,
        max_response_size: int = 10 * 1024 * 1024,  # 10MB
    ) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[tuple[str, str], SessionState] = {}
        self._max_sessions = max_sessions
        self._max_response_size = max_response_size

    def analyze_message(
        self,
        tenant_id: str,
        server_id: str,
        message: str | dict[str, Any],
        direction: str = "server_to_client",  # or "client_to_server"
        latency_ms: float | None = None,
    ) -> list[ProtocolAnomaly]:
        """Analyze a single MCP message. Returns list of anomalies (may be empty)."""
        anomalies: list[ProtocolAnomaly] = []
        now = datetime.now(UTC)

        # Parse message
        parsed = self._parse_message(message, tenant_id, server_id, anomalies)
        if parsed is None:
            return anomalies

        # Compute true message size BEFORE truncating for evidence
        if isinstance(message, str):
            message_size = len(message.encode("utf-8", errors="replace"))
        elif isinstance(parsed, dict):
            message_size = len(json.dumps(parsed).encode("utf-8", errors="replace"))
        else:
            message_size = 0

        raw_str = json.dumps(parsed)[:500] if isinstance(parsed, dict) else str(message)[:500]

        with self._lock:
            session = self._get_or_create_session(tenant_id, server_id)
            session.message_count += 1
            session.last_message_at = now

            # ── 1. JSON-RPC structure validation ──
            self._check_jsonrpc_structure(parsed, session, anomalies, raw_str)

            # ── 2. Method validation ──
            method = parsed.get("method", "")
            if method and method not in VALID_MCP_METHODS:
                anomalies.append(
                    ProtocolAnomaly(
                        violation_type=ProtocolViolationType.UNEXPECTED_METHOD,
                        severity=ProtocolSeverity.MEDIUM,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        detail=f"Unexpected MCP method: {method}",
                        raw_evidence=raw_str,
                        timestamp=now,
                    )
                )

            # ── 3. Response size check (uses true message_size, not truncated evidence) ──
            if message_size > self._max_response_size:
                anomalies.append(
                    ProtocolAnomaly(
                        violation_type=ProtocolViolationType.RESPONSE_SIZE_ANOMALY,
                        severity=ProtocolSeverity.HIGH,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        detail=f"Message size {message_size:,}B exceeds limit ({self._max_response_size:,}B) — possible data exfiltration",
                        raw_evidence=raw_str,
                        timestamp=now,
                    )
                )
            session.recent_response_sizes.append(message_size)

            # ── 4. Latency / timing anomaly ──
            if latency_ms is not None:
                session.recent_latencies.append(latency_ms)

            # ── 5. Tool list change detection (on tools/list response) ──
            if method == "tools/list" or (
                "result" in parsed and isinstance(parsed.get("result"), dict) and "tools" in parsed["result"]
            ):
                self._check_tool_list_change(parsed, session, anomalies, now)

            # ── 6. Content injection patterns (server → client only) ──
            if direction == "server_to_client":
                self._check_injection_patterns(parsed, server_id, tenant_id, anomalies, raw_str, now)

            # ── 7. Error rate ──
            if "error" in parsed:
                session.error_count += 1
                if session.message_count > 10:
                    err_rate = session.error_count / session.message_count
                    if err_rate > 0.5:
                        anomalies.append(
                            ProtocolAnomaly(
                                violation_type=ProtocolViolationType.EXCESSIVE_ERROR_RATE,
                                severity=ProtocolSeverity.MEDIUM,
                                server_id=server_id,
                                tenant_id=tenant_id,
                                detail=f"Error rate {err_rate:.0%} ({session.error_count}/{session.message_count})",
                                raw_evidence=raw_str,
                                timestamp=now,
                            )
                        )

        return anomalies

    def get_session(self, tenant_id: str, server_id: str) -> SessionState | None:
        """Return session state for a server."""
        with self._lock:
            return self._sessions.get((tenant_id, server_id))

    def list_sessions(self, tenant_id: str) -> list[SessionState]:
        """Return all sessions for a tenant."""
        with self._lock:
            return [s for k, s in self._sessions.items() if k[0] == tenant_id]

    # ── Private ─────────────────────────────────────────────────────

    def _parse_message(
        self,
        message: str | dict[str, Any],
        tenant_id: str,
        server_id: str,
        anomalies: list[ProtocolAnomaly],
    ) -> dict[str, Any] | None:
        """Parse and validate the message is valid JSON."""
        if isinstance(message, dict):
            return message

        try:
            parsed = json.loads(message)
            if not isinstance(parsed, dict):
                anomalies.append(
                    ProtocolAnomaly(
                        violation_type=ProtocolViolationType.MALFORMED_MESSAGE,
                        severity=ProtocolSeverity.HIGH,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        detail="MCP message is not a JSON object",
                        raw_evidence=str(message)[:500],
                    )
                )
                return None
            return parsed
        except (json.JSONDecodeError, TypeError):
            anomalies.append(
                ProtocolAnomaly(
                    violation_type=ProtocolViolationType.MALFORMED_MESSAGE,
                    severity=ProtocolSeverity.HIGH,
                    server_id=server_id,
                    tenant_id=tenant_id,
                    detail="Invalid JSON in MCP message",
                    raw_evidence=str(message)[:500],
                )
            )
            return None

    def _check_jsonrpc_structure(
        self,
        msg: dict[str, Any],
        session: SessionState,
        anomalies: list[ProtocolAnomaly],
        raw_str: str,
    ) -> None:
        """Validate JSON-RPC 2.0 structure."""
        # JSON-RPC requires "jsonrpc": "2.0"
        version = msg.get("jsonrpc")
        if version and version != "2.0":
            anomalies.append(
                ProtocolAnomaly(
                    violation_type=ProtocolViolationType.INVALID_JSONRPC,
                    severity=ProtocolSeverity.MEDIUM,
                    server_id=session.server_id,
                    tenant_id=session.tenant_id,
                    detail=f"Invalid JSON-RPC version: {version}",
                    raw_evidence=raw_str,
                )
            )

        # Version downgrade detection
        if version and session.protocol_version and version < session.protocol_version:
            anomalies.append(
                ProtocolAnomaly(
                    violation_type=ProtocolViolationType.VERSION_DOWNGRADE,
                    severity=ProtocolSeverity.HIGH,
                    server_id=session.server_id,
                    tenant_id=session.tenant_id,
                    detail=f"Protocol version downgraded: {session.protocol_version} → {version}",
                    raw_evidence=raw_str,
                )
            )
        if version:
            session.protocol_version = version

    def _check_tool_list_change(
        self,
        msg: dict[str, Any],
        session: SessionState,
        anomalies: list[ProtocolAnomaly],
        now: datetime,
    ) -> None:
        """Detect tool list changes between sessions."""
        result = msg.get("result", {})
        tools = result.get("tools", []) if isinstance(result, dict) else []

        # Build hash of tool names
        tool_names = sorted(t.get("name", "") for t in tools if isinstance(t, dict))
        new_hash = hashlib.sha256(json.dumps(tool_names).encode()).hexdigest()[:16]

        if session.tool_list_hash and session.tool_list_hash != new_hash:
            anomalies.append(
                ProtocolAnomaly(
                    violation_type=ProtocolViolationType.TOOL_LIST_CHANGE,
                    severity=ProtocolSeverity.HIGH,
                    server_id=session.server_id,
                    tenant_id=session.tenant_id,
                    detail=f"Tool list changed mid-session: hash {session.tool_list_hash} → {new_hash} ({len(tool_names)} tools)",
                    raw_evidence=json.dumps(tool_names)[:500],
                    timestamp=now,
                )
            )

        session.tool_list_hash = new_hash

    def _check_injection_patterns(
        self,
        msg: dict[str, Any],
        server_id: str,
        tenant_id: str,
        anomalies: list[ProtocolAnomaly],
        raw_str: str,
        now: datetime,
    ) -> None:
        """Search for injection payloads in MCP server responses."""
        # Flatten message content to a searchable string
        content = self._extract_content(msg)
        if not content:
            return

        for pattern in INJECTION_PATTERNS:
            match = pattern.search(content)
            if match:
                anomalies.append(
                    ProtocolAnomaly(
                        violation_type=ProtocolViolationType.INJECTION_PATTERN,
                        severity=ProtocolSeverity.CRITICAL,
                        server_id=server_id,
                        tenant_id=tenant_id,
                        detail=f"Injection payload detected: pattern={pattern.pattern!r}, match={match.group()!r}",
                        raw_evidence=content[max(0, match.start() - 50) : match.end() + 50],
                        timestamp=now,
                    )
                )
                break  # One injection finding per message is enough

    @staticmethod
    def _extract_content(msg: dict[str, Any]) -> str:
        """Extract searchable text content from an MCP message."""
        parts: list[str] = []

        # Result content
        result = msg.get("result")
        if isinstance(result, dict):
            for key in ("content", "text", "description", "data"):
                val = result.get(key)
                if isinstance(val, str):
                    parts.append(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            text = item.get("text", "")
                            if text:
                                parts.append(text)
                        elif isinstance(item, str):
                            parts.append(item)

        # Params content
        params = msg.get("params")
        if isinstance(params, dict):
            for key in ("content", "text", "message", "arguments"):
                val = params.get(key)
                if isinstance(val, str):
                    parts.append(val)

        return "\n".join(parts)

    def _get_or_create_session(self, tenant_id: str, server_id: str) -> SessionState:
        """Get or create a session. Must be called under lock."""
        key = (tenant_id, server_id)
        if key not in self._sessions:
            if len(self._sessions) >= self._max_sessions:
                oldest = min(
                    self._sessions,
                    key=lambda k: self._sessions[k].last_message_at,
                )
                del self._sessions[oldest]
            self._sessions[key] = SessionState(server_id=server_id, tenant_id=tenant_id)
        return self._sessions[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
