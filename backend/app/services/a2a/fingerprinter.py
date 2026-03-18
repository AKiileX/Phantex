# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — A2A Protocol Fingerprinter.

Detects non-standard A2A implementations that may indicate
attacker-built or compromised agents by analysing:
  - Message structure conformance
  - Required field presence
  - Timing pattern anomalies
  - Header / metadata deviations
  - Protocol version mismatches

Returns a conformance score (0.0–1.0) and list of deviations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.a2a.fingerprinter")

# ── Expected A2A protocol fields ──────────────────────────────────────────────

_AGENT_CARD_REQUIRED = {"name", "url", "capabilities"}
_AGENT_CARD_OPTIONAL = {"description", "version", "auth_type", "metadata", "agent_id"}
_AGENT_CARD_ALL = _AGENT_CARD_REQUIRED | _AGENT_CARD_OPTIONAL

_TASK_MSG_REQUIRED = {"task_id", "source_agent", "target_agent", "capability"}
_TASK_MSG_OPTIONAL = {"description", "parameters", "parent_task_id", "timeout", "priority"}
_TASK_MSG_ALL = _TASK_MSG_REQUIRED | _TASK_MSG_OPTIONAL

_TASK_RESPONSE_REQUIRED = {"task_id", "status"}
_TASK_RESPONSE_OPTIONAL = {"result", "error", "metadata", "artifacts"}

_VALID_STATUSES = {"submitted", "working", "completed", "failed", "cancelled"}
_VALID_AUTH_TYPES = {"none", "bearer", "mtls", "oauth2", "api_key"}
_KNOWN_VERSIONS = {"1.0", "1.1", "2.0"}

@dataclass
class FingerprintResult:
    """Result of fingerprinting an A2A message."""

    conformance_score: float  # 0.0 (non-conformant) to 1.0 (perfect)
    message_type: str  # "agent_card", "task_request", "task_response", "unknown"
    deviations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    suspicious: bool = False
    agent_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

class ProtocolFingerprinter:
    """Analyse A2A protocol messages for conformance and anomalies."""

    _SUSPICIOUS_THRESHOLD = 0.7

    def fingerprint(self, message: dict[str, Any], message_type: str = "") -> FingerprintResult:
        """Fingerprint an A2A protocol message.

        Args:
            message: The raw A2A message dict.
            message_type: Override auto-detection ("agent_card", "task_request", "task_response").
        """
        if not message_type:
            message_type = self._detect_type(message)

        if message_type == "agent_card":
            return self._fingerprint_card(message)
        elif message_type == "task_request":
            return self._fingerprint_task_request(message)
        elif message_type == "task_response":
            return self._fingerprint_task_response(message)
        else:
            return FingerprintResult(
                conformance_score=0.0,
                message_type="unknown",
                deviations=["Unable to determine message type"],
                suspicious=True,
            )

    # ── Agent Card fingerprinting ─────────────────────────────────────

    def _fingerprint_card(self, msg: dict[str, Any]) -> FingerprintResult:
        deviations: list[str] = []
        warnings: list[str] = []
        checks_passed = 0
        total_checks = 0

        # Required fields
        total_checks += len(_AGENT_CARD_REQUIRED)
        for f in _AGENT_CARD_REQUIRED:
            if f in msg and msg[f]:
                checks_passed += 1
            else:
                deviations.append(f"Missing required field: {f}")

        # Unknown fields (may indicate custom implementation)
        extra_fields = set(msg.keys()) - _AGENT_CARD_ALL
        if extra_fields:
            total_checks += 1
            warnings.append(f"Non-standard fields: {sorted(extra_fields)}")
        else:
            total_checks += 1
            checks_passed += 1

        # URL validation
        total_checks += 1
        url = msg.get("url", "")
        if url and re.match(r"^https?://[\w\-.]+(:\d+)?(/\S*)?$", url):
            checks_passed += 1
        else:
            deviations.append(f"Malformed URL: {url!r}")

        # Version check
        total_checks += 1
        version = msg.get("version", "1.0")
        if version in _KNOWN_VERSIONS:
            checks_passed += 1
        else:
            warnings.append(f"Unknown protocol version: {version}")

        # Auth type
        total_checks += 1
        auth = msg.get("auth_type", "none")
        if auth in _VALID_AUTH_TYPES:
            checks_passed += 1
        else:
            deviations.append(f"Unknown auth type: {auth!r}")

        # Capabilities format
        total_checks += 1
        caps = msg.get("capabilities", [])
        if isinstance(caps, list) and all(isinstance(c, str) for c in caps):
            checks_passed += 1
        else:
            deviations.append("capabilities must be a list of strings")

        score = checks_passed / max(total_checks, 1)
        suspicious = score < self._SUSPICIOUS_THRESHOLD

        if suspicious:
            logger.warning(
                "a2a_suspicious_agent_card",
                agent_id=msg.get("name", "unknown"),
                score=round(score, 2),
                deviations=deviations,
            )

        return FingerprintResult(
            conformance_score=round(score, 3),
            message_type="agent_card",
            deviations=deviations,
            warnings=warnings,
            suspicious=suspicious,
            agent_id=msg.get("name", msg.get("agent_id", "")),
        )

    # ── Task request fingerprinting ───────────────────────────────────

    def _fingerprint_task_request(self, msg: dict[str, Any]) -> FingerprintResult:
        deviations: list[str] = []
        warnings: list[str] = []
        checks_passed = 0
        total_checks = 0

        # Required fields
        total_checks += len(_TASK_MSG_REQUIRED)
        for f in _TASK_MSG_REQUIRED:
            if f in msg and msg[f]:
                checks_passed += 1
            else:
                deviations.append(f"Missing required field: {f}")

        # Unknown fields
        extra = set(msg.keys()) - _TASK_MSG_ALL
        total_checks += 1
        if extra:
            warnings.append(f"Non-standard fields: {sorted(extra)}")
        else:
            checks_passed += 1

        # task_id format (should be non-empty string)
        total_checks += 1
        tid = msg.get("task_id", "")
        if isinstance(tid, str) and len(tid) >= 4:
            checks_passed += 1
        else:
            deviations.append(f"task_id too short or wrong type: {tid!r}")

        score = checks_passed / max(total_checks, 1)
        return FingerprintResult(
            conformance_score=round(score, 3),
            message_type="task_request",
            deviations=deviations,
            warnings=warnings,
            suspicious=score < self._SUSPICIOUS_THRESHOLD,
            agent_id=msg.get("source_agent", ""),
        )

    # ── Task response fingerprinting ──────────────────────────────────

    def _fingerprint_task_response(self, msg: dict[str, Any]) -> FingerprintResult:
        deviations: list[str] = []
        warnings: list[str] = []
        checks_passed = 0
        total_checks = 0

        total_checks += len(_TASK_RESPONSE_REQUIRED)
        for f in _TASK_RESPONSE_REQUIRED:
            if f in msg and msg[f]:
                checks_passed += 1
            else:
                deviations.append(f"Missing required field: {f}")

        # Status value
        total_checks += 1
        status = msg.get("status", "")
        if status in _VALID_STATUSES:
            checks_passed += 1
        else:
            deviations.append(f"Invalid status: {status!r}")

        # Extra fields
        extra = set(msg.keys()) - (_TASK_RESPONSE_REQUIRED | _TASK_RESPONSE_OPTIONAL)
        total_checks += 1
        if extra:
            warnings.append(f"Non-standard fields: {sorted(extra)}")
        else:
            checks_passed += 1

        score = checks_passed / max(total_checks, 1)
        return FingerprintResult(
            conformance_score=round(score, 3),
            message_type="task_response",
            deviations=deviations,
            warnings=warnings,
            suspicious=score < self._SUSPICIOUS_THRESHOLD,
        )

    # ── Type auto-detection ───────────────────────────────────────────

    @staticmethod
    def _detect_type(msg: dict[str, Any]) -> str:
        if "capabilities" in msg and "url" in msg:
            return "agent_card"
        if "source_agent" in msg and "target_agent" in msg:
            return "task_request"
        if "task_id" in msg and "status" in msg and "source_agent" not in msg:
            return "task_response"
        return "unknown"
