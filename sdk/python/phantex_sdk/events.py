# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK event definitions.

Matches the protobuf schema (events.proto) for tool call / tool response events.
Events are plain dataclasses — no protobuf dependency required at runtime.
Serialized to JSON dicts for transport.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any

# ── Event Types (mirrors EventType in events.proto) ──────────────────────────

class EventType(IntEnum):
    """Event type codes — must match proto/phantex/v1/events.proto."""

    UNSPECIFIED = 0
    PROCESS_EXEC = 1
    PROCESS_EXIT = 2
    FILE_OPEN = 10
    FILE_WRITE = 11
    FILE_READ = 12
    NETWORK_CONNECT = 20
    NETWORK_ACCEPT = 21
    NETWORK_DNS = 22
    MEMORY_MMAP = 30
    AGENT_DISCOVERED = 40
    AGENT_TERMINATED = 41
    TOOL_CALL = 50
    TOOL_RESPONSE = 51
    ALERT_FIRED = 60

class Severity(IntEnum):
    """Severity levels — must match proto/phantex/v1/events.proto."""

    UNSPECIFIED = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

# ── Helper Functions ──────────────────────────────────────────────────────────

def _event_id() -> str:
    """Generate a UUID v4 event ID (hex, no dashes)."""
    return uuid.uuid4().hex

def _timestamp_ns() -> int:
    """Current time in nanoseconds since epoch."""
    return int(time.time() * 1_000_000_000)

def _hash_prompt(prompt: str) -> str:
    """SHA-256 hash of prompt content. Never store plaintext prompts."""
    return hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()

def _safe_serialize(obj: Any, max_bytes: int = 4096) -> str:
    """
    Safely serialize an object to JSON string, truncated to max_bytes.
    Never raises — returns "<unserializable>" on failure.
    """
    try:
        raw = json.dumps(obj, default=str, ensure_ascii=False)
        if len(raw) > max_bytes:
            return raw[: max_bytes - 3] + "..."
        return raw
    except Exception:
        return "<unserializable>"

# ── Event Dataclasses ─────────────────────────────────────────────────────────

@dataclass(slots=True)
class ToolCallEvent:
    """
    A tool/function call captured by an SDK hook.

    Maps to EventType.TOOL_CALL (50) in the protobuf schema.
    """

    # ── Identity ──────────────────────────────────
    event_id: str = field(default_factory=_event_id)
    event_type: int = field(default=EventType.TOOL_CALL, init=False)
    timestamp_ns: int = field(default_factory=_timestamp_ns)

    # ── Agent/Tenant context ──────────────────────
    tenant_id: str = ""
    agent_paid: str = ""
    pid: int = 0

    # ── Tool info ─────────────────────────────────
    tool_name: str = ""
    tool_input: str = ""  # Serialized arguments (truncated, redacted)
    protocol: str = ""  # "langchain_tool", "autogen", "crewai", "http", etc.
    framework: str = ""  # "langchain", "autogen", "crewai"

    # ── LLM call info (for HTTP / ChatModel hooks) ─
    model_name: str = ""  # e.g., "gpt-4", "claude-3-opus"
    prompt_hash: str = ""  # SHA-256 of prompt content
    input_tokens: int = 0
    output_tokens: int = 0

    # ── Trace context ─────────────────────────────
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""

    # ── Severity ──────────────────────────────────
    severity: int = field(default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON transport. Keeps False/0 when semantically meaningful."""
        d = {}
        for k, v in asdict(self).items():
            # Keep False booleans and 0 integers (semantically meaningful)
            # Drop empty strings, None, and empty collections
            if v is not None and v != "" and v != []:
                d[k] = v
        return d

@dataclass(slots=True)
class ToolResponseEvent:
    """
    A tool/function response captured by an SDK hook.

    Maps to EventType.TOOL_RESPONSE (51) in the protobuf schema.
    """

    # ── Identity ──────────────────────────────────
    event_id: str = field(default_factory=_event_id)
    event_type: int = field(default=EventType.TOOL_RESPONSE, init=False)
    timestamp_ns: int = field(default_factory=_timestamp_ns)

    # ── Agent/Tenant context ──────────────────────
    tenant_id: str = ""
    agent_paid: str = ""
    pid: int = 0

    # ── Tool info ─────────────────────────────────
    tool_name: str = ""
    protocol: str = ""
    framework: str = ""

    # ── Result ────────────────────────────────────
    success: bool = True
    duration_ns: int = 0  # Wall-clock time in nanoseconds
    output_size: int = 0  # Response size in bytes (content NOT captured)
    error_message: str = ""  # Only set on failure

    # ── LLM response info ─────────────────────────
    model_name: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    # ── Trace context ─────────────────────────────
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""

    # ── Severity ──────────────────────────────────
    severity: int = field(default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON transport. Keeps False/0 when semantically meaningful."""
        d = {}
        for k, v in asdict(self).items():
            if v is not None and v != "" and v != []:
                d[k] = v
        return d
