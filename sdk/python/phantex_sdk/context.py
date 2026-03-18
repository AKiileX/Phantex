# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK context management.

Uses contextvars (PEP 567) — works correctly in both threaded and async contexts.
Each coroutine / thread gets its own trace context automatically.
"""

from __future__ import annotations

import os
import uuid
from contextvars import ContextVar
from dataclasses import dataclass

# ── Context Variables ─────────────────────────────────────────────────────────

# Trace ID: groups related events in a single request/action chain
_trace_id: ContextVar[str] = ContextVar("phantex_trace_id", default="")

# Span ID: identifies the current operation within a trace
_span_id: ContextVar[str] = ContextVar("phantex_span_id", default="")

# Parent span ID: for nested operations (e.g., tool call inside chain)
_parent_span_id: ContextVar[str] = ContextVar("phantex_parent_span_id", default="")

# Agent PAID: Phantex Agent ID — set from env or auto-detected
_agent_paid: ContextVar[str] = ContextVar("phantex_agent_paid", default="")

# Framework name: which framework is currently active
_framework: ContextVar[str] = ContextVar("phantex_framework", default="")

# ── Public API ────────────────────────────────────────────────────────────────

def new_trace_id() -> str:
    """Generate a new trace ID (UUID v4 hex)."""
    return uuid.uuid4().hex

def new_span_id() -> str:
    """Generate a new span ID (first 16 chars of UUID v4 hex)."""
    return uuid.uuid4().hex[:16]

def get_trace_id() -> str:
    """Get the current trace ID, or generate one if not set."""
    tid = _trace_id.get()
    if not tid:
        tid = new_trace_id()
        _trace_id.set(tid)
    return tid

def set_trace_id(trace_id: str) -> None:
    _trace_id.set(trace_id)

def get_span_id() -> str:
    return _span_id.get()

def set_span_id(span_id: str) -> None:
    _span_id.set(span_id)

def get_parent_span_id() -> str:
    return _parent_span_id.get()

def set_parent_span_id(span_id: str) -> None:
    _parent_span_id.set(span_id)

def get_agent_paid() -> str:
    """Get agent PAID — from context, env var, or empty."""
    paid = _agent_paid.get()
    if not paid:
        paid = os.environ.get("PHANTEX_AGENT_ID", "")
        if paid:
            _agent_paid.set(paid)
    return paid

def set_agent_paid(paid: str) -> None:
    _agent_paid.set(paid)
    # Also set env var so the sensor's /proc scanner can discover us.
    # NOTE: os.environ is process-global. In multi-agent processes this is
    # a best-effort hint for /proc discovery; the ContextVar is the
    # authoritative per-coroutine value.
    try:
        os.environ["PHANTEX_AGENT_ID"] = paid
    except Exception:
        pass  # Non-critical — ContextVar is the primary storage

def get_framework() -> str:
    return _framework.get()

def set_framework(name: str) -> None:
    _framework.set(name)

@dataclass(frozen=True, slots=True)
class SpanContext:
    """Snapshot of the current context for embedding in events."""

    trace_id: str
    span_id: str
    parent_span_id: str
    agent_paid: str
    framework: str
    pid: int

    @classmethod
    def current(cls) -> SpanContext:
        return cls(
            trace_id=get_trace_id(),
            span_id=get_span_id(),
            parent_span_id=get_parent_span_id(),
            agent_paid=get_agent_paid(),
            framework=get_framework(),
            pid=os.getpid(),
        )
