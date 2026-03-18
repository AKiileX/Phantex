# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — Runtime security instrumentation for AI agent frameworks.

Auto-instruments on import:
    import phantex_sdk  # That's it — hooks are installed automatically

Supports:
    - LangChain (tool calls, LLM calls, chain invocations)
    - AutoGen (agent replies, inter-agent messages, group chat)
    - CrewAI (crew kickoff, task execution, agent execution)
    - HTTP (requests/httpx — detects LLM API calls to OpenAI, Anthropic, etc.)

Configuration via environment variables:
    PHANTEX_TOKEN          Auth token for sensor/gateway
    PHANTEX_TENANT_ID      Tenant UUID
    PHANTEX_AGENT_ID       Agent PAID (also set in env for sensor discovery)
    PHANTEX_TRANSPORT      auto|socket|http|buffer (default: auto)
    PHANTEX_HOOKS          auto|langchain,autogen,crewai,http,mcp|none (default: auto)
    PHANTEX_ENABLED        0|1 (default: 1)
    PHANTEX_DEBUG          0|1 (default: 0)
    PHANTEX_GATEWAY_ADDR   Gateway address (alias: PHANTEX_GATEWAY)
    PHANTEX_AUTO_INSTRUMENT  0|1 (default: 1) — set to 0 to disable auto-init at import

Manual control:
    from phantex_sdk.client import PhantexClient
    client = PhantexClient()
    client.start()
    # ... your agent code ...
    client.stop()
"""

from __future__ import annotations

import logging
import os

from ._version import __version__
from .client import PhantexClient
from .config import PhantexConfig, get_config, set_config
from .context import (
    SpanContext,
    get_agent_paid,
    get_trace_id,
    set_agent_paid,
    set_trace_id,
)
from .events import EventType, Severity, ToolCallEvent, ToolResponseEvent
from .sdk import PhantexSDK
from .transport import BufferTransport

__all__ = [
    "__version__",
    "PhantexSDK",
    "PhantexClient",
    "PhantexConfig",
    "BufferTransport",
    "EventType",
    "Severity",
    "ToolCallEvent",
    "ToolResponseEvent",
    "SpanContext",
    "get_config",
    "set_config",
    "get_agent_paid",
    "set_agent_paid",
    "get_trace_id",
    "set_trace_id",
    "init",
    "stop",
]

# ── Module-level state ────────────────────────────────────────────────────────

_client: PhantexClient | None = None

def init(**kwargs) -> PhantexClient:
    """
    Explicitly initialize the SDK with custom settings.

    Keyword arguments are passed to PhantexConfig constructor.
    Returns the PhantexClient instance.
    """
    global _client
    if _client is not None and _client.started:
        _client.stop()

    config = PhantexConfig(**kwargs) if kwargs else PhantexConfig.from_env()
    _client = PhantexClient(config=config)
    _client.start()
    return _client

def stop() -> None:
    """Stop the SDK and restore all hooks."""
    global _client
    if _client is not None:
        _client.stop()
        _client = None

def get_client() -> PhantexClient | None:
    """Return the current client instance (or None if not started)."""
    return _client

# ── Auto-instrumentation on import ────────────────────────────────────────────
# Only auto-start if PHANTEX_ENABLED != "0" and not in test mode

def _auto_init() -> None:
    """Auto-initialize the SDK on first import."""
    global _client

    # Kill switch
    if os.environ.get("PHANTEX_ENABLED", "1") == "0":
        return

    # Don't auto-init during pytest (tests should control init explicitly)
    if os.environ.get("PHANTEX_NO_AUTO_INIT", "0") == "1":
        return

    # PHANTEX_AUTO_INSTRUMENT=0 disables auto-init (same effect as NO_AUTO_INIT)
    if os.environ.get("PHANTEX_AUTO_INSTRUMENT", "1") == "0":
        return

    # Configure logging
    debug = os.environ.get("PHANTEX_DEBUG", "0") == "1"
    log_level = logging.DEBUG if debug else logging.WARNING
    logging.getLogger("phantex").setLevel(log_level)

    try:
        _client = PhantexClient()
        _client.start()
    except Exception as e:
        # NEVER crash the user's app due to SDK initialization failure
        logging.getLogger("phantex").warning("Phantex SDK auto-init failed: %s", e)

_auto_init()
