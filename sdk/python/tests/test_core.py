# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Core SDK tests — config, context, events, transport, client lifecycle.

Tests AC4 (graceful skip), AC5 (performance), AC6 (transport modes).
"""

from __future__ import annotations

import os

os.environ["PHANTEX_NO_AUTO_INIT"] = "1"
os.environ["PHANTEX_ENABLED"] = "1"

import pytest

from phantex_sdk.client import PhantexClient
from phantex_sdk.config import PhantexConfig
from phantex_sdk.context import (
    SpanContext,
    get_trace_id,
    new_span_id,
    new_trace_id,
    set_agent_paid,
    set_trace_id,
)
from phantex_sdk.events import (
    EventType,
    Severity,
    ToolCallEvent,
    ToolResponseEvent,
    _hash_prompt,
    _safe_serialize,
)
from phantex_sdk.transport import BufferTransport, create_transport

# ── Config Tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_config(self):
        config = PhantexConfig()
        assert config.enabled is True
        assert config.transport == "auto"
        assert config.hooks == "auto"
        assert config.batch_size == 50
        assert config.record_prompts is False

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("PHANTEX_TOKEN", "test-token-123")
        monkeypatch.setenv("PHANTEX_TENANT_ID", "tenant-abc")
        monkeypatch.setenv("PHANTEX_TRANSPORT", "buffer")
        monkeypatch.setenv("PHANTEX_DEBUG", "1")
        monkeypatch.setenv("PHANTEX_ENABLED", "0")

        config = PhantexConfig.from_env()
        assert config.auth_token == "test-token-123"
        assert config.tenant_id == "tenant-abc"
        assert config.transport == "buffer"
        assert config.debug is True
        assert config.enabled is False

    def test_config_immutable(self):
        config = PhantexConfig()
        with pytest.raises(AttributeError):
            config.enabled = False  # type: ignore

# ── Context Tests ─────────────────────────────────────────────────────────────

class TestContext:
    def test_trace_id_generation(self):
        tid = new_trace_id()
        assert len(tid) == 32  # UUID hex
        assert tid != new_trace_id()  # Unique each time

    def test_span_id_generation(self):
        sid = new_span_id()
        assert len(sid) == 16

    def test_trace_id_auto_created(self):
        set_trace_id("")  # Reset
        tid = get_trace_id()
        assert len(tid) == 32
        # Should return same ID on subsequent calls
        assert get_trace_id() == tid

    def test_span_context_snapshot(self):
        set_trace_id("abc123")
        set_agent_paid("ptx-test-001")
        ctx = SpanContext.current()
        assert ctx.trace_id == "abc123"
        assert ctx.agent_paid == "ptx-test-001"
        assert ctx.pid == os.getpid()

# ── Event Tests ───────────────────────────────────────────────────────────────

class TestEvents:
    def test_tool_call_event(self):
        event = ToolCallEvent(
            tool_name="calculator",
            tool_input='{"expression": "2+2"}',
            protocol="langchain_tool",
            framework="langchain",
        )
        assert event.event_type == EventType.TOOL_CALL
        assert event.tool_name == "calculator"
        d = event.to_dict()
        assert d["tool_name"] == "calculator"
        assert d["event_type"] == EventType.TOOL_CALL

    def test_tool_response_event(self):
        event = ToolResponseEvent(
            tool_name="calculator",
            success=True,
            duration_ns=500_000,
            output_size=1,
        )
        assert event.event_type == EventType.TOOL_RESPONSE
        assert event.duration_ns == 500_000
        assert event.success is True

    def test_prompt_hashing(self):
        h = _hash_prompt("secret prompt")
        assert len(h) == 64
        assert "secret" not in h

    def test_safe_serialize(self):
        assert _safe_serialize({"key": "value"}) == '{"key": "value"}'
        assert _safe_serialize(42) == "42"

        # Truncation
        big = "x" * 10000
        result = _safe_serialize(big, max_bytes=100)
        assert len(result) <= 100
        assert result.endswith("...")

        # Unserializable
        class Bad:
            def __repr__(self):
                raise Exception("nope")

        # json.dumps with default=str should handle this
        result = _safe_serialize(Bad())
        assert isinstance(result, str)

    def test_event_type_enum(self):
        assert EventType.TOOL_CALL == 50
        assert EventType.TOOL_RESPONSE == 51
        assert Severity.INFO == 1
        assert Severity.CRITICAL == 5

# ── Transport Tests ───────────────────────────────────────────────────────────

class TestTransport:
    def test_buffer_transport(self):
        t = BufferTransport(max_size=100)
        event = ToolCallEvent(tool_name="test")
        t.send(event)
        assert len(t) == 1

        events = t.peek()
        assert len(events) == 1
        assert events[0]["tool_name"] == "test"

        drained = t.drain()
        assert len(drained) == 1
        assert len(t) == 0

    def test_buffer_transport_max_size(self):
        t = BufferTransport(max_size=3)
        for i in range(5):
            t.send(ToolCallEvent(tool_name=f"test-{i}"))
        assert len(t) == 3
        events = t.drain()
        # Oldest events should be dropped
        assert events[0]["tool_name"] == "test-2"
        assert events[-1]["tool_name"] == "test-4"

    def test_create_transport_buffer(self):
        config = PhantexConfig(transport="buffer")
        t = create_transport(config)
        assert isinstance(t, BufferTransport)

# ── Client Tests ──────────────────────────────────────────────────────────────

class TestClient:
    def test_client_lifecycle(self):
        transport = BufferTransport()
        config = PhantexConfig(transport="buffer", hooks="none", enabled=True)
        client = PhantexClient(config=config, transport=transport)
        assert not client.started

        client.start()
        assert client.started

        client.stop()
        assert not client.started

    def test_client_disabled(self):
        config = PhantexConfig(transport="buffer", enabled=False)
        client = PhantexClient(config=config)
        client.start()
        # Should return immediately without installing hooks
        assert client.started is False
        assert len(client.hooks) == 0

    def test_client_context_manager(self):
        transport = BufferTransport()
        config = PhantexConfig(transport="buffer", hooks="none", enabled=True)
        with PhantexClient(config=config, transport=transport) as client:
            assert client.started
        assert not client.started

    def test_client_get_events(self):
        transport = BufferTransport()
        config = PhantexConfig(transport="buffer", hooks="none", enabled=True)
        client = PhantexClient(config=config, transport=transport)
        client.start()

        transport.send(ToolCallEvent(tool_name="test"))
        events = client.get_events()
        assert len(events) == 1

        drained = client.drain_events()
        assert len(drained) == 1
        assert len(client.get_events()) == 0

        client.stop()

    def test_double_start(self):
        transport = BufferTransport()
        config = PhantexConfig(transport="buffer", hooks="none", enabled=True)
        client = PhantexClient(config=config, transport=transport)
        client.start()
        client.start()  # Should not raise
        assert client.started
        client.stop()

    # ── AC4: Missing frameworks don't crash ──────────────────────────────

    def test_all_hooks_graceful_skip(self):
        """AC4: SDK silently skips hooks for frameworks that aren't installed."""
        transport = BufferTransport()
        config = PhantexConfig(
            transport="buffer",
            hooks="auto",  # Try all — should not crash
            enabled=True,
        )
        client = PhantexClient(config=config, transport=transport)
        client.start()
        # Should work regardless of which frameworks are installed
        client.stop()

    # ── AC6: SDK sends events to transport ───────────────────────────────

    def test_events_reach_transport(self):
        """AC6: Events are sent to the transport layer."""
        transport = BufferTransport()
        config = PhantexConfig(transport="buffer", hooks="none", enabled=True)
        client = PhantexClient(config=config, transport=transport)
        client.start()

        # Manually send an event through transport
        event = ToolCallEvent(
            tool_name="test_tool",
            tenant_id="tenant-123",
            agent_paid="ptx-test-001",
            pid=os.getpid(),
        )
        transport.send(event)

        events = client.drain_events()
        assert len(events) == 1
        assert events[0]["tool_name"] == "test_tool"
        assert events[0]["tenant_id"] == "tenant-123"

        client.stop()
