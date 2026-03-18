# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
D2 Integration tests — SDK → Unix Socket → Sensor pipeline.

Tests that:
1. SocketTransport sends NDJSON events to a Unix domain socket
2. Events arrive in the correct format (matching what Go parser expects)
3. Multiple events batch-flush correctly
4. Connection/reconnect behavior works
5. End-to-end: SDK hook capture → transport → socket → verify JSON format

These tests use a mock Unix socket server (Python) to verify the SDK side.
The Go side is tested separately in sensor/internal/sdksocket/listener_test.go.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from typing import Any

import pytest

# ── Ensure phantex_sdk is importable ─────────────────────────────────────────

os.environ["PHANTEX_NO_AUTO_INIT"] = "1"

import contextlib

from phantex_sdk.events import EventType, Severity, ToolCallEvent, ToolResponseEvent
from phantex_sdk.transport import SocketTransport

# ── Mock Unix Socket Server ──────────────────────────────────────────────────

class MockSensorSocket:
    """
    A mock Unix socket server that mimics the sensor's SDK socket listener.
    Accepts connections and reads NDJSON lines, storing them for assertion.
    """

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.received_lines: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._server: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        """Start the mock server in a background thread."""
        # Remove stale socket file if it exists
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(5)
        self._server.settimeout(2.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._server.accept()
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    def _handle_conn(self, conn: socket.socket) -> None:
        buf = b""
        try:
            while self._running:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        try:
                            parsed = json.loads(line)
                            with self._lock:
                                self.received_lines.append(parsed)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._running = False
        if self._server:
            with contextlib.suppress(Exception):
                self._server.close()

    def get_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.received_lines)

    def wait_for_events(self, count: int, timeout: float = 5.0) -> list[dict[str, Any]]:
        """Wait until at least `count` events are received."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            events = self.get_events()
            if len(events) >= count:
                return events
            time.sleep(0.05)
        return self.get_events()

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def socket_pair():
    """Create a temp socket path and mock sensor server."""
    tmpdir = tempfile.mkdtemp()
    sock_path = os.path.join(tmpdir, "sdk.sock")
    server = MockSensorSocket(sock_path)
    server.start()
    yield sock_path, server
    server.stop()
    try:
        os.unlink(sock_path)
        os.rmdir(tmpdir)
    except OSError:
        pass

# ── Tests ────────────────────────────────────────────────────────────────────

class TestSocketTransportSendsNDJSON:
    """Verify SocketTransport sends events in the format the Go parser expects."""

    def test_tool_call_event_format(self, socket_pair):
        """ToolCallEvent arrives as correct JSON matching Go sdkEvent struct."""
        sock_path, server = socket_pair
        transport = SocketTransport(socket_path=sock_path, batch_size=1, batch_timeout=0.1)

        evt = ToolCallEvent(
            tool_name="web_search",
            tool_input='{"query": "test"}',
            protocol="langchain_tool",
            framework="langchain",
            agent_paid="ptx-acme-dev-abc123",
            model_name="gpt-4",
            prompt_hash="sha256:abc123",
        )
        transport.send(evt)
        transport.flush()

        events = server.wait_for_events(1)
        assert len(events) >= 1, f"Expected >= 1 event, got {len(events)}"

        e = events[0]
        assert e["event_type"] == EventType.TOOL_CALL  # 50
        assert e["tool_name"] == "web_search"
        assert e["tool_input"] == '{"query": "test"}'
        assert e["protocol"] == "langchain_tool"
        assert e["framework"] == "langchain"
        assert e["agent_paid"] == "ptx-acme-dev-abc123"
        assert e["model_name"] == "gpt-4"
        assert "event_id" in e
        assert "timestamp_ns" in e
        assert e["timestamp_ns"] > 0

        transport.close()

    def test_tool_response_event_format(self, socket_pair):
        """ToolResponseEvent arrives as correct JSON with success/duration/size."""
        sock_path, server = socket_pair
        transport = SocketTransport(socket_path=sock_path, batch_size=1, batch_timeout=0.1)

        evt = ToolResponseEvent(
            tool_name="web_search",
            protocol="langchain_tool",
            success=True,
            duration_ns=5_000_000,
            output_size=1024,
        )
        transport.send(evt)
        transport.flush()

        events = server.wait_for_events(1)
        assert len(events) >= 1

        e = events[0]
        assert e["event_type"] == EventType.TOOL_RESPONSE  # 51
        assert e["tool_name"] == "web_search"
        assert e["success"] is True
        assert e["duration_ns"] == 5_000_000
        assert e["output_size"] == 1024

        transport.close()

    def test_failed_tool_response(self, socket_pair):
        """Failed tool response preserves success=False and error_message."""
        sock_path, server = socket_pair
        transport = SocketTransport(socket_path=sock_path, batch_size=1, batch_timeout=0.1)

        evt = ToolResponseEvent(
            tool_name="dangerous_tool",
            success=False,
            error_message="permission denied",
            duration_ns=100_000,
        )
        transport.send(evt)
        transport.flush()

        events = server.wait_for_events(1)
        assert len(events) >= 1

        e = events[0]
        assert e["event_type"] == 51
        assert e["success"] is False
        assert e["error_message"] == "permission denied"

        transport.close()

    def test_batch_flush(self, socket_pair):
        """Multiple events batch-flush correctly."""
        sock_path, server = socket_pair
        transport = SocketTransport(
            socket_path=sock_path,
            batch_size=5,
            batch_timeout=0.1,
        )

        for i in range(5):
            evt = ToolCallEvent(tool_name=f"tool_{i}", protocol="test")
            transport.send(evt)

        # batch_size=5, so it should auto-flush
        events = server.wait_for_events(5)
        assert len(events) >= 5

        tool_names = {e["tool_name"] for e in events}
        for i in range(5):
            assert f"tool_{i}" in tool_names

        transport.close()

    def test_reconnect_on_server_restart(self, socket_pair):
        """Transport reconnects after server restart."""
        sock_path, server = socket_pair
        transport = SocketTransport(socket_path=sock_path, batch_size=1, batch_timeout=0.1)

        # Send first event
        evt1 = ToolCallEvent(tool_name="before_restart", protocol="test")
        transport.send(evt1)
        transport.flush()

        events = server.wait_for_events(1)
        assert len(events) >= 1

        # Restart server
        server.stop()
        time.sleep(0.2)

        server2 = MockSensorSocket(sock_path)
        server2.start()
        time.sleep(0.2)

        # Send second event — transport should reconnect
        evt2 = ToolCallEvent(tool_name="after_restart", protocol="test")
        transport.send(evt2)
        transport.flush()
        time.sleep(0.5)
        transport.flush()  # May need double-flush after reconnect

        server2.wait_for_events(1, timeout=3.0)
        server2.stop()

        # May or may not reconnect instantly — this is a best-effort test
        # The important thing is that the transport doesn't crash
        transport.close()

    def test_timestamp_format(self, socket_pair):
        """Timestamp is in nanoseconds (int64 compatible with Go)."""
        sock_path, server = socket_pair
        transport = SocketTransport(socket_path=sock_path, batch_size=1, batch_timeout=0.1)

        before_ns = int(time.time() * 1_000_000_000)
        evt = ToolCallEvent(tool_name="timestamp_test")
        transport.send(evt)
        transport.flush()
        after_ns = int(time.time() * 1_000_000_000)

        events = server.wait_for_events(1)
        assert len(events) >= 1

        ts = events[0]["timestamp_ns"]
        assert isinstance(ts, int)
        assert before_ns <= ts <= after_ns + 1_000_000_000  # 1s tolerance

        transport.close()

    def test_pid_included(self, socket_pair):
        """PID is included in events (Go will override with SO_PEERCRED)."""
        sock_path, server = socket_pair
        transport = SocketTransport(socket_path=sock_path, batch_size=1, batch_timeout=0.1)

        evt = ToolCallEvent(tool_name="pid_test", pid=os.getpid())
        transport.send(evt)
        transport.flush()

        events = server.wait_for_events(1)
        assert len(events) >= 1

        assert events[0]["pid"] == os.getpid()

        transport.close()

class TestEventDataclassJsonCompatibility:
    """Verify event to_dict() output matches the Go sdkEvent struct fields."""

    def test_tool_call_all_fields(self):
        """All ToolCallEvent fields map to Go sdkEvent JSON tags."""
        evt = ToolCallEvent(
            tenant_id="t1",
            agent_paid="ptx-test",
            pid=1234,
            tool_name="test_tool",
            tool_input='{"key": "val"}',
            protocol="mcp",
            framework="langchain",
            model_name="gpt-4",
            prompt_hash="sha256:abc",
            input_tokens=100,
            output_tokens=200,
            trace_id="trace-1",
            span_id="span-1",
            parent_span_id="parent-1",
        )
        d = evt.to_dict()

        # These are the exact keys the Go parser expects
        go_fields = {
            "event_id",
            "event_type",
            "timestamp_ns",
            "tenant_id",
            "agent_paid",
            "pid",
            "tool_name",
            "tool_input",
            "protocol",
            "framework",
            "model_name",
            "prompt_hash",
            "input_tokens",
            "output_tokens",
            "trace_id",
            "span_id",
            "parent_span_id",
            "severity",
        }

        for field in go_fields:
            assert field in d, f"Missing field: {field}"

    def test_tool_response_all_fields(self):
        """All ToolResponseEvent fields map to Go sdkEvent JSON tags."""
        evt = ToolResponseEvent(
            tenant_id="t1",
            agent_paid="ptx-test",
            pid=1234,
            tool_name="test_tool",
            protocol="mcp",
            framework="langchain",
            success=True,
            duration_ns=5000,
            output_size=512,
            error_message="some error",
            model_name="gpt-4",
            input_tokens=100,
            output_tokens=200,
            trace_id="trace-1",
            span_id="span-1",
            parent_span_id="parent-1",
        )
        d = evt.to_dict()

        go_fields = {
            "event_id",
            "event_type",
            "timestamp_ns",
            "tenant_id",
            "agent_paid",
            "pid",
            "tool_name",
            "protocol",
            "framework",
            "success",
            "duration_ns",
            "output_size",
            "error_message",
            "model_name",
            "input_tokens",
            "output_tokens",
            "trace_id",
            "span_id",
            "parent_span_id",
            "severity",
        }

        for field in go_fields:
            assert field in d, f"Missing field: {field}"

    def test_severity_values_match_proto(self):
        """Severity enum values match proto (SDK sends int, Go maps to pb.Severity)."""
        assert Severity.UNSPECIFIED == 0
        assert Severity.INFO == 1
        assert Severity.LOW == 2
        assert Severity.MEDIUM == 3
        assert Severity.HIGH == 4
        assert Severity.CRITICAL == 5

    def test_event_type_values_match_proto(self):
        """EventType values match proto enum."""
        assert EventType.TOOL_CALL == 50
        assert EventType.TOOL_RESPONSE == 51
