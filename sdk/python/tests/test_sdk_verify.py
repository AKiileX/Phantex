# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Verification tests for SDK audit fixes: PhantexSDK, HTTPTransport, env vars."""

from __future__ import annotations

import os

os.environ["PHANTEX_NO_AUTO_INIT"] = "1"
os.environ["PHANTEX_ENABLED"] = "1"

import pytest

from phantex_sdk import PhantexSDK
from phantex_sdk.config import PhantexConfig
from phantex_sdk.transport import BufferTransport, HTTPTransport, create_transport


class TestPhantexSDK:
    def test_lifecycle(self):
        sdk = PhantexSDK(
            gateway_addr="localhost:50051",
            agent_id="test-agent",
            hooks="none",
            _transport_instance=BufferTransport(),
        )
        sdk.auto_instrument()
        assert sdk.client.started
        sdk.stop()
        assert not sdk.client.started

    def test_context_manager(self):
        with PhantexSDK(hooks="none", _transport_instance=BufferTransport()) as s:
            assert s.client.started
        assert not s.client.started

    def test_kwargs_override_config(self):
        sdk = PhantexSDK(
            gateway_addr="custom:9090",
            agent_id="custom-agent",
            auth_token="custom-token",
            hooks="none",
            _transport_instance=BufferTransport(),
        )
        assert sdk.client.config.gateway_addr == "custom:9090"
        assert sdk.client.config.agent_id == "custom-agent"
        assert sdk.client.config.auth_token == "custom-token"

    def test_get_drain_events(self):
        buf = BufferTransport()
        sdk = PhantexSDK(hooks="none", _transport_instance=buf)
        sdk.auto_instrument()

        from phantex_sdk.events import ToolCallEvent
        buf.send(ToolCallEvent(tool_name="test-tool"))

        events = sdk.get_events()
        assert len(events) == 1
        assert events[0]["tool_name"] == "test-tool"

        drained = sdk.drain_events()
        assert len(drained) == 1
        assert len(sdk.get_events()) == 0
        sdk.stop()


class TestGatewayEnvAlias:
    def test_phantex_gateway_alias(self, monkeypatch):
        monkeypatch.delenv("PHANTEX_GATEWAY_ADDR", raising=False)
        monkeypatch.setenv("PHANTEX_GATEWAY", "alias-gateway:9090")
        config = PhantexConfig.from_env()
        assert config.gateway_addr == "alias-gateway:9090"

    def test_gateway_addr_takes_precedence(self, monkeypatch):
        monkeypatch.setenv("PHANTEX_GATEWAY_ADDR", "primary:8080")
        monkeypatch.setenv("PHANTEX_GATEWAY", "alias:9090")
        config = PhantexConfig.from_env()
        assert config.gateway_addr == "primary:8080"

    def test_default_when_neither_set(self, monkeypatch):
        monkeypatch.delenv("PHANTEX_GATEWAY_ADDR", raising=False)
        monkeypatch.delenv("PHANTEX_GATEWAY", raising=False)
        config = PhantexConfig.from_env()
        assert config.gateway_addr == "localhost:50051"


class TestHTTPTransport:
    def test_localhost_uses_http(self):
        t = HTTPTransport(gateway_addr="localhost:50051")
        assert t._endpoint == "http://localhost:50051/v1/events"

    def test_127_uses_http(self):
        t = HTTPTransport(gateway_addr="127.0.0.1:50051")
        assert t._endpoint == "http://127.0.0.1:50051/v1/events"

    def test_remote_uses_https(self):
        t = HTTPTransport(gateway_addr="production-gw:443")
        assert t._endpoint == "https://production-gw:443/v1/events"

    def test_explicit_https_scheme(self):
        t = HTTPTransport(gateway_addr="https://gw.example.com:443")
        assert t._endpoint == "https://gw.example.com:443/v1/events"

    def test_explicit_http_scheme(self):
        t = HTTPTransport(gateway_addr="http://internal:8080")
        assert t._endpoint == "http://internal:8080/v1/events"

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValueError, match="Unsupported scheme"):
            HTTPTransport(gateway_addr="ftp://evil:21")

    def test_rejects_file_scheme(self):
        with pytest.raises(ValueError, match="Unsupported scheme"):
            HTTPTransport(gateway_addr="file:///etc/passwd")

    def test_header_sanitization(self):
        t = HTTPTransport(gateway_addr="localhost:50051")
        assert t._safe_header("Bearer tok\r\nEvil: header") == "Bearer tokEvil: header"

    def test_empty_addr_defaults(self):
        t = HTTPTransport(gateway_addr="")
        assert t._endpoint == "https://localhost:50051/v1/events"

    def test_send_and_buffer(self):
        t = HTTPTransport(gateway_addr="localhost:50051", batch_size=100)
        from phantex_sdk.events import ToolCallEvent
        t.send(ToolCallEvent(tool_name="buffered"))
        assert len(t) == 1
        t.close()


class TestCreateTransportHTTP:
    def test_http_mode(self):
        config = PhantexConfig(transport="http", gateway_addr="gw:443", auth_token="tok")
        try:
            import httpx  # noqa: F401
            t = create_transport(config)
            assert isinstance(t, HTTPTransport)
        except ImportError:
            pytest.skip("httpx not installed")

    def test_grpc_mode_uses_http(self):
        """grpc mode should resolve to HTTPTransport (no proto stubs)."""
        config = PhantexConfig(transport="grpc", gateway_addr="gw:443")
        try:
            import httpx  # noqa: F401
            t = create_transport(config)
            assert isinstance(t, HTTPTransport)
        except ImportError:
            pytest.skip("httpx not installed")

    def test_buffer_mode(self):
        config = PhantexConfig(transport="buffer")
        t = create_transport(config)
        assert isinstance(t, BufferTransport)
