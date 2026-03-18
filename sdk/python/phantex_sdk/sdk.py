# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PhantexSDK — High-level convenience wrapper for PhantexClient.

Provides the clean API shown in documentation:

    from phantex_sdk import PhantexSDK

    sdk = PhantexSDK(gateway_addr="gateway:50051", agent_id="my-agent")
    sdk.auto_instrument()       # Enable all framework hooks
    # ... your agent code runs with auto-capture ...
    sdk.stop()
"""

from __future__ import annotations

import logging
from typing import Any

from .client import PhantexClient
from .config import PhantexConfig, get_config
from .transport import Transport, create_transport

logger = logging.getLogger("phantex")


class PhantexSDK:
    """
    High-level SDK entry point — wraps PhantexClient with a friendlier API.

    Accepts the most common settings as keyword arguments. For full control,
    use PhantexClient directly.
    """

    def __init__(
        self,
        *,
        gateway_addr: str | None = None,
        agent_id: str | None = None,
        auth_token: str | None = None,
        tenant_id: str | None = None,
        transport: str | None = None,
        hooks: str = "auto",
        debug: bool = False,
        _transport_instance: Transport | None = None,
    ) -> None:
        # Build config from env, then override with explicit args
        base = get_config()
        self._config = PhantexConfig(
            auth_token=auth_token if auth_token is not None else base.auth_token,
            tenant_id=tenant_id if tenant_id is not None else base.tenant_id,
            agent_id=agent_id if agent_id is not None else base.agent_id,
            transport=transport if transport is not None else base.transport,
            socket_path=base.socket_path,
            gateway_addr=gateway_addr if gateway_addr is not None else base.gateway_addr,
            batch_size=base.batch_size,
            batch_timeout=base.batch_timeout,
            buffer_size=base.buffer_size,
            hooks=hooks,
            record_prompts=base.record_prompts,
            debug=debug if debug else base.debug,
            enabled=base.enabled,
        )

        transport_obj = _transport_instance or create_transport(self._config)
        self._client = PhantexClient(config=self._config, transport=transport_obj)

    def auto_instrument(self) -> PhantexSDK:
        """
        Install all detected framework hooks (LangChain, AutoGen, CrewAI, HTTP, MCP).

        Returns self for chaining.
        """
        self._client.start()
        return self

    def stop(self) -> None:
        """Uninstall hooks and flush remaining events."""
        self._client.stop()

    @property
    def client(self) -> PhantexClient:
        """Access the underlying PhantexClient for advanced usage."""
        return self._client

    def get_events(self) -> list[dict[str, Any]]:
        """Return captured events (BufferTransport only, for testing)."""
        return self._client.get_events()

    def drain_events(self) -> list[dict[str, Any]]:
        """Return and clear captured events (BufferTransport only, for testing)."""
        return self._client.drain_events()

    def __enter__(self) -> PhantexSDK:
        self.auto_instrument()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()
