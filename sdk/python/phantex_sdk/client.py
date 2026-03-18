# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK client.

The main entry point for programmatic SDK control.
Most users just `import phantex_sdk` for auto-instrumentation,
but this class allows fine-grained control.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from .config import PhantexConfig, get_config, set_config
from .context import set_agent_paid
from .hooks import install_hooks, uninstall_hooks
from .hooks.base import BaseHook
from .transport import BufferTransport, Transport, create_transport

logger = logging.getLogger("phantex")

class PhantexClient:
    """
    Phantex SDK client — manages hooks, transport, and configuration.

    Usage (auto):
        import phantex_sdk  # Auto-instruments on import

    Usage (manual):
        from phantex_sdk.client import PhantexClient
        client = PhantexClient(config=PhantexConfig(...))
        client.start()
        # ... run your agent code ...
        client.stop()
    """

    def __init__(
        self,
        config: PhantexConfig | None = None,
        transport: Transport | None = None,
    ) -> None:
        self._config = config or get_config()
        self._transport = transport or create_transport(self._config)
        self._hooks: list[BaseHook] = []
        self._started = False

        # Apply config to global state
        set_config(self._config)

        # Set agent ID in environment for sensor discovery
        if self._config.agent_id:
            set_agent_paid(self._config.agent_id)

    @property
    def config(self) -> PhantexConfig:
        return self._config

    @property
    def transport(self) -> Transport:
        return self._transport

    @property
    def hooks(self) -> list[BaseHook]:
        return list(self._hooks)

    @property
    def started(self) -> bool:
        return self._started

    def start(self) -> PhantexClient:
        """
        Install all configured hooks and start the transport.
        Returns self for chaining.
        """
        if self._started:
            logger.debug("Phantex SDK already started")
            return self

        if not self._config.enabled:
            logger.debug("Phantex SDK disabled by config (PHANTEX_ENABLED=0)")
            return self

        # Install framework hooks
        self._hooks = install_hooks(self._transport, self._config)

        self._started = True

        if self._hooks:
            hook_names = [h.name for h in self._hooks]
            logger.info("Phantex SDK started — hooks: %s", ", ".join(hook_names))
        else:
            logger.info(
                "Phantex SDK started — no framework hooks installed (using buffer transport)"
            )

        return self

    def stop(self) -> None:
        """Uninstall all hooks and flush/close the transport."""
        if not self._started:
            return

        # Uninstall hooks (restore original methods)
        uninstall_hooks(self._hooks)
        self._hooks.clear()

        # Flush and close transport
        try:
            self._transport.flush()
            self._transport.close()
        except Exception as e:
            logger.debug("Error closing transport: %s", e)

        self._started = False
        logger.info("Phantex SDK stopped")

    def get_events(self) -> list[dict[str, Any]]:
        """
        Return captured events (only works with BufferTransport).
        Useful for testing.
        """
        if isinstance(self._transport, BufferTransport):
            return self._transport.peek()
        return []

    def drain_events(self) -> list[dict[str, Any]]:
        """
        Return and clear captured events (only works with BufferTransport).
        Useful for testing.
        """
        if isinstance(self._transport, BufferTransport):
            return self._transport.drain()
        return []

    def __enter__(self) -> PhantexClient:
        return self.start()

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def __del__(self) -> None:
        if self._started:
            with contextlib.suppress(Exception):
                self.stop()
