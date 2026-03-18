# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Syslog CEF Integration (N1-P0).

Syslog transport (UDP/TCP) with Common Event Format (CEF) or LEEF formatting.
Covers QRadar, ArcSight, and dozens of legacy SIEMs that accept syslog input.

Security:
  - No user-controlled data in CEF header fields (sanitized)
  - Extension values escaped to prevent injection
  - TCP with optional TLS (TLS strongly recommended for production)
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl as ssl_module
from typing import Any

import structlog

from app.integrations.base import BaseSIEMIntegration, IntegrationError
from app.integrations.formatter import to_cef_batch

logger = structlog.get_logger("phantex.integration.syslog")

class SyslogCEFIntegration(BaseSIEMIntegration):
    """Syslog CEF/LEEF integration (UDP/TCP transport)."""

    platform_name = "syslog_cef"
    max_batch_size = 1000

    def __init__(self, *, tenant_id: str, config: dict[str, Any], **kwargs) -> None:
        super().__init__(tenant_id=tenant_id, config=config, **kwargs)

        self._host = config.get("host", "")
        try:
            self._port = int(config.get("port", 514))
        except (ValueError, TypeError):
            raise IntegrationError(
                f"Syslog port must be numeric (got {str(config.get('port'))[:20]})",
                retryable=False,
            )
        self._protocol = config.get("protocol", "tcp").lower()
        self._tls_enabled = config.get("tls_enabled", False)
        self._tls_verify = config.get("tls_verify", True)

        if not self._host:
            raise IntegrationError(
                "Syslog requires host address",
                retryable=False,
            )

        if self._protocol not in ("tcp", "udp"):
            raise IntegrationError(
                f"Unsupported syslog protocol: {self._protocol} (use tcp or udp)",
                retryable=False,
            )

        self._tcp_writer: asyncio.StreamWriter | None = None
        self._tcp_reader: asyncio.StreamReader | None = None
        self._udp_socket: socket.socket | None = None

    async def send_batch(self, events: list[dict[str, Any]]) -> int:
        """Send events as CEF syslog messages."""
        if not events:
            return 0

        self._check_rate_limit(len(events))
        cef_messages = to_cef_batch(events)

        sent = 0
        for msg in cef_messages:
            try:
                await self._send_message(msg)
                sent += 1
            except Exception as e:
                logger.warning(
                    "syslog_send_error",
                    host=self._host,
                    port=self._port,
                    error=str(e),
                )
                raise IntegrationError(f"Syslog send error: {e}", retryable=True)

        return sent

    async def _send_message(self, message: str) -> None:
        """Send a single CEF message via configured transport."""
        # RFC 5424: add newline as message delimiter
        data = (message + "\n").encode("utf-8")

        if self._protocol == "tcp":
            await self._send_tcp(data)
        else:
            self._send_udp(data)

    async def _send_tcp(self, data: bytes) -> None:
        """Send via TCP (with optional TLS)."""
        if self._tcp_writer is None or self._tcp_writer.is_closing():
            ssl_ctx = None
            if self._tls_enabled:
                ssl_ctx = ssl_module.create_default_context()
                if not self._tls_verify:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl_module.CERT_NONE

            self._tcp_reader, self._tcp_writer = await asyncio.open_connection(self._host, self._port, ssl=ssl_ctx)

        self._tcp_writer.write(data)
        await self._tcp_writer.drain()

    def _send_udp(self, data: bytes) -> None:
        """Send via UDP (best-effort, no ack)."""
        if self._udp_socket is None:
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.settimeout(5.0)

        # UDP has a practical limit of ~65507 bytes; truncate if needed
        if len(data) > 65000:
            data = data[:65000]

        self._udp_socket.sendto(data, (self._host, self._port))

    async def test_connection(self) -> dict[str, Any]:
        """Test syslog connection by sending a test CEF message."""
        try:
            test_msg = (
                "CEF:0|Phantex|Phantex|1.0|connection_test|Connection Test|1|msg=Phantex syslog connectivity test"
            )
            await self._send_message(test_msg)
            return {
                "success": True,
                "message": f"Syslog {self._protocol.upper()} connection to {self._host}:{self._port} successful",
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    async def close(self) -> None:
        if self._tcp_writer and not self._tcp_writer.is_closing():
            self._tcp_writer.close()
            with contextlib.suppress(Exception):
                await self._tcp_writer.wait_closed()
            self._tcp_writer = None
            self._tcp_reader = None

        if self._udp_socket:
            self._udp_socket.close()
            self._udp_socket = None
