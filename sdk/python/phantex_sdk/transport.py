# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK event transport.

Supports multiple backends:
- BufferTransport: in-memory buffer (testing / fallback)
- SocketTransport: Unix domain socket → local sensor (D2)
- GrpcTransport: direct gRPC → gateway (standalone mode)

Auto-select logic:
  1. If Unix socket exists → SocketTransport
  2. If gRPC deps available + gateway reachable → GrpcTransport
  3. Else → BufferTransport (events buffered, retrievable via .drain())
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import threading
import time
from collections import deque
from typing import Any, Protocol

from .config import PhantexConfig, get_config
from .events import ToolCallEvent, ToolResponseEvent

logger = logging.getLogger("phantex.transport")

# Type alias for events the transport accepts
Event = ToolCallEvent | ToolResponseEvent

# ── Transport Protocol ────────────────────────────────────────────────────────

class Transport(Protocol):
    """Interface that all transports implement."""

    def send(self, event: Event) -> None:
        """Enqueue an event for delivery. Must not block for more than 1ms."""
        ...

    def flush(self) -> None:
        """Force-flush any buffered events."""
        ...

    def close(self) -> None:
        """Shut down the transport cleanly."""
        ...

# ── Buffer Transport (in-memory, for testing) ────────────────────────────────

class BufferTransport:
    """
    Stores events in an in-memory deque. Used for:
    - Testing (inspect captured events)
    - Fallback when no sensor or gateway is available
    """

    def __init__(self, max_size: int = 5000) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def send(self, event: Event) -> None:
        with self._lock:
            self._buffer.append(event.to_dict())

    def flush(self) -> None:
        pass  # No-op for in-memory buffer

    def close(self) -> None:
        pass

    def drain(self) -> list[dict[str, Any]]:
        """Return and clear all buffered events. For testing."""
        with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
            return events

    def peek(self) -> list[dict[str, Any]]:
        """Return all buffered events without clearing. For testing."""
        with self._lock:
            return list(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    def __bool__(self) -> bool:
        """Always truthy — prevents 'transport or fallback' from skipping us."""
        return True

# ── Socket Transport (Unix domain socket → sensor) ───────────────────────────

class SocketTransport:
    """
    Sends events as newline-delimited JSON over a Unix domain socket.
    The local Phantex sensor listens on the socket and merges SDK events
    with kernel events into the same gRPC stream → Kafka pipeline.

    - Non-blocking sends with internal batch buffer
    - Auto-reconnect on socket errors
    - Drops oldest events when buffer overflows
    """

    def __init__(
        self,
        socket_path: str = "/var/run/phantex/sdk.sock",
        batch_size: int = 50,
        batch_timeout: float = 1.0,
        buffer_size: int = 5000,
    ) -> None:
        self._socket_path = socket_path
        self._batch_size = batch_size
        self._batch_timeout = batch_timeout
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._running = True
        self._reconnect_delay = 1.0  # Starting backoff delay in seconds
        self._max_reconnect_delay = 30.0  # Max backoff cap
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="phantex-socket-flush"
        )
        self._flush_thread.start()

    def _connect(self) -> bool:
        """Attempt to connect to the Unix socket with exponential backoff."""
        try:
            if self._sock is not None:
                with contextlib.suppress(Exception):
                    self._sock.close()
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(2.0)
            self._sock.connect(self._socket_path)
            logger.debug("Connected to sensor at %s", self._socket_path)
            self._reconnect_delay = 1.0  # Reset backoff on success
            return True
        except (OSError, ConnectionError) as e:
            logger.debug(
                "Cannot connect to sensor socket: %s (retry in %.1fs)",
                e,
                self._reconnect_delay,
            )
            self._sock = None
            # Exponential backoff: sleep before allowing next attempt
            time.sleep(self._reconnect_delay)
            self._reconnect_delay = min(self._reconnect_delay * 2, self._max_reconnect_delay)
            return False

    def send(self, event: Event) -> None:
        with self._lock:
            self._buffer.append(event.to_dict())
            if len(self._buffer) >= self._batch_size:
                self._do_flush()

    def flush(self) -> None:
        with self._lock:
            self._do_flush()

    def _do_flush(self) -> None:
        """Flush buffer to socket. Must be called under lock."""
        if not self._buffer:
            return

        if self._sock is None and not self._connect():
            return  # Buffer until socket is available

        batch = []
        while self._buffer and len(batch) < self._batch_size:
            batch.append(self._buffer.popleft())

        try:
            payload = "\n".join(json.dumps(e, default=str) for e in batch) + "\n"
            self._sock.sendall(payload.encode("utf-8"))
        except (OSError, BrokenPipeError) as e:
            logger.debug("Socket send failed: %s — re-buffering %d events", e, len(batch))
            self._sock = None
            # Re-buffer events (at the front)
            for event in reversed(batch):
                self._buffer.appendleft(event)

    def _flush_loop(self) -> None:
        """Background thread: periodic flush of partial batches."""
        while self._running:
            time.sleep(self._batch_timeout)
            try:
                self.flush()
            except Exception:
                pass  # Never crash the flush thread

    def close(self) -> None:
        self._running = False
        self.flush()
        if self._sock is not None:
            with contextlib.suppress(Exception):
                self._sock.close()

    def __len__(self) -> int:
        return len(self._buffer)

    def __bool__(self) -> bool:
        """Always truthy — prevents 'transport or fallback' from skipping us."""
        return True

# ── HTTP Transport (NDJSON POST → gateway) ───────────────────────────────────

class HTTPTransport:
    """
    Sends events as newline-delimited JSON over HTTPS to the gateway.

    Used when:
    - No local sensor socket is available
    - User explicitly sets PHANTEX_TRANSPORT=http or PHANTEX_TRANSPORT=grpc

    Security:
    - TLS 1.2+ enforced (configurable via httpx)
    - Bearer token auth via PHANTEX_TOKEN
    - Header values are sanitized (no CRLF injection)
    - Connect/read timeouts to prevent hanging
    """

    _ALLOWED_SCHEMES = frozenset(("https", "http"))

    def __init__(
        self,
        gateway_addr: str = "localhost:50051",
        auth_token: str = "",
        batch_size: int = 50,
        batch_timeout: float = 1.0,
        buffer_size: int = 5000,
    ) -> None:
        self._gateway_addr = gateway_addr
        self._auth_token = auth_token
        self._batch_size = batch_size
        self._batch_timeout = batch_timeout
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._running = True
        self._client: Any = None  # httpx.Client, lazy-init
        self._endpoint = self._build_endpoint(gateway_addr)

        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="phantex-http-flush"
        )
        self._flush_thread.start()

    @staticmethod
    def _build_endpoint(addr: str) -> str:
        """
        Build the POST endpoint URL from a gateway address.

        Accepts:  "host:port", "http://host:port", "https://host:port"
        Returns:  "https://host:port/v1/events" (or http for localhost only)
        """
        import urllib.parse

        addr = addr.strip()
        if not addr:
            return "https://localhost:50051/v1/events"

        # If no scheme, decide based on host
        if "://" not in addr:
            host = addr.split(":")[0].lower()
            scheme = "http" if host in ("localhost", "127.0.0.1", "::1") else "https"
            addr = f"{scheme}://{addr}"

        parsed = urllib.parse.urlparse(addr)
        if parsed.scheme not in HTTPTransport._ALLOWED_SCHEMES:
            raise ValueError(f"Unsupported scheme: {parsed.scheme}")

        # Build clean endpoint — strip any existing path, always use /v1/events
        base = f"{parsed.scheme}://{parsed.netloc}"
        return f"{base}/v1/events"

    def _get_client(self) -> Any:
        """Lazy-init httpx client with security defaults."""
        if self._client is not None:
            return self._client

        try:
            import httpx
            import ssl

            ssl_ctx = ssl.create_default_context()
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            self._client = httpx.Client(
                timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0),
                verify=ssl_ctx if self._endpoint.startswith("https") else False,
                limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            )
            return self._client
        except ImportError:
            logger.warning(
                "httpx not installed — install phantex-sdk[http] for HTTP transport"
            )
            return None

    def _safe_header(self, value: str) -> str:
        """Sanitize header values to prevent CRLF injection."""
        return value.replace("\r", "").replace("\n", "")

    def send(self, event: Event) -> None:
        with self._lock:
            self._buffer.append(event.to_dict())
            if len(self._buffer) >= self._batch_size:
                self._do_flush()

    def flush(self) -> None:
        with self._lock:
            self._do_flush()

    def _do_flush(self) -> None:
        """Flush buffer via HTTP POST. Must be called under lock."""
        if not self._buffer:
            return

        client = self._get_client()
        if client is None:
            return  # httpx not available — keep buffering

        batch: list[dict[str, Any]] = []
        while self._buffer and len(batch) < self._batch_size:
            batch.append(self._buffer.popleft())

        payload = "\n".join(json.dumps(e, default=str) for e in batch) + "\n"

        headers: dict[str, str] = {
            "Content-Type": "application/x-ndjson",
        }
        if self._auth_token:
            headers["Authorization"] = self._safe_header(f"Bearer {self._auth_token}")

        try:
            resp = client.post(self._endpoint, content=payload.encode("utf-8"), headers=headers)
            if resp.status_code >= 400:
                logger.debug(
                    "HTTP transport POST failed: %d — re-buffering %d events",
                    resp.status_code,
                    len(batch),
                )
                for event in reversed(batch):
                    self._buffer.appendleft(event)
        except Exception as e:
            logger.debug("HTTP transport error: %s — re-buffering %d events", e, len(batch))
            for event in reversed(batch):
                self._buffer.appendleft(event)

    def _flush_loop(self) -> None:
        """Background thread: periodic flush of partial batches."""
        while self._running:
            time.sleep(self._batch_timeout)
            try:
                self.flush()
            except Exception:
                pass  # Never crash the flush thread

    def close(self) -> None:
        self._running = False
        self.flush()
        if self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()

    def __len__(self) -> int:
        return len(self._buffer)

    def __bool__(self) -> bool:
        return True


# ── Auto-Select Transport ────────────────────────────────────────────────────

def create_transport(config: PhantexConfig | None = None) -> Transport:
    """
    Create the best available transport based on config and environment.

    Priority:
    1. Explicit config.transport setting
    2. Unix socket exists → SocketTransport
    3. Gateway address available → HTTPTransport
    4. Fallback → BufferTransport
    """
    if config is None:
        config = get_config()

    mode = config.transport.lower()

    if mode == "buffer":
        logger.debug("Using BufferTransport (explicit config)")
        return BufferTransport(max_size=config.buffer_size)

    if mode == "socket" or (mode == "auto" and os.path.exists(config.socket_path)):
        logger.debug("Using SocketTransport at %s", config.socket_path)
        return SocketTransport(
            socket_path=config.socket_path,
            batch_size=config.batch_size,
            batch_timeout=config.batch_timeout,
            buffer_size=config.buffer_size,
        )

    # HTTP transport — explicit "http" or "grpc" mode, or auto with gateway address
    if mode in ("http", "grpc") or (mode == "auto" and config.gateway_addr):
        try:
            import httpx  # noqa: F401

            logger.debug("Using HTTPTransport → %s", config.gateway_addr)
            return HTTPTransport(
                gateway_addr=config.gateway_addr,
                auth_token=config.auth_token,
                batch_size=config.batch_size,
                batch_timeout=config.batch_timeout,
                buffer_size=config.buffer_size,
            )
        except ImportError:
            logger.debug("httpx not available — falling back to BufferTransport")

    # Default fallback: buffer
    logger.debug("Using BufferTransport (no sensor socket available)")
    return BufferTransport(max_size=config.buffer_size)
