# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — Async-Native Transport.

Provides non-blocking event delivery for async frameworks (LangChain async,
async AutoGen, etc.). Uses asyncio natively instead of threading wrappers.

Supports:
- AsyncBufferTransport: in-memory async buffer (testing / fallback)
- AsyncHTTPTransport: httpx-based HTTPS delivery to gateway

Security:
- Auth token from env only (PHANTEX_TOKEN)
- TLS certificate validation by default
- No plaintext fallback
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import deque
from typing import Any, Protocol

logger = logging.getLogger("phantex.async_transport")

class AsyncTransport(Protocol):
    """Interface for async transports."""

    async def send(self, event: dict[str, Any]) -> None: ...
    async def flush(self) -> None: ...
    async def close(self) -> None: ...

class AsyncBufferTransport:
    """
    Async in-memory buffer transport for testing.

    Events stored in a deque, retrievable via drain().
    """

    def __init__(self, max_size: int = 5000) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._lock = asyncio.Lock()

    async def send(self, event: dict[str, Any]) -> None:
        async with self._lock:
            self._buffer.append(event)

    async def flush(self) -> None:
        pass  # No-op for buffer

    async def close(self) -> None:
        pass

    async def drain(self) -> list[dict[str, Any]]:
        """Return and clear buffered events."""
        async with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
            return events

    def peek_sync(self) -> list[dict[str, Any]]:
        """Synchronous peek for testing assertions."""
        return list(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    def __bool__(self) -> bool:
        return True

class AsyncHTTPTransport:
    """
    HTTPS transport using httpx for non-blocking event delivery.

    Batches events and sends them as JSON-L to the gateway's
    /api/v1/ingest endpoint.

    Security:
    - TLS required (no http:// unless explicitly overridden)
    - Auth token from PHANTEX_TOKEN env var
    - Content-Type: application/x-ndjson
    """

    def __init__(
        self,
        endpoint: str = "",
        auth_token: str = "",
        batch_size: int = 50,
        batch_timeout: float = 1.0,
        max_buffer: int = 5000,
        verify_tls: bool = True,
    ) -> None:
        self._endpoint = endpoint or os.environ.get(
            "PHANTEX_GATEWAY_HTTP", "https://localhost:8443/api/v1/ingest"
        )
        self._auth_token = auth_token or os.environ.get("PHANTEX_TOKEN", "")
        self._batch_size = batch_size
        self._batch_timeout = batch_timeout
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer)
        self._lock = asyncio.Lock()
        self._verify_tls = verify_tls
        self._client: Any = None  # Lazy httpx.AsyncClient
        self._flush_task: asyncio.Task | None = None

    async def _get_client(self) -> Any:
        """Lazy-init httpx async client."""
        if self._client is None:
            try:
                import httpx

                self._client = httpx.AsyncClient(
                    verify=self._verify_tls,
                    timeout=httpx.Timeout(10.0),
                    headers={
                        "Authorization": f"Bearer {self._auth_token}",
                        "Content-Type": "application/x-ndjson",
                        "User-Agent": "phantex-sdk/2.0.0",
                    },
                )
            except ImportError:
                logger.debug("httpx not installed — async HTTP transport unavailable")
                raise
        return self._client

    async def send(self, event: dict[str, Any]) -> None:
        async with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                await self._do_flush()

    async def flush(self) -> None:
        async with self._lock:
            await self._do_flush()

    async def _do_flush(self) -> None:
        """Flush buffer to HTTP endpoint. Must be called under lock."""
        if not self._buffer:
            return

        batch: list[dict[str, Any]] = []
        while self._buffer and len(batch) < self._batch_size:
            batch.append(self._buffer.popleft())

        try:
            client = await self._get_client()
            payload = "\n".join(json.dumps(e, default=str) for e in batch) + "\n"
            resp = await client.post(self._endpoint, content=payload.encode("utf-8"))

            if resp.status_code >= 400:
                logger.debug(
                    "HTTP transport: %d — re-buffering %d events", resp.status_code, len(batch)
                )
                for event in reversed(batch):
                    self._buffer.appendleft(event)
        except Exception as e:
            logger.debug(
                "HTTP transport error: %s — re-buffering %d events", type(e).__name__, len(batch)
            )
            for event in reversed(batch):
                self._buffer.appendleft(event)

    async def close(self) -> None:
        # Drain all remaining batches (flush sends at most _batch_size per call)
        for _ in range(100):  # safety cap
            async with self._lock:
                if not self._buffer:
                    break
                await self._do_flush()
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def __len__(self) -> int:
        return len(self._buffer)

    def __bool__(self) -> bool:
        return True

async def create_async_transport(
    endpoint: str = "",
    auth_token: str = "",
    mode: str = "auto",
) -> AsyncTransport:
    """
    Create the best available async transport.

    Modes:
    - "buffer": in-memory (testing)
    - "http": httpx HTTPS transport
    - "auto": try http, fall back to buffer
    """
    if mode == "buffer":
        return AsyncBufferTransport()

    if mode == "http" or mode == "auto":
        try:
            import httpx  # noqa: F401

            return AsyncHTTPTransport(endpoint=endpoint, auth_token=auth_token)
        except ImportError:
            if mode == "http":
                raise
            logger.debug("httpx not available — falling back to buffer transport")

    return AsyncBufferTransport()
