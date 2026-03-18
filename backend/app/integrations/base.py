# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SIEM / XDR Integration Base Class (N1).

Abstract adapter interface that all platform-specific integrations must
implement.  Each adapter provides:
  - send_batch(events) — Push a batch of formatted events/alerts
  - test_connection()  — Validate credentials + endpoint reachability
  - close()            — Release HTTP sessions / sockets

Security rules:
  - All HTTP-based integrations MUST use TLS (reject plain HTTP)
  - Credentials are NEVER logged or returned in API responses
  - Rate limiting: max events/min is configurable per integration
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

class IntegrationError(Exception):
    """Raised when an integration operation fails."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable

class BaseSIEMIntegration(ABC):
    """Abstract base for SIEM/XDR integrations."""

    # Override in subclass
    platform_name: str = "unknown"
    max_batch_size: int = 100
    default_rate_limit: int = 1000  # events per minute

    def __init__(
        self,
        *,
        tenant_id: str,
        config: dict[str, Any],
        rate_limit_per_min: int | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._config = config
        self._rate_limit = rate_limit_per_min or self.default_rate_limit

        # Rate limit tracking
        self._window_start = time.monotonic()
        self._window_count = 0

    def _check_rate_limit(self, count: int) -> None:
        """Enforce per-integration rate limit."""
        now = time.monotonic()
        if now - self._window_start >= 60:
            # Reset window
            self._window_start = now
            self._window_count = 0

        if self._window_count + count > self._rate_limit:
            raise IntegrationError(
                f"Rate limit exceeded ({self._rate_limit}/min) for {self.platform_name}",
                retryable=False,
            )
        self._window_count += count

    @abstractmethod
    async def send_batch(self, events: list[dict[str, Any]]) -> int:
        """Send a batch of events/alerts to the platform.

        Returns the number of events successfully sent.
        Raises IntegrationError on failure.
        """
        ...

    @abstractmethod
    async def test_connection(self) -> dict[str, Any]:
        """Validate credentials and endpoint reachability.

        Returns a dict with at least:
          {"success": bool, "message": str}
        """
        ...

    @abstractmethod
    async def close(self) -> None:
        """Release HTTP sessions, sockets, etc."""
        ...

    @staticmethod
    def _require_https(url: str) -> None:
        """Reject plain HTTP and empty endpoints for HTTP-based integrations."""
        if not url:
            raise IntegrationError(
                "TLS required: endpoint URL must not be empty",
                retryable=False,
            )
        if not url.startswith("https://"):
            raise IntegrationError(
                f"TLS required: endpoint must use https:// (got {url[:30]}...)",
                retryable=False,
            )

    @staticmethod
    def _mask_credential(value: str, visible: int = 4) -> str:
        """Mask credentials for safe display (never log full values)."""
        if not value or len(value) <= visible:
            return "***"
        return value[:visible] + "***"
