# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Notification Channel Base Class (N2).

Abstract interface for notification channels (Slack, PagerDuty,
Webhook, Email). Each channel implements:
  - send(alert) — Send a notification for a single alert
  - test()      — Validate config + send test message
  - close()     — Release resources

Security:
  - Webhook URLs, API keys, tokens are NEVER logged
  - Rate limiting per channel (default 60/min, prevents API throttle)
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

class NotificationError(Exception):
    """Raised when a notification send fails."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable

class BaseNotificationChannel(ABC):
    """Abstract base for notification channels."""

    channel_type: str = "unknown"
    default_rate_limit: int = 60  # per minute

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

        self._window_start = time.monotonic()
        self._window_count = 0

    def _check_rate_limit(self) -> None:
        now = time.monotonic()
        if now - self._window_start >= 60:
            self._window_start = now
            self._window_count = 0
        if self._window_count >= self._rate_limit:
            raise NotificationError(
                f"Rate limit ({self._rate_limit}/min) for {self.channel_type}",
                retryable=False,
            )
        self._window_count += 1

    @abstractmethod
    async def send(self, alert: dict[str, Any]) -> bool:
        """Send a notification for the given alert. Returns True on success."""
        ...

    @abstractmethod
    async def test(self) -> dict[str, Any]:
        """Send a test notification. Returns {"success": bool, "message": str}."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Release HTTP clients, sockets, etc."""
        ...
