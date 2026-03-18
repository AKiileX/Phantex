# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK configuration.

All configuration comes from environment variables — no secrets embedded.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class PhantexConfig:
    """SDK configuration — read from env vars at init time."""

    # ── Identity ──────────────────────────────────────────────────────────
    # Auth token for the sensor / gateway
    auth_token: str = ""

    # Tenant ID (UUID). Sensor will validate this against the token.
    tenant_id: str = ""

    # Agent ID (set by SDK, read by sensor discovery via /proc/<pid>/environ)
    agent_id: str = ""

    # ── Transport ─────────────────────────────────────────────────────────
    # Transport mode: "socket" (Unix socket to sensor), "grpc" (direct to gateway),
    # "buffer" (in-memory for testing — default when no socket/gateway available)
    transport: str = "auto"

    # Unix socket path for sensor communication (D2)
    socket_path: str = "/var/run/phantex/sdk.sock"

    # gRPC gateway address for direct transport (fallback)
    gateway_addr: str = "localhost:50051"

    # ── Batching ──────────────────────────────────────────────────────────
    # Max events in a batch before flush
    batch_size: int = 50

    # Max seconds before flushing a partial batch
    batch_timeout: float = 1.0

    # Max events to buffer when transport is unavailable
    buffer_size: int = 5000

    # ── Features ──────────────────────────────────────────────────────────
    # Which framework hooks to enable. "auto" detects installed frameworks.
    hooks: str = "auto"

    # Record prompt content (Level 2/3). Default: hash only (Level 1).
    record_prompts: bool = False

    # Enable debug logging from the SDK itself
    debug: bool = False

    # SDK enabled/disabled (kill switch)
    enabled: bool = True

    @classmethod
    def from_env(cls) -> PhantexConfig:
        """
        Build config from environment variables.

        Env vars (all prefixed PHANTEX_):
            PHANTEX_TOKEN         → auth_token
            PHANTEX_TENANT_ID     → tenant_id
            PHANTEX_AGENT_ID      → agent_id
            PHANTEX_TRANSPORT     → transport (auto|socket|grpc|buffer)
            PHANTEX_SOCKET_PATH   → socket_path
            PHANTEX_GATEWAY_ADDR  → gateway_addr
            PHANTEX_BATCH_SIZE    → batch_size
            PHANTEX_BATCH_TIMEOUT → batch_timeout
            PHANTEX_BUFFER_SIZE   → buffer_size
            PHANTEX_HOOKS         → hooks (auto|langchain,autogen,crewai,http|none)
            PHANTEX_RECORD_PROMPTS → record_prompts (0|1)
            PHANTEX_DEBUG         → debug (0|1)
            PHANTEX_ENABLED       → enabled (0|1)
        """
        return cls(
            auth_token=os.environ.get("PHANTEX_TOKEN", ""),
            tenant_id=os.environ.get("PHANTEX_TENANT_ID", ""),
            agent_id=os.environ.get("PHANTEX_AGENT_ID", ""),
            transport=os.environ.get("PHANTEX_TRANSPORT", "auto"),
            socket_path=os.environ.get("PHANTEX_SOCKET_PATH", "/var/run/phantex/sdk.sock"),
            gateway_addr=(
                os.environ.get("PHANTEX_GATEWAY_ADDR")
                or os.environ.get("PHANTEX_GATEWAY")  # alias for Dockerfile convenience
                or "localhost:50051"
            ),
            batch_size=int(os.environ.get("PHANTEX_BATCH_SIZE", "50")),
            batch_timeout=float(os.environ.get("PHANTEX_BATCH_TIMEOUT", "1.0")),
            buffer_size=int(os.environ.get("PHANTEX_BUFFER_SIZE", "5000")),
            hooks=os.environ.get("PHANTEX_HOOKS", "auto"),
            record_prompts=os.environ.get("PHANTEX_RECORD_PROMPTS", "0") == "1",
            debug=os.environ.get("PHANTEX_DEBUG", "0") == "1",
            enabled=os.environ.get("PHANTEX_ENABLED", "1") == "1",
        )

# Singleton — set once at import, read everywhere
_config: PhantexConfig | None = None

def get_config() -> PhantexConfig:
    """Return the current SDK config (lazy-init from env on first call)."""
    global _config
    if _config is None:
        _config = PhantexConfig.from_env()
    return _config

def set_config(config: PhantexConfig) -> None:
    """Override config (for testing)."""
    global _config
    _config = config
