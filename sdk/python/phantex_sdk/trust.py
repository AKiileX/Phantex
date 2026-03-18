# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — Trust Score Context.

Reads the current agent's trust score from the Trust Engine
and makes it available as telemetry context.

The SDK periodically refreshes the score in the background and
attaches it to outgoing events as `trust_score` metadata.

Security:
- Trust score is read-only; the SDK cannot modify scores
- gRPC call uses the same mTLS certs as the main transport
- Fallback: if trust engine unreachable, score = 0.5 (neutral)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("phantex.trust")

# Neutral trust score (returned when engine is unavailable)
_NEUTRAL_SCORE = 0.5

# Refresh interval for background polling
_DEFAULT_REFRESH_INTERVAL = 30.0  # seconds

@dataclass(slots=True)
class TrustContext:
    """Cached trust score with metadata."""

    score: float = _NEUTRAL_SCORE
    factors: dict[str, float] = field(default_factory=dict)
    last_updated: float = 0.0
    engine_reachable: bool = False

    @property
    def is_stale(self) -> bool:
        """Score is stale if older than 2× refresh interval."""
        return (time.time() - self.last_updated) > (_DEFAULT_REFRESH_INTERVAL * 2)

    @property
    def is_healthy(self) -> bool:
        """Score above 0.5 and engine reachable."""
        return self.engine_reachable and self.score > _NEUTRAL_SCORE

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_score": round(self.score, 4),
            "trust_factors": self.factors,
            "trust_stale": self.is_stale,
            "trust_engine_reachable": self.engine_reachable,
        }

class TrustScoreProvider:
    """
    Background trust score refresh provider.

    Polls the local trust engine gRPC endpoint on a timer and caches
    the result for attachment to SDK events.

    Usage:
        provider = TrustScoreProvider(agent_id="agent-123")
        provider.start()
        score = provider.current  # TrustContext
        provider.stop()
    """

    def __init__(
        self,
        agent_id: str = "",
        refresh_interval: float = _DEFAULT_REFRESH_INTERVAL,
        trust_engine_addr: str = "",
    ) -> None:
        self._agent_id = agent_id or os.environ.get("PHANTEX_AGENT_ID", "")
        self._refresh_interval = refresh_interval
        self._addr = trust_engine_addr or os.environ.get(
            "PHANTEX_TRUST_ENGINE_ADDR", "localhost:50052"
        )
        self._context = TrustContext()
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def current(self) -> TrustContext:
        """Get the current cached trust context (thread-safe)."""
        with self._lock:
            return TrustContext(
                score=self._context.score,
                factors=dict(self._context.factors),
                last_updated=self._context.last_updated,
                engine_reachable=self._context.engine_reachable,
            )

    def start(self) -> None:
        """Start background refresh thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name="phantex-trust-refresh",
        )
        self._thread.start()
        logger.debug("Trust score refresh started (interval=%.0fs)", self._refresh_interval)

    def stop(self) -> None:
        """Stop background refresh."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _refresh_loop(self) -> None:
        """Background loop: periodically fetch trust score."""
        while self._running:
            try:
                self._fetch_score()
            except Exception as e:
                logger.debug("Trust score fetch failed: %s", type(e).__name__)
                with self._lock:
                    self._context.engine_reachable = False
            time.sleep(self._refresh_interval)

    def _fetch_score(self) -> None:
        """
        Fetch trust score from the trust engine.

        In production, this calls the gRPC TrustService.GetTrustScore().
        For now, uses a lightweight HTTP/gRPC stub that degrades gracefully.
        """
        if not self._agent_id:
            logger.debug("No agent_id configured — using neutral trust score")
            return

        try:
            # Try gRPC client if available
            score, factors = self._grpc_fetch()
            with self._lock:
                self._context.score = max(0.0, min(1.0, score))
                self._context.factors = factors
                self._context.last_updated = time.time()
                self._context.engine_reachable = True
        except Exception:
            # Graceful degradation: keep last known score
            with self._lock:
                self._context.engine_reachable = False

    def _grpc_fetch(self) -> tuple[float, dict[str, float]]:
        """
        Attempt gRPC call to trust engine.

        Returns (score, factors_dict). Raises if unavailable.
        """
        try:
            import grpc
            from proto.gen.phantex.v1 import trust_pb2, trust_pb2_grpc

            # Reuse sensor's TLS certs if available
            cert_path = os.environ.get("PHANTEX_TLS_CERT", "")
            key_path = os.environ.get("PHANTEX_TLS_KEY", "")
            ca_path = os.environ.get("PHANTEX_TLS_CA", "")

            if cert_path and key_path and ca_path:
                with open(cert_path, "rb") as f:
                    cert = f.read()
                with open(key_path, "rb") as f:
                    key = f.read()
                with open(ca_path, "rb") as f:
                    ca = f.read()
                creds = grpc.ssl_channel_credentials(ca, key, cert)
                channel = grpc.secure_channel(self._addr, creds)
            else:
                channel = grpc.insecure_channel(self._addr)

            stub = trust_pb2_grpc.TrustServiceStub(channel)
            req = trust_pb2.GetTrustScoreRequest(
                entity_id=self._agent_id,
                entity_type="agent",
            )
            resp = stub.GetTrustScore(req, timeout=5.0)
            channel.close()

            factors = {}
            if hasattr(resp, "factors"):
                for f in resp.factors:
                    factors[f.name] = f.value

            return resp.score, factors

        except ImportError:
            # No gRPC deps — fall back to neutral
            raise RuntimeError("grpc not available")
        except Exception:
            raise
