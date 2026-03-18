# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Trust Graph Engine gRPC Client.

Provides ``TrustClient``, a thin async wrapper around the Rust trust-engine's
gRPC ``TrustService``.  Used by:
  - PRL rule engine  (``trust_score()`` built-in function)
  - ML feature pipeline (trust score as a feature dimension)
  - Analytics / dashboard (neighbourhood graph visualisation)

Graceful degradation: when the engine is unreachable the client returns a
**neutral score of 0.5** so that detection rules keep running.

Connection management uses exponential back-off retries (max 3 attempts).
Retries are limited to transient gRPC status codes only.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

# ---------------------------------------------------------------------------
# Path setup: ensure project root + proto/gen are on sys.path so that
#   - ``from proto.gen.phantex.v1 import ...`` resolves (project root)
#   - generated stubs ``from phantex.v1 import trust_pb2`` resolve (proto/gen)
#
# In Docker: __file__ = /app/app/services/trust_client.py → parents[3] = /
#            but proto/ is mounted at /app/proto/ → use parents[2] = /app
# Locally:   __file__ = .../backend/app/services/trust_client.py → parents[3] = project root
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve()
_BACKEND_ROOT = str(_THIS_DIR.parents[2])  # /app or .../backend
_PROJECT_ROOT = str(_THIS_DIR.parents[3])  # / or .../PHANTEX

# Try both possible proto locations
_PROTO_CANDIDATES = [
    Path(_BACKEND_ROOT, "proto", "gen"),  # Docker: /app/proto/gen
    Path(_PROJECT_ROOT, "proto", "gen"),  # Local:  .../PHANTEX/proto/gen
]
for _candidate in [str(_BACKEND_ROOT), str(_PROJECT_ROOT)]:
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)
for _pg in _PROTO_CANDIDATES:
    _pg_str = str(_pg)
    if _pg.exists() and _pg_str not in sys.path:
        sys.path.insert(0, _pg_str)

logger = structlog.get_logger("phantex.services.trust_client")

# ---------------------------------------------------------------------------
# Lazy import: grpcio / grpcio-tools might not be installed in every env.
# ---------------------------------------------------------------------------
_grpc_available = False
try:
    import grpc  # type: ignore[import-untyped]
    import grpc.aio  # type: ignore[import-untyped]

    _grpc_available = True
except ImportError:
    logger.warning("grpc package not installed — trust_client will use fallback mode")

# ---------------------------------------------------------------------------
# Retriable gRPC status codes (transient errors only)
# ---------------------------------------------------------------------------
_RETRIABLE_CODES: frozenset[int] = frozenset()
if _grpc_available:
    _RETRIABLE_CODES = frozenset(
        {
            grpc.StatusCode.UNAVAILABLE,
            grpc.StatusCode.DEADLINE_EXCEEDED,
            grpc.StatusCode.RESOURCE_EXHAUSTED,
            grpc.StatusCode.ABORTED,
            grpc.StatusCode.INTERNAL,
        }
    )

# ---------------------------------------------------------------------------
# Data classes for typed responses
# ---------------------------------------------------------------------------

NEUTRAL_SCORE = 0.5

@dataclass
class TrustFactor:
    """Breakdown of a single trust factor."""

    name: str
    weight: float
    value: float

@dataclass
class TrustScoreResult:
    """Result from ``GetTrustScore``."""

    trust_score: float
    factors: list[TrustFactor] = field(default_factory=list)
    entity_id: str = ""
    entity_type: str = ""
    last_updated: float | None = None  # unix epoch

@dataclass
class TrustGraphNode:
    """A node in the trust sub-graph."""

    id: str
    entity_type: str
    trust_score: float
    metadata: dict[str, str] = field(default_factory=dict)

@dataclass
class TrustGraphEdge:
    """An edge in the trust sub-graph."""

    source_id: str
    target_id: str
    edge_type: str
    count: int = 0
    weight: float = 0.0

@dataclass
class TrustNeighbourhood:
    """Result from ``GetTrustGraph``."""

    nodes: list[TrustGraphNode] = field(default_factory=list)
    edges: list[TrustGraphEdge] = field(default_factory=list)

@dataclass
class PropagationResult:
    """Result from ``PropagateScores``."""

    iterations: int = 0
    max_delta: float = 0.0
    converged: bool = False
    nodes_updated: int = 0
    elapsed_ms: float = 0.0

@dataclass
class HealthStatus:
    """Result from ``HealthCheck``."""

    status: str = "NOT_SERVING"
    total_nodes: int = 0
    total_edges: int = 0
    tenants: int = 0
    uptime_secs: float = 0.0

# ---------------------------------------------------------------------------
# gRPC client
# ---------------------------------------------------------------------------

class TrustClient:
    """
    Async gRPC client for the Phantex Rust trust engine.

    Parameters
    ----------
    addr : str
        Trust engine gRPC address (default ``localhost:50052``).
    timeout : float
        Per-call deadline in seconds (default 2.0 s).
    max_retries : int
        Maximum retries with exponential back-off (default 3).
    use_tls : bool
        When ``True``, use ``grpc.aio.secure_channel`` (default: reads
        ``TRUST_ENGINE_TLS`` env var, falling back to ``False``).
    api_key : str | None
        Optional API key sent as ``x-api-key`` metadata.
    cache_ttl : float
        TTL in seconds for the trust-score cache (default 5.0).
    cache_max : int
        Maximum entries in the trust-score cache (default 4096).
    """

    def __init__(
        self,
        addr: str | None = None,
        *,
        timeout: float = 2.0,
        max_retries: int = 3,
        use_tls: bool | None = None,
        api_key: str | None = None,
        cache_ttl: float = 5.0,
        cache_max: int = 4096,
    ) -> None:
        self._addr = addr or os.getenv("TRUST_ENGINE_ADDR", "localhost:50052")
        self._timeout = timeout
        self._max_retries = max_retries
        self._use_tls = (
            use_tls if use_tls is not None else os.getenv("TRUST_ENGINE_TLS", "").lower() in ("1", "true", "yes")
        )
        self._api_key = api_key or os.getenv("TRUST_ENGINE_API_KEY")
        self._channel: Any = None
        self._stub: Any = None
        self._healthy = False

        # Simple TTL cache: OrderedDict[key → (value, expiry)]
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._cache_ttl = cache_ttl
        self._cache_max = cache_max

    # -- cache ---------------------------------------------------------------

    def _cache_get(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        value, expiry = entry
        if time.monotonic() > expiry:
            self._cache.pop(key, None)
            return None
        # Move to end (LRU)
        self._cache.move_to_end(key)
        return value

    def _cache_put(self, key: str, value: Any) -> None:
        self._cache[key] = (value, time.monotonic() + self._cache_ttl)
        self._cache.move_to_end(key)
        # Evict oldest if over max
        while len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Establish a gRPC channel (lazy — called on first request)."""
        if not _grpc_available:
            logger.info("grpc not available — running in fallback mode")
            return

        if self._use_tls:
            credentials = grpc.ssl_channel_credentials()
            self._channel = grpc.aio.secure_channel(self._addr, credentials)
            logger.info("trust_client.secure_channel", addr=self._addr)
        else:
            self._channel = grpc.aio.insecure_channel(self._addr)
            logger.info("trust_client.insecure_channel", addr=self._addr)

        # Wait for the channel to be ready (prevents "Channel is closed"
        # errors when the stub is used immediately after creation).
        try:
            await asyncio.wait_for(self._channel.channel_ready(), timeout=self._timeout)
        except TimeoutError:
            logger.warning(
                "trust_client.channel_ready_timeout",
                addr=self._addr,
                timeout=self._timeout,
            )
            # Channel may still transition to READY later; continue.

        # Dynamically import the generated stubs.
        try:
            from proto.gen.phantex.v1 import trust_pb2_grpc  # type: ignore[import-untyped]

            self._stub = trust_pb2_grpc.TrustServiceStub(self._channel)
        except ImportError:
            # If generated stubs aren't available, use generic unary call.
            logger.warning("trust_pb2_grpc not found — falling back to neutral scores")
            self._stub = None

        self._healthy = True
        logger.info("trust_client.connected", addr=self._addr, tls=self._use_tls)

    async def close(self) -> None:
        """Shut down the gRPC channel."""
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
            self._stub = None
            self._healthy = False

    async def _ensure_connected(self) -> None:
        """Reconnect if the channel was closed or marked unhealthy."""
        if self._channel is None or not self._healthy:
            # Reset completely so connect() creates a fresh channel.
            if self._channel is not None:
                with contextlib.suppress(Exception):
                    await self._channel.close()
                self._channel = None
                self._stub = None
            await self.connect()

    # -- metadata ------------------------------------------------------------

    def _call_metadata(self) -> list[tuple[str, str]] | None:
        """Return gRPC metadata (API key header) if configured."""
        if self._api_key:
            return [("x-api-key", self._api_key)]
        return None

    # -- retry helper --------------------------------------------------------

    async def _call_with_retry(self, fn, *args, **kwargs):
        """Call *fn* with exponential back-off retries (retriable errors only)."""
        await self._ensure_connected()

        if self._stub is None:
            return None  # fallback mode

        # Inject metadata if configured.
        meta = self._call_metadata()
        if meta:
            kwargs.setdefault("metadata", meta)

        last_exc = None
        for attempt in range(1, self._max_retries + 1):
            try:
                return await asyncio.wait_for(
                    fn(*args, **kwargs),
                    timeout=self._timeout,
                )
            except TimeoutError as exc:
                last_exc = exc
                # Timeout is retriable
            except Exception as exc:
                last_exc = exc
                # Only retry on transient gRPC errors.
                if _grpc_available and isinstance(exc, grpc.aio.AioRpcError):
                    if exc.code() not in _RETRIABLE_CODES:
                        logger.warning(
                            "trust_client.non_retriable",
                            code=str(exc.code()),
                            error=str(exc),
                        )
                        break  # Don't retry INVALID_ARGUMENT, NOT_FOUND, etc.

            if attempt < self._max_retries:
                delay = min(0.1 * (2 ** (attempt - 1)), 2.0)
                logger.warning(
                    "trust_client.retry",
                    attempt=attempt,
                    delay=delay,
                    error=str(last_exc),
                )
                await asyncio.sleep(delay)

        logger.error(
            "trust_client.call_failed",
            error=str(last_exc),
            retries=self._max_retries,
        )
        self._healthy = False
        return None

    # -- public API ----------------------------------------------------------

    async def get_trust_score(
        self,
        tenant_id: str,
        entity_id: str,
        entity_type: str = "agent",
    ) -> TrustScoreResult:
        """
        Query the trust score for an entity.

        Returns a neutral score (0.5) if the engine is unavailable.
        Results are cached with a short TTL to reduce gRPC call volume.
        """
        # Check cache first.
        cache_key = f"score:{tenant_id}:{entity_id}:{entity_type}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not _grpc_available:
            return TrustScoreResult(
                trust_score=NEUTRAL_SCORE,
                entity_id=entity_id,
                entity_type=entity_type,
            )
        if self._stub is None:
            await self._ensure_connected()
            if self._stub is None:
                return TrustScoreResult(
                    trust_score=NEUTRAL_SCORE,
                    entity_id=entity_id,
                    entity_type=entity_type,
                )

        try:
            from proto.gen.phantex.v1 import trust_pb2  # type: ignore[import-untyped]
        except ImportError:
            return TrustScoreResult(
                trust_score=NEUTRAL_SCORE,
                entity_id=entity_id,
                entity_type=entity_type,
            )

        req = trust_pb2.GetTrustScoreRequest(
            tenant_id=tenant_id,
            entity_id=entity_id,
            entity_type=entity_type,
        )

        resp = await self._call_with_retry(self._stub.GetTrustScore, req)
        if resp is None:
            return TrustScoreResult(
                trust_score=NEUTRAL_SCORE,
                entity_id=entity_id,
                entity_type=entity_type,
            )

        factors = [TrustFactor(name=f.name, weight=f.weight, value=f.value) for f in resp.factors]
        ts = None
        if resp.HasField("last_updated"):
            ts = resp.last_updated.seconds + resp.last_updated.nanos / 1e9

        # Clamp score to [0, 1] — defend against buggy engine responses.
        score = max(0.0, min(1.0, resp.trust_score))

        result = TrustScoreResult(
            trust_score=score,
            factors=factors,
            entity_id=resp.entity_id,
            entity_type=resp.entity_type,
            last_updated=ts,
        )

        # Cache the result.
        self._cache_put(cache_key, result)
        return result

    async def get_trust_graph(
        self,
        tenant_id: str,
        entity_id: str,
        entity_type: str = "agent",
        depth: int = 1,
    ) -> TrustNeighbourhood:
        """Return the local neighbourhood of an entity."""
        # Clamp depth to prevent server-side DoS.
        depth = max(1, min(depth, 5))
        if not _grpc_available:
            return TrustNeighbourhood()
        if self._stub is None:
            await self._ensure_connected()
            if self._stub is None:
                return TrustNeighbourhood()

        try:
            from proto.gen.phantex.v1 import trust_pb2  # type: ignore[import-untyped]
        except ImportError:
            return TrustNeighbourhood()

        req = trust_pb2.GetTrustGraphRequest(
            tenant_id=tenant_id,
            entity_id=entity_id,
            entity_type=entity_type,
            depth=depth,
        )

        resp = await self._call_with_retry(self._stub.GetTrustGraph, req)
        if resp is None:
            return TrustNeighbourhood()

        nodes = [
            TrustGraphNode(
                id=n.id,
                entity_type=n.entity_type,
                trust_score=n.trust_score,
                metadata=dict(n.metadata),
            )
            for n in resp.nodes
        ]
        edges = [
            TrustGraphEdge(
                source_id=e.source_id,
                target_id=e.target_id,
                edge_type=e.edge_type,
                count=e.count,
                weight=e.weight,
            )
            for e in resp.edges
        ]

        return TrustNeighbourhood(nodes=nodes, edges=edges)

    async def update_event(
        self,
        tenant_id: str,
        source_id: str,
        source_type: str,
        target_id: str,
        target_type: str,
        event_type: str,
        severity: str = "low",
        bytes_count: int = 0,
    ) -> tuple[float, float]:
        """
        Push a single event into the trust graph.

        Returns ``(source_score, target_score)`` or ``(0.5, 0.5)`` on failure.
        """
        if not _grpc_available:
            return (NEUTRAL_SCORE, NEUTRAL_SCORE)

        # Lazy-connect: _stub is None until first call triggers connect()
        if self._stub is None:
            await self._ensure_connected()
            if self._stub is None:
                return (NEUTRAL_SCORE, NEUTRAL_SCORE)

        try:
            from proto.gen.phantex.v1 import trust_pb2  # type: ignore[import-untyped]
        except ImportError:
            return (NEUTRAL_SCORE, NEUTRAL_SCORE)

        req = trust_pb2.UpdateEventRequest(
            tenant_id=tenant_id,
            source_id=source_id,
            source_type=source_type,
            target_id=target_id,
            target_type=target_type,
            event_type=event_type,
            severity=severity,
            bytes=bytes_count,
        )

        resp = await self._call_with_retry(self._stub.UpdateEvent, req)
        if resp is None:
            return (NEUTRAL_SCORE, NEUTRAL_SCORE)

        return (resp.source_score, resp.target_score)

    async def propagate_scores(
        self,
        tenant_id: str = "",
        max_iterations: int = 0,
        convergence_threshold: float = 0.0,
    ) -> PropagationResult:
        """Trigger trust propagation (PageRank pass)."""
        if not _grpc_available:
            return PropagationResult()
        if self._stub is None:
            await self._ensure_connected()
            if self._stub is None:
                return PropagationResult()

        try:
            from proto.gen.phantex.v1 import trust_pb2  # type: ignore[import-untyped]
        except ImportError:
            return PropagationResult()

        req = trust_pb2.PropagateRequest(
            tenant_id=tenant_id,
            max_iterations=max_iterations,
            convergence_threshold=convergence_threshold,
        )

        resp = await self._call_with_retry(self._stub.PropagateScores, req)
        if resp is None:
            return PropagationResult()

        return PropagationResult(
            iterations=resp.iterations,
            max_delta=resp.max_delta,
            converged=resp.converged,
            nodes_updated=resp.nodes_updated,
            elapsed_ms=resp.elapsed_ms,
        )

    async def health_check(self) -> HealthStatus:
        """Query engine health."""
        if not _grpc_available:
            return HealthStatus()

        await self._ensure_connected()

        if self._stub is None:
            return HealthStatus()

        try:
            from proto.gen.phantex.v1 import trust_pb2  # type: ignore[import-untyped]
        except ImportError:
            return HealthStatus()

        req = trust_pb2.HealthCheckRequest()

        resp = await self._call_with_retry(self._stub.HealthCheck, req)
        if resp is None:
            return HealthStatus()

        return HealthStatus(
            status=resp.status,
            total_nodes=resp.total_nodes,
            total_edges=resp.total_edges,
            tenants=resp.tenants,
            uptime_secs=resp.uptime_secs,
        )

    @property
    def is_healthy(self) -> bool:
        """Whether the last call to the engine succeeded."""
        return self._healthy

# ---------------------------------------------------------------------------
# Singleton accessor (thread-safe)
# ---------------------------------------------------------------------------

_trust_client: TrustClient | None = None
_trust_client_lock = threading.Lock()

def get_trust_client() -> TrustClient:
    """Return (and lazily create) the global ``TrustClient`` instance.

    Thread-safe: uses a lock so concurrent callers (e.g. PRL evaluator
    threads) don't create duplicate instances.
    """
    global _trust_client
    if _trust_client is None:
        with _trust_client_lock:
            if _trust_client is None:  # double-check under lock
                _trust_client = TrustClient()
    return _trust_client
