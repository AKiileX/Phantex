# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — System Nerve Center Router.

Real-time infrastructure observability for the full Phantex pipeline:
  Sensor → Gateway → Kafka → 11 Consumers → [Postgres, ClickHouse, Neo4j, Redis]
                                  ↓
                           Trust Engine (Rust gRPC)
                                  ↓
                           Backend API → Dashboard

10 concurrent probes:
  postgres, redis, clickhouse, neo4j, kafka, gateway, backend,
  trust_engine, mcp_servers, consumers

Routes:
  GET  /api/v1/system/nerve-center — Full pipeline health snapshot
  GET  /api/v1/system/throughput   — Real-time throughput counters

Security:
  - Admin-only (ml.manage or telemetry.read permission)
  - Tenant-scoped where relevant
  - Rate-limited
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.database import engine as async_engine
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.utils.logging import get_logger

logger = get_logger("phantex.router.nerve_center")

router = APIRouter(
    prefix="/api/v1/system",
    tags=["system"],
    dependencies=[Depends(rate_limit), Depends(require_permission("telemetry.read"))],
)

# ── Probe helpers ─────────────────────────────────────────────────────────────
# Each returns a dict with status, latency_ms, and optional detail fields.
# Probes are isolated — one failure doesn't crash the endpoint.

async def _probe_postgres() -> dict[str, Any]:
    """Check PostgreSQL connectivity and collect pool stats."""
    t0 = time.monotonic()
    try:
        async with async_engine.connect() as conn:
            row = await conn.execute(text("SELECT 1"))
            row.close()
        latency = round((time.monotonic() - t0) * 1000, 1)
        pool = async_engine.pool  # type: ignore[attr-defined]
        result: dict[str, Any] = {
            "status": "healthy",
            "latency_ms": latency,
            "pool_size": pool.size() if hasattr(pool, "size") else 0,
            "pool_checked_in": pool.checkedin() if hasattr(pool, "checkedin") else 0,
            "pool_checked_out": pool.checkedout() if hasattr(pool, "checkedout") else 0,
            "pool_overflow": pool.overflow() if hasattr(pool, "overflow") else 0,
        }
        # Warn if pool is under pressure
        psize = result.get("pool_size", 0)
        pout = result.get("pool_checked_out", 0)
        if psize > 0 and pout / psize > 0.8:
            result["status"] = "degraded"
            result["diagnostic"] = (
                f"Connection pool under pressure: {pout}/{psize} connections checked out "
                f"({round(pout / psize * 100)}% utilization). Queries may queue."
            )
            result["troubleshooting"] = [
                "Monitor pool_checked_out / pool_size ratio over time",
                "Check for long-running queries: SELECT pid, state, query FROM pg_stat_activity WHERE state = 'active'",
                "Consider increasing SQLALCHEMY_POOL_SIZE in backend config",
            ]
        return result
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        logger.warning("nerve_center_pg_probe_failed", error=err)
        diagnostic = f"PostgreSQL connection failed: {err}"
        if "connection refused" in err.lower():
            diagnostic = f"PostgreSQL is not accepting connections on the configured host/port. Raw error: {err}"
        elif "password authentication" in err.lower():
            diagnostic = f"PostgreSQL rejected credentials. Check POSTGRES_PASSWORD env var. Raw error: {err}"
        elif "does not exist" in err.lower():
            diagnostic = f"PostgreSQL database or role not found. Verify DB_NAME and DB_USER. Raw error: {err}"
        return {
            "status": "unhealthy",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "docker logs phantex-postgres --tail 30",
                "docker exec phantex-postgres pg_isready -U phantex",
                "Check POSTGRES_HOST, POSTGRES_PORT, POSTGRES_PASSWORD env vars",
            ],
        }

async def _probe_redis() -> dict[str, Any]:
    """Check Redis connectivity."""
    import os

    t0 = time.monotonic()
    try:
        url = os.environ.get("PHANTEX_REDIS_URL", os.environ.get("REDIS_URL", "redis://redis:6379/0"))
        r = aioredis.from_url(url, socket_connect_timeout=3)
        pong = await r.ping()
        info = await r.info("memory")
        await r.aclose()
        latency = round((time.monotonic() - t0) * 1000, 1)
        used_mb = round(info.get("used_memory", 0) / 1024 / 1024, 1)
        result: dict[str, Any] = {
            "status": "healthy" if pong else "unhealthy",
            "latency_ms": latency,
            "used_memory_mb": used_mb,
            "connected_clients": info.get("connected_clients", 0),
        }
        if not pong:
            result["diagnostic"] = "Redis PING returned False — server may be in protected mode or shutting down."
            result["troubleshooting"] = [
                "docker logs phantex-redis --tail 20",
                "docker exec phantex-redis redis-cli PING",
                "Check if Redis is in protected mode and needs a password",
            ]
        elif used_mb > 200:
            result["status"] = "degraded"
            result["diagnostic"] = f"Redis memory usage high: {used_mb} MB. Consider flushing stale keys."
            result["troubleshooting"] = [
                "docker exec phantex-redis redis-cli INFO memory",
                "docker exec phantex-redis redis-cli DBSIZE",
                "Consider setting maxmemory and maxmemory-policy in redis.conf",
            ]
        return result
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        logger.warning("nerve_center_redis_probe_failed", error=err)
        diagnostic = f"Redis connection failed: {err}"
        if "connection refused" in err.lower():
            diagnostic = f"Redis is not running or not listening on the configured URL. Raw error: {err}"
        elif "auth" in err.lower() or "noauth" in err.lower():
            diagnostic = f"Redis requires authentication. Set REDIS_URL with password. Raw error: {err}"
        return {
            "status": "unhealthy",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "docker logs phantex-redis --tail 20",
                "docker exec phantex-redis redis-cli PING",
                "Check PHANTEX_REDIS_URL or REDIS_URL env var",
            ],
        }

async def _probe_clickhouse() -> dict[str, Any]:
    """Check ClickHouse connectivity and event throughput."""
    import os

    t0 = time.monotonic()
    try:
        import httpx

        ch_host = os.environ.get("PHANTEX_CLICKHOUSE_HOST", os.environ.get("CLICKHOUSE_HOST", "clickhouse"))
        ch_port = os.environ.get("PHANTEX_CLICKHOUSE_PORT", os.environ.get("CLICKHOUSE_HTTP_PORT", "8123"))
        ch_user = os.environ.get("CLICKHOUSE_USER", "phantex")
        ch_pass = os.environ.get(
            "PHANTEX_CLICKHOUSE_PASSWORD", os.environ.get("CLICKHOUSE_PASSWORD", "phantex-dev-password")
        )
        ch_db = os.environ.get("CLICKHOUSE_DB", "phantex")
        url = f"http://{ch_host}:{ch_port}/"

        async with httpx.AsyncClient(timeout=5) as client:
            # Basic ping
            resp = await client.get(url, params={"query": "SELECT 1", "user": ch_user, "password": ch_pass})
            latency = round((time.monotonic() - t0) * 1000, 1)

            if resp.status_code != 200:
                return {
                    "status": "degraded",
                    "latency_ms": latency,
                    "error": f"ClickHouse returned HTTP {resp.status_code}: {resp.text[:200]}",
                    "diagnostic": f"ClickHouse health check returned HTTP {resp.status_code}. "
                    f"The server is reachable but not responding correctly. Response: {resp.text[:150]}",
                    "troubleshooting": [
                        f"curl 'http://{ch_host}:{ch_port}/?query=SELECT+1&user={ch_user}&password=***'",
                        "docker logs phantex-clickhouse --tail 30",
                        "Check CLICKHOUSE_USER and CLICKHOUSE_PASSWORD env vars",
                    ],
                }

            # Event count last 60s (must specify database)
            count_resp = await client.get(
                url,
                params={
                    "query": f"SELECT count() FROM {ch_db}.events WHERE timestamp >= now() - INTERVAL 60 SECOND",
                    "user": ch_user,
                    "password": ch_pass,
                },
            )
            events_last_60s = 0
            with contextlib.suppress(ValueError, TypeError):
                events_last_60s = int(count_resp.text.strip())

            return {
                "status": "healthy",
                "latency_ms": latency,
                "events_last_60s": events_last_60s,
                "events_per_sec": round(events_last_60s / 60, 1),
            }
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        logger.warning("nerve_center_ch_probe_failed", error=err)
        diagnostic = f"ClickHouse connection failed: {err}"
        if "connection refused" in err.lower() or "connect" in err.lower():
            diagnostic = f"ClickHouse is not reachable at {os.environ.get('CLICKHOUSE_HOST', 'clickhouse')}:{os.environ.get('CLICKHOUSE_HTTP_PORT', '8123')}. Raw error: {err}"
        return {
            "status": "unhealthy",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "docker logs phantex-clickhouse --tail 30",
                "curl http://clickhouse:8123/?query=SELECT+1",
                "Check CLICKHOUSE_HOST and CLICKHOUSE_HTTP_PORT env vars",
            ],
        }

async def _probe_neo4j() -> dict[str, Any]:
    """Check Neo4j connectivity."""
    import os

    t0 = time.monotonic()
    try:
        import httpx

        neo4j_host = os.environ.get("NEO4J_HOST", "neo4j")
        url = f"http://{neo4j_host}:7474"

        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            latency = round((time.monotonic() - t0) * 1000, 1)
            if resp.status_code == 200:
                return {
                    "status": "healthy",
                    "latency_ms": latency,
                }
            return {
                "status": "degraded",
                "latency_ms": latency,
                "error": f"Neo4j returned HTTP {resp.status_code}",
                "diagnostic": f"Neo4j HTTP API returned status {resp.status_code} instead of 200. "
                f"The server may be starting up or in maintenance mode.",
                "troubleshooting": [
                    "docker logs phantex-neo4j --tail 30",
                    f"curl http://{neo4j_host}:7474",
                    "Check Neo4j Browser at http://localhost:7474 for status details",
                ],
            }
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        logger.warning("nerve_center_neo4j_probe_failed", error=err)
        diagnostic = f"Neo4j is unreachable: {err}"
        if "connection refused" in err.lower():
            diagnostic = f"Neo4j is not running or not listening on port 7474. Raw error: {err}"
        return {
            "status": "unhealthy",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "docker logs phantex-neo4j --tail 30",
                "docker restart phantex-neo4j",
                "Check NEO4J_HOST env var (default: neo4j)",
            ],
        }

async def _probe_kafka() -> dict[str, Any]:
    """Check Kafka connectivity and consumer lag."""
    import os

    t0 = time.monotonic()
    try:
        import httpx

        # Try Kafka UI API for cluster info
        kafka_ui = os.environ.get("KAFKA_UI_URL", "http://kafka-ui:8080")
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{kafka_ui}/api/clusters/phantex-dev/stats")
            latency = round((time.monotonic() - t0) * 1000, 1)
            if resp.status_code == 200:
                stats = resp.json()
                return {
                    "status": "healthy",
                    "latency_ms": latency,
                    "broker_count": stats.get("brokerCount", 1),
                    "topic_count": stats.get("topicCount", 0),
                    "active_consumers": stats.get("activeConsumers", 0),
                }
            return {
                "status": "degraded",
                "latency_ms": latency,
                "error": f"Kafka-UI stats returned HTTP {resp.status_code}",
                "diagnostic": (
                    f"Kafka-UI API at {kafka_ui}/api/clusters/phantex-dev/stats "
                    f"returned HTTP {resp.status_code}. The Kafka cluster may be "
                    f"misconfigured in kafka-ui or the cluster name 'phantex-dev' "
                    f"doesn't match."
                ),
                "troubleshooting": [
                    "docker logs phantex-kafka-ui --tail 20",
                    f"curl {kafka_ui}/api/clusters",
                    "Check that the cluster name in kafka-ui config matches 'phantex-dev'",
                    "Verify KAFKA_UI_URL env var",
                ],
            }
    except Exception:
        # Fallback — just check the bootstrap server
        try:
            import socket

            kafka_host = os.environ.get("KAFKA_BOOTSTRAP", "kafka")
            kafka_port = int(os.environ.get("KAFKA_PORT", "9092"))
            sock = socket.create_connection((kafka_host, kafka_port), timeout=3)
            sock.close()
            latency = round((time.monotonic() - t0) * 1000, 1)
            return {
                "status": "healthy",
                "latency_ms": latency,
                "diagnostic": (
                    "Kafka broker is reachable via TCP but kafka-ui API is unavailable. "
                    "Broker health confirmed via direct socket connection to "
                    f"{kafka_host}:{kafka_port}."
                ),
            }
        except Exception as exc2:
            latency = round((time.monotonic() - t0) * 1000, 1)
            err = str(exc2)[:300]
            logger.warning("nerve_center_kafka_probe_failed", error=err)
            return {
                "status": "unhealthy",
                "latency_ms": latency,
                "error": err,
                "diagnostic": f"Kafka broker is unreachable: {err}. Neither kafka-ui nor direct TCP connection succeeded.",
                "troubleshooting": [
                    "docker logs phantex-kafka --tail 30",
                    "docker restart phantex-kafka",
                    "Check KAFKA_BOOTSTRAP and KAFKA_PORT env vars",
                    "Verify Docker network connectivity: docker network inspect phantex_default",
                ],
            }

async def _probe_gateway() -> dict[str, Any]:
    """Check Gateway gRPC port connectivity (no HTTP health — gRPC only)."""
    import os
    import socket

    t0 = time.monotonic()
    try:
        gw_host = os.environ.get("GATEWAY_HOST", "phantex-gateway")
        gw_port = int(os.environ.get("GATEWAY_GRPC_PORT", "50051"))
        # Non-blocking TCP check via asyncio
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        await loop.run_in_executor(None, sock.connect, (gw_host, gw_port))
        sock.close()
        latency = round((time.monotonic() - t0) * 1000, 1)
        return {
            "status": "healthy",
            "latency_ms": latency,
        }
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        gw_host = os.environ.get("GATEWAY_HOST", "phantex-gateway")
        gw_port = os.environ.get("GATEWAY_GRPC_PORT", "50051")
        diagnostic = (
            f"Gateway gRPC port unreachable at {gw_host}:{gw_port}. "
            f"The gateway container may be down or the gRPC listener failed to bind. "
            f"Raw error: {err}"
        )
        return {
            "status": "unhealthy",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "docker logs phantex-gateway --tail 30",
                "docker restart phantex-gateway",
                f"Test TCP: docker exec phantex-backend python -c \"import socket; s=socket.create_connection(('{gw_host}', {gw_port}), 3); s.close(); print('OK')\"",
                "Check GATEWAY_HOST and GATEWAY_GRPC_PORT env vars",
            ],
        }

async def _probe_trust_engine() -> dict[str, Any]:
    """Check Rust trust engine via gRPC health endpoint."""
    t0 = time.monotonic()
    try:
        from app.services.trust_client import get_trust_client

        client = get_trust_client()
        health = await client.health_check()
        latency = round((time.monotonic() - t0) * 1000, 1)

        if health.status and health.status.lower() in ("ok", "healthy", "serving"):
            return {
                "status": "healthy",
                "latency_ms": latency,
                "total_nodes": health.total_nodes,
                "total_edges": health.total_edges,
                "tenants": health.tenants,
                "uptime_secs": health.uptime_secs,
            }
        # Engine responded but status is unknown — might be starting up
        raw = health.status or "no-response"
        return {
            "status": "degraded",
            "latency_ms": latency,
            "total_nodes": health.total_nodes,
            "total_edges": health.total_edges,
            "raw_status": raw,
            "diagnostic": (
                f"Trust Engine gRPC responded but reported status '{raw}' instead of "
                f"'healthy'/'serving'. The engine may be starting up, rebuilding its "
                f"graph, or in a degraded state. Nodes: {health.total_nodes}, "
                f"Edges: {health.total_edges}."
            ),
            "troubleshooting": [
                "docker logs phantex-trust-engine --tail 30",
                "grpcurl -plaintext localhost:50052 grpc.health.v1.Health/Check",
                "Check if the trust graph has been initialized (total_nodes > 0)",
            ],
        }
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        logger.warning("nerve_center_trust_engine_probe_failed", error=err)
        diagnostic = f"Trust Engine gRPC unreachable: {err}"
        if "connect" in err.lower() or "refused" in err.lower():
            diagnostic = (
                f"Trust Engine (Rust gRPC service) is not running or not reachable "
                f"on port 50052. This prevents trust score computation and graph "
                f"propagation. Raw error: {err}"
            )
        elif "deadline" in err.lower() or "timeout" in err.lower():
            diagnostic = (
                f"Trust Engine gRPC timed out. The engine may be overloaded with graph computations. Raw error: {err}"
            )
        return {
            "status": "unhealthy",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "docker logs phantex-trust-engine --tail 30",
                "docker restart phantex-trust-engine",
                "Check port 50052 is exposed and not conflicting",
                "Verify TRUST_ENGINE_HOST env var",
            ],
        }

async def _probe_mcp_servers() -> dict[str, Any]:
    """Check MCP server registry (count via PostgreSQL)."""
    t0 = time.monotonic()
    try:
        async with async_engine.connect() as conn:
            row = await conn.execute(
                text("SELECT count(*) FROM mcp_servers"),
            )
            total = row.scalar() or 0
            blocked_row = await conn.execute(
                text("SELECT count(*) FROM mcp_servers WHERE trust_level = 'BLOCKED'"),
            )
            blocked = blocked_row.scalar() or 0
        latency = round((time.monotonic() - t0) * 1000, 1)
        result: dict[str, Any] = {
            "status": "healthy",
            "latency_ms": latency,
            "total_servers": total,
            "blocked_servers": blocked,
        }
        if blocked > 0 and total > 0 and blocked / total > 0.5:
            result["status"] = "degraded"
            result["diagnostic"] = (
                f"{blocked}/{total} MCP servers are BLOCKED ({round(blocked / total * 100)}%). "
                f"This may indicate a supply-chain compromise or overly aggressive blocking rules."
            )
            result["troubleshooting"] = [
                "Review blocked servers: SELECT name, trust_level, blocked_reason FROM mcp_servers WHERE trust_level = 'BLOCKED'",
                "Check MCP trust scoring configuration",
                "Review recent MCP observatory alerts",
            ]
        return result
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        # Table might not exist yet — treat as degraded, not unhealthy
        logger.warning("nerve_center_mcp_probe_failed", error=err)
        diagnostic = f"MCP server registry query failed: {err}"
        if "does not exist" in err.lower() or "relation" in err.lower():
            diagnostic = (
                f"The mcp_servers table does not exist yet. This is expected if "
                f"MCP migrations haven't been applied. Raw error: {err}"
            )
        return {
            "status": "degraded",
            "latency_ms": latency,
            "error": err,
            "diagnostic": diagnostic,
            "troubleshooting": [
                "Run MCP migrations: alembic upgrade head",
                "Check if mcp_servers table exists: \\dt mcp_servers",
                "Verify PostgreSQL connectivity for the MCP schema",
            ],
        }

async def _probe_consumers() -> dict[str, Any]:
    """Check Kafka consumer group status via kafka-ui or direct socket."""
    import os

    t0 = time.monotonic()
    try:
        import httpx

        kafka_ui = os.environ.get("KAFKA_UI_URL", "http://kafka-ui:8080")
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                f"{kafka_ui}/api/clusters/phantex-dev/consumer-groups/paged",
                params={"page": 0, "perPage": 100},
            )
            latency = round((time.monotonic() - t0) * 1000, 1)
            if resp.status_code == 200:
                body = resp.json()
                groups = body.get("consumerGroups", body) if isinstance(body, dict) else body
                total_lag = 0
                active_groups = 0
                group_details = {}
                lagging_groups = []
                for g in groups if isinstance(groups, list) else []:
                    name = g.get("groupId", g.get("consumerGroupId", "unknown"))
                    lag = g.get("consumerLag", g.get("messagesBehind", 0)) or 0
                    total_lag += lag
                    active_groups += 1
                    group_details[name] = {"lag": lag}
                    if lag > 10_000:
                        lagging_groups.append(f"{name} (lag: {lag:,})")
                result: dict[str, Any] = {
                    "status": "healthy" if total_lag < 100_000 else "degraded",
                    "latency_ms": latency,
                    "active_groups": active_groups,
                    "total_lag": total_lag,
                    "groups": group_details,
                }
                if total_lag >= 100_000:
                    result["diagnostic"] = (
                        f"Consumer lag is {total_lag:,} messages across {active_groups} groups. "
                        f"Lagging groups: {', '.join(lagging_groups[:5])}. "
                        f"Consumers can't keep up with production rate."
                    )
                    result["troubleshooting"] = [
                        "docker ps | grep writer — check consumer containers are running",
                        "docker logs phantex-storage-writer --tail 30",
                        "Consider scaling consumer instances or increasing batch sizes",
                        f"Monitor topic offsets: {kafka_ui}/ui/clusters/phantex-dev/consumer-groups",
                    ]
                return result

            # consumer-groups endpoint returned non-200 (404 in newer kafka-ui).
            # Fall back to cluster stats for basic health check.
            cg_status = resp.status_code
            cg_body = resp.text[:200]
            stats_resp = await client.get(f"{kafka_ui}/api/clusters/phantex-dev/stats")
            latency = round((time.monotonic() - t0) * 1000, 1)
            if stats_resp.status_code == 200:
                stats = stats_resp.json()
                return {
                    "status": "healthy",
                    "latency_ms": latency,
                    "active_groups": 0,
                    "total_lag": 0,
                    "broker_count": stats.get("brokerCount", 0),
                    "online_partitions": stats.get("onlinePartitionCount", 0),
                    "diagnostic": (
                        f"Consumer group details unavailable: kafka-ui /consumer-groups "
                        f"endpoint returned HTTP {cg_status} ({cg_body[:80]}). "
                        f"This is a known issue with newer kafka-ui versions where the "
                        f"consumer-groups API path has changed. Kafka cluster health "
                        f"confirmed via /stats endpoint instead."
                    ),
                    "troubleshooting": [
                        f"kafka-ui consumer-groups returned {cg_status} — API path may have changed in this kafka-ui version",
                        "Try: curl http://kafka-ui:8080/api/clusters/phantex-dev/consumer-groups",
                        "Consider upgrading or checking kafka-ui release notes for API changes",
                        "As a workaround, consumer lag is not monitored — check manually via kafka CLI",
                    ],
                }
            return {
                "status": "degraded",
                "latency_ms": latency,
                "diagnostic": (
                    f"Both kafka-ui endpoints failed. /consumer-groups returned HTTP {cg_status}, "
                    f"/stats returned HTTP {stats_resp.status_code}. Kafka-UI may be misconfigured."
                ),
                "troubleshooting": [
                    "docker logs phantex-kafka-ui --tail 30",
                    "docker restart phantex-kafka-ui",
                    "Verify kafka-ui cluster name matches 'phantex-dev'",
                ],
            }
    except Exception as exc:
        latency = round((time.monotonic() - t0) * 1000, 1)
        err = str(exc)[:300]
        logger.warning("nerve_center_consumer_probe_failed", error=err)
        return {
            "status": "degraded",
            "latency_ms": latency,
            "error": err,
            "diagnostic": (
                f"Consumer probe failed: {err}. Could not reach kafka-ui to check "
                f"consumer group status. This doesn't necessarily mean consumers are "
                f"down — only that monitoring via kafka-ui is unavailable."
            ),
            "troubleshooting": [
                "docker logs phantex-kafka-ui --tail 20",
                "docker ps | grep writer — verify consumer containers directly",
                "Check KAFKA_UI_URL env var (default: http://kafka-ui:8080)",
            ],
        }

async def _probe_backend() -> dict[str, Any]:
    """Self-check — backend process stats via /proc (no psutil needed)."""
    import os
    import pathlib

    time.monotonic()
    try:
        pid = os.getpid()
        # RSS from /proc/<pid>/status (Linux)
        rss_kb = 0
        threads = 0
        status_path = pathlib.Path(f"/proc/{pid}/status")
        if status_path.exists():
            for line in status_path.read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
        # Uptime from /proc/<pid>/stat field 22 (start ticks)
        uptime_s = 0
        stat_path = pathlib.Path(f"/proc/{pid}/stat")
        if stat_path.exists():
            fields = stat_path.read_text().split()
            # field index 21 = starttime in clock ticks
            try:
                clock_ticks = os.sysconf("SC_CLK_TCK")
                boot_time = float(pathlib.Path("/proc/uptime").read_text().split()[0])
                start_ticks = int(fields[21])
                proc_start = start_ticks / clock_ticks
                uptime_s = round(boot_time - proc_start)
            except (IndexError, ValueError, OSError):
                pass
        return {
            "status": "healthy",
            "latency_ms": 0,
            "pid": pid,
            "uptime_seconds": max(0, uptime_s),
            "memory_rss_mb": round(rss_kb / 1024, 1),
            "threads": threads,
        }
    except Exception as exc:
        err = str(exc)[:300]
        return {
            "status": "degraded",
            "latency_ms": 0,
            "error": err,
            "diagnostic": f"Backend self-check failed: {err}. This is unexpected since the API is clearly running (you're seeing this response).",
            "troubleshooting": [
                "docker logs phantex-backend --tail 30",
                "Check /proc filesystem availability inside container",
                "This is a non-critical self-check — the API is functioning",
            ],
        }

# ── Pipeline event counters (in-memory, updated by consumer) ──────────────────

_throughput: dict[str, Any] = {
    "events_ingested": 0,
    "events_processed": 0,
    "events_dropped": 0,
    "last_event_at": None,
    "start_time": time.time(),
}

def record_event(*, ingested: int = 0, processed: int = 0, dropped: int = 0) -> None:
    """Called by the event consumer to update throughput counters."""
    _throughput["events_ingested"] += ingested
    _throughput["events_processed"] += processed
    _throughput["events_dropped"] += dropped
    _throughput["last_event_at"] = time.time()

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/nerve-center", summary="Full pipeline health snapshot")
async def get_nerve_center(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """
    Aggregate health probes for every component in the Phantex pipeline.
    All probes run in parallel with timeouts — one failure doesn't block others.
    """
    # Run all probes concurrently (10 probes)
    results = await asyncio.gather(
        _probe_postgres(),
        _probe_redis(),
        _probe_clickhouse(),
        _probe_neo4j(),
        _probe_kafka(),
        _probe_gateway(),
        _probe_backend(),
        _probe_trust_engine(),
        _probe_mcp_servers(),
        _probe_consumers(),
        return_exceptions=True,
    )

    def _safe(idx: int, name: str) -> dict[str, Any]:
        r = results[idx]
        if isinstance(r, Exception):
            return {"status": "error", "latency_ms": 0, "error": str(r)[:200]}
        return r  # type: ignore[return-value]

    components = {
        "postgres": _safe(0, "postgres"),
        "redis": _safe(1, "redis"),
        "clickhouse": _safe(2, "clickhouse"),
        "neo4j": _safe(3, "neo4j"),
        "kafka": _safe(4, "kafka"),
        "gateway": _safe(5, "gateway"),
        "backend": _safe(6, "backend"),
        "trust_engine": _safe(7, "trust_engine"),
        "mcp_servers": _safe(8, "mcp_servers"),
        "consumers": _safe(9, "consumers"),
    }

    # Overall status
    statuses = [c.get("status", "unknown") for c in components.values()]
    if all(s == "healthy" for s in statuses):
        overall = "operational"
    elif any(s == "unhealthy" or s == "error" for s in statuses):
        overall = "degraded"
    else:
        overall = "partial"

    # Throughput snapshot
    uptime = max(1, time.time() - _throughput["start_time"])
    throughput = {
        "events_ingested": _throughput["events_ingested"],
        "events_processed": _throughput["events_processed"],
        "events_dropped": _throughput["events_dropped"],
        "events_per_sec": round(_throughput["events_ingested"] / uptime, 2),
        "last_event_at": _throughput["last_event_at"],
        "uptime_seconds": round(uptime),
    }

    # Pipeline definition (for the visualization)
    pipeline = [
        {"id": "sensor", "label": "Sensor", "type": "source", "group": "ingress"},
        {"id": "gateway", "label": "Gateway", "type": "service", "group": "ingress"},
        {"id": "kafka", "label": "Kafka", "type": "queue", "group": "transport"},
        {
            "id": "consumers",
            "label": "Consumers",
            "type": "service",
            "group": "processing",
            "detail": "11 groups: 3 storage + 4 ML + 2 trust/MCP + 2 fanout",
        },
        {"id": "backend", "label": "Backend API", "type": "service", "group": "processing"},
        {
            "id": "trust_engine",
            "label": "Trust Engine",
            "type": "service",
            "group": "processing",
            "detail": "Rust gRPC — graph scoring, PageRank propagation",
        },
        {"id": "postgres", "label": "PostgreSQL", "type": "database", "group": "storage"},
        {"id": "clickhouse", "label": "ClickHouse", "type": "database", "group": "storage"},
        {"id": "neo4j", "label": "Neo4j", "type": "database", "group": "storage"},
        {"id": "redis", "label": "Redis", "type": "cache", "group": "storage"},
        {
            "id": "mcp",
            "label": "MCP Servers",
            "type": "external",
            "group": "agents",
            "detail": "Monitored MCP servers (supply chain detection)",
        },
        {"id": "dashboard", "label": "Dashboard", "type": "service", "group": "presentation"},
    ]

    connections = [
        {"from": "sensor", "to": "gateway", "label": "gRPC events (mTLS)"},
        {"from": "gateway", "to": "kafka", "label": "Produce messages (LZ4)"},
        {"from": "kafka", "to": "consumers", "label": "Fan-out to 11 groups"},
        {"from": "consumers", "to": "postgres", "label": "pg-writer batch 500/2s"},
        {"from": "consumers", "to": "clickhouse", "label": "ch-writer batch 5000/5s"},
        {"from": "consumers", "to": "neo4j", "label": "neo4j-writer batch 1000/5s"},
        {"from": "consumers", "to": "redis", "label": "ML features → ZSETs"},
        {"from": "consumers", "to": "trust_engine", "label": "trust-bridge → gRPC events"},
        {"from": "trust_engine", "to": "backend", "label": "gRPC trust scores"},
        {"from": "backend", "to": "postgres", "label": "Alerts, agents, sessions"},
        {"from": "backend", "to": "redis", "label": "Cache, rate limiting, tickets"},
        {"from": "backend", "to": "dashboard", "label": "REST + WebSocket"},
        {"from": "mcp", "to": "sensor", "label": "SDK hooks (tool calls)"},
    ]

    return {
        "status": overall,
        "timestamp": time.time(),
        "components": components,
        "throughput": throughput,
        "pipeline": pipeline,
        "connections": connections,
    }

@router.get("/throughput", summary="Real-time throughput counters")
async def get_throughput(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Lightweight endpoint for high-frequency polling of throughput stats."""
    uptime = max(1, time.time() - _throughput["start_time"])
    return {
        "events_ingested": _throughput["events_ingested"],
        "events_processed": _throughput["events_processed"],
        "events_dropped": _throughput["events_dropped"],
        "events_per_sec": round(_throughput["events_ingested"] / uptime, 2),
        "last_event_at": _throughput["last_event_at"],
        "uptime_seconds": round(uptime),
    }
