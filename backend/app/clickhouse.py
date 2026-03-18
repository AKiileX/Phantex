# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — ClickHouse Client.

Async ClickHouse client using clickhouse-connect for analytics queries.
Provides connection pool, health check, and query helpers.

All queries MUST include tenant_id parameter for isolation.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.asyncclient import AsyncClient

from app.config import get_settings
from app.utils.logging import get_logger

logger = get_logger("phantex.clickhouse")

_client: AsyncClient | None = None
_client_lock = asyncio.Lock()

async def get_clickhouse() -> AsyncClient | None:
    """Return the shared async ClickHouse client, creating it on first call.

    Returns None if ClickHouse is not configured (clickhouse_host is empty).
    Uses asyncio.Lock to prevent race conditions during lazy initialisation.
    """
    global _client
    if _client is not None:
        return _client

    async with _client_lock:
        # Double-check after acquiring the lock
        if _client is not None:
            return _client

        settings = get_settings()
        if not settings.clickhouse_host:
            logger.info("clickhouse_disabled", reason="PHANTEX_CLICKHOUSE_HOST not set")
            return None

        ssl_ctx: ssl.SSLContext | bool | None = None
        if settings.clickhouse_tls_enabled:
            ssl_ctx = ssl.create_default_context()
            if settings.clickhouse_tls_ca_file:
                ssl_ctx.load_verify_locations(settings.clickhouse_tls_ca_file)
            if settings.clickhouse_tls_cert_file and settings.clickhouse_tls_key_file:
                ssl_ctx.load_cert_chain(
                    settings.clickhouse_tls_cert_file,
                    settings.clickhouse_tls_key_file,
                )

        try:
            kwargs: dict[str, Any] = dict(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                database=settings.clickhouse_database,
                username=settings.clickhouse_user,
                password=settings.clickhouse_password,
                secure=settings.clickhouse_tls_enabled,
                connect_timeout=10,
                send_receive_timeout=30,
                compress=True,
            )
            if isinstance(ssl_ctx, ssl.SSLContext):
                kwargs["ssl_context"] = ssl_ctx
            _client = await clickhouse_connect.get_async_client(**kwargs)
            logger.info(
                "clickhouse_connected",
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                database=settings.clickhouse_database,
            )
        except Exception as e:
            logger.warning("clickhouse_connect_failed", error=str(e))
            _client = None

        return _client

async def close_clickhouse() -> None:
    """Close the ClickHouse client connection."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
        logger.info("clickhouse_closed")

async def ensure_schema(client: AsyncClient | None = None) -> bool:
    """Verify critical ClickHouse tables exist and create them if missing.

    Uses CREATE TABLE IF NOT EXISTS — fully idempotent.
    Returns True if schema is ready, False if ClickHouse is unavailable.
    """
    if client is None:
        client = await get_clickhouse()
    if client is None:
        return False

    _REQUIRED_TABLES = [
        # ── Core events table (001_events.sql) ───────────────────────
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id      UUID,
            tenant_id     UUID,
            agent_id      String        DEFAULT '',
            sensor_id     String        DEFAULT '',
            event_type    LowCardinality(String),
            attack_class  LowCardinality(Nullable(String)),
            severity      LowCardinality(String)     DEFAULT 'info',
            payload       String        DEFAULT '{}',
            source_ip     Nullable(IPv4),
            dest_ip       Nullable(IPv4),
            dest_port     Nullable(UInt16),
            bytes_sent    Nullable(UInt64),
            bytes_recv    Nullable(UInt64),
            file_path     Nullable(String),
            tool_name     Nullable(String),
            duration_ms   Nullable(UInt32),
            framework     LowCardinality(String)     DEFAULT '',
            timestamp     DateTime64(3, 'UTC'),
            ingested_at   DateTime64(3, 'UTC')       DEFAULT now64(3)
        )
        ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (tenant_id, agent_id, timestamp)
        TTL toDateTime(timestamp) + INTERVAL 90 DAY
        SETTINGS index_granularity = 8192
        """,
        # ── Hourly aggregations (002_aggregations.sql) ───────────────
        """
        CREATE TABLE IF NOT EXISTS events_hourly (
            tenant_id    UUID,
            agent_id     String,
            event_type   LowCardinality(String),
            severity     LowCardinality(String),
            hour         DateTime,
            event_count  UInt64,
            bytes_sent   UInt64,
            bytes_recv   UInt64
        )
        ENGINE = SummingMergeTree()
        PARTITION BY toYYYYMM(hour)
        ORDER BY (tenant_id, agent_id, event_type, severity, hour)
        TTL hour + INTERVAL 90 DAY
        """,
        # ── ML features (003_ml_features.sql) ────────────────────────
        """
        CREATE TABLE IF NOT EXISTS ml_features_hourly (
            tenant_id               UUID,
            agent_id                String,
            hour                    DateTime,
            event_count             UInt64,
            tool_call_count         UInt64,
            file_read_count         UInt64,
            network_connect_count   UInt64,
            bytes_sent_total        UInt64,
            bytes_recv_total        UInt64,
            unique_dest_ips         UInt64,
            unique_dest_ports       UInt64,
            unique_event_types      UInt64,
            unique_tools            UInt64,
            unique_files            UInt64,
            avg_duration_ms         Float64,
            max_duration_ms         UInt32
        )
        ENGINE = SummingMergeTree()
        PARTITION BY toYYYYMM(hour)
        ORDER BY (tenant_id, agent_id, hour)
        TTL hour + INTERVAL 90 DAY
        """,
        # ── Token usage / FinOps (005_finops_cost_tracking.sql) ──────
        """
        CREATE TABLE IF NOT EXISTS token_usage (
            tenant_id          UUID,
            agent_id           String,
            request_id         String,
            provider           LowCardinality(String),
            model              LowCardinality(String),
            prompt_tokens      UInt32,
            completion_tokens  UInt32,
            total_tokens       UInt32,
            estimated_cost_usd Float64,
            latency_ms         Float64,
            source             LowCardinality(String)  DEFAULT 'backend',
            timestamp          DateTime64(3)           DEFAULT now64(3)
        )
        ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (tenant_id, agent_id, timestamp)
        TTL toDateTime(timestamp) + INTERVAL 90 DAY
        """,
    ]

    settings = get_settings()
    db = settings.clickhouse_database

    try:
        # Ensure database exists
        await client.command(f"CREATE DATABASE IF NOT EXISTS {db}")

        # Verify and create each table
        for ddl in _REQUIRED_TABLES:
            await client.command(ddl)

        # Verify with a count query
        result = await client.query(
            "SELECT count() FROM system.tables WHERE database = {db:String}",
            parameters={"db": db},
        )
        table_count = result.first_row[0] if result.first_row else 0
        logger.info("clickhouse_schema_verified", database=db, tables=table_count)
        return True
    except Exception as e:
        logger.error("clickhouse_schema_verify_failed", error=str(e))
        return False

async def check_clickhouse_health() -> dict[str, Any]:
    """Health check — returns version and uptime."""
    client = await get_clickhouse()
    if client is None:
        return {"status": "disabled"}
    try:
        result = await client.query("SELECT version(), uptime()")
        row = result.first_row
        return {
            "status": "healthy",
            "version": row[0],
            "uptime_seconds": row[1],
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
