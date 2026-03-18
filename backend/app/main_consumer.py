# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Consumer Entry Point (I4).

Launches all storage-writer consumers (PostgreSQL, ClickHouse, Neo4j),
the Trust Engine Bridge, and MCP Server Auto-Registrar as concurrent
asyncio tasks. This replaces inline API writes, enabling true decoupled
event processing.

Run: python -m app.main_consumer
"""

from __future__ import annotations

import asyncio
import signal
import sys

import structlog

from app.config import get_settings
from app.utils.logging import setup_logging

logger = structlog.get_logger("phantex.consumer.main")

async def main() -> None:
    """Start all storage-writer consumers and wait for shutdown signal."""
    setup_logging()
    settings = get_settings()

    consumers = []
    ssl_ctx = _build_ssl_context(settings)

    kafka_bootstrap = settings.kafka_bootstrap

    # ── PostgreSQL Writer ────────────────────────────────────────────
    try:
        import asyncpg

        pg_ssl_ctx = _build_pg_ssl_context(settings)
        # Consumer writes for ALL tenants — use admin DSN to bypass RLS.
        # asyncpg expects plain postgresql:// not postgresql+asyncpg://
        pg_dsn = settings.admin_database_url.replace("+asyncpg", "")
        pg_pool = await asyncpg.create_pool(
            dsn=pg_dsn,
            min_size=2,
            max_size=10,
            ssl=pg_ssl_ctx,
        )

        from app.consumers.pg_writer import PostgresWriter

        pg_consumer = PostgresWriter(
            pg_pool,
            bootstrap_servers=kafka_bootstrap,
            ssl_context=ssl_ctx,
        )
        consumers.append(("pg", pg_consumer, pg_pool))
        logger.info("pg_writer_configured")
    except Exception as e:
        logger.error("pg_writer_init_error", error=str(e))

    # ── ClickHouse Writer ────────────────────────────────────────────
    if settings.clickhouse_host:
        try:
            import clickhouse_connect

            ch_kwargs: dict = dict(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                database=settings.clickhouse_database,
                username=settings.clickhouse_user,
                password=settings.clickhouse_password,
            )
            if settings.clickhouse_tls_enabled:
                import ssl as _ssl

                ch_ssl_ctx = _ssl.create_default_context()
                if settings.clickhouse_tls_ca_file:
                    ch_ssl_ctx.load_verify_locations(settings.clickhouse_tls_ca_file)
                if settings.clickhouse_tls_cert_file and settings.clickhouse_tls_key_file:
                    ch_ssl_ctx.load_cert_chain(
                        settings.clickhouse_tls_cert_file,
                        settings.clickhouse_tls_key_file,
                    )
                ch_kwargs["secure"] = True
                ch_kwargs["ssl_context"] = ch_ssl_ctx

            ch_client = clickhouse_connect.get_client(**ch_kwargs)

            # Verify/create ClickHouse schema before starting writer
            from app.clickhouse import ensure_schema
            schema_ok = await ensure_schema()
            if schema_ok:
                logger.info("ch_schema_verified")
            else:
                logger.warning("ch_schema_verify_failed", msg="ClickHouse writer may encounter missing tables")

            from app.consumers.ch_writer import ClickHouseWriter

            ch_consumer = ClickHouseWriter(
                ch_client,
                bootstrap_servers=kafka_bootstrap,
                ssl_context=ssl_ctx,
            )
            consumers.append(("ch", ch_consumer, ch_client))
            logger.info("ch_writer_configured")
        except Exception as e:
            logger.error("ch_writer_init_error", error=str(e))

    # ── Neo4j Writer ─────────────────────────────────────────────────
    if settings.neo4j_uri:
        try:
            from neo4j import AsyncGraphDatabase

            neo4j_driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                encrypted=settings.neo4j_tls_enabled,
            )

            from app.consumers.neo4j_writer import Neo4jWriter

            neo4j_consumer = Neo4jWriter(
                neo4j_driver,
                bootstrap_servers=kafka_bootstrap,
                ssl_context=ssl_ctx,
            )
            consumers.append(("neo4j", neo4j_consumer, neo4j_driver))
            logger.info("neo4j_writer_configured")
        except Exception as e:
            logger.error("neo4j_writer_init_error", error=str(e))

    # ── Trust Engine Bridge ──────────────────────────────────────────
    try:
        from app.consumers.trust_bridge import TrustBridgeConsumer
        from app.services.trust_client import TrustClient

        trust_client = TrustClient()
        trust_bridge = TrustBridgeConsumer(
            trust_client,
            bootstrap_servers=kafka_bootstrap,
            ssl_context=ssl_ctx,
        )
        consumers.append(("trust-bridge", trust_bridge, trust_client))
        logger.info("trust_bridge_configured")
    except Exception as e:
        logger.error("trust_bridge_init_error", error=str(e))

    # ── MCP Server Auto-Registrar ────────────────────────────────────
    try:
        # Reuse the existing PG pool if available, otherwise create one
        mcp_pool = None
        for name, consumer, resource in consumers:
            if name == "pg":
                mcp_pool = resource
                break

        if mcp_pool is None:
            import asyncpg

            pg_ssl_ctx2 = _build_pg_ssl_context(settings)
            pg_dsn2 = settings.admin_database_url.replace("+asyncpg", "")
            mcp_pool = await asyncpg.create_pool(
                dsn=pg_dsn2,
                min_size=1,
                max_size=3,
                ssl=pg_ssl_ctx2,
            )

        from app.consumers.mcp_registrar import MCPRegistrarConsumer

        mcp_registrar = MCPRegistrarConsumer(
            mcp_pool,
            bootstrap_servers=kafka_bootstrap,
            ssl_context=ssl_ctx,
        )
        consumers.append(("mcp-registrar", mcp_registrar, mcp_pool))
        logger.info("mcp_registrar_configured")
    except Exception as e:
        logger.error("mcp_registrar_init_error", error=str(e))

    if not consumers:
        logger.error("no_consumers_configured", msg="Nothing to start")
        sys.exit(1)

    # ── Start all consumers ──────────────────────────────────────────
    for name, consumer, _ in consumers:
        await consumer.start()
        logger.info("consumer_started", name=name)

    # ── Wait for shutdown signal ─────────────────────────────────────
    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("shutdown_signal_received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    logger.info(
        "all_consumers_running",
        count=len(consumers),
        names=[name for name, _, _ in consumers],
    )

    await shutdown_event.wait()

    # ── Graceful shutdown ────────────────────────────────────────────
    logger.info("consumers_shutting_down")

    for name, consumer, resource in consumers:
        try:
            await consumer.stop()
        except Exception as e:
            logger.error("consumer_stop_error", name=name, error=str(e))

        # Close underlying connections
        try:
            if hasattr(resource, "close"):
                result = resource.close()
                if asyncio.iscoroutine(result):
                    await result
        except Exception as e:
            logger.warning("resource_close_error", name=name, error=str(e))

    logger.info("all_consumers_stopped")

def _build_ssl_context(settings):
    """Build SSL context for Kafka if TLS is enabled."""
    if not settings.kafka_tls_enabled:
        return None

    import ssl

    ctx = ssl.create_default_context()
    if settings.kafka_tls_ca_file:
        ctx.load_verify_locations(settings.kafka_tls_ca_file)
    if settings.kafka_tls_cert_file and settings.kafka_tls_key_file:
        ctx.load_cert_chain(settings.kafka_tls_cert_file, settings.kafka_tls_key_file)
    return ctx

def _build_pg_ssl_context(settings):
    """Build SSL context for asyncpg consumer pool.

    Mirrors the logic in app.database._build_ssl_context so that
    consumer PG connections use the same TLS settings as the main engine.
    """
    import ssl as _ssl

    mode = settings.db_ssl_mode
    if mode == "disable":
        return None

    # asyncpg natively supports "prefer" as a string — it negotiates
    # SSL and falls back silently if the server doesn't support it.
    if mode in ("prefer", "allow"):
        return "prefer"

    ctx = _ssl.create_default_context()

    if settings.db_ssl_ca_file:
        ctx.load_verify_locations(settings.db_ssl_ca_file)
    if settings.db_ssl_cert_file and settings.db_ssl_key_file:
        ctx.load_cert_chain(settings.db_ssl_cert_file, settings.db_ssl_key_file)

    if mode in ("require", "allow", "prefer"):
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    elif mode == "verify-ca":
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_REQUIRED
    elif mode == "verify-full":
        ctx.check_hostname = True
        ctx.verify_mode = _ssl.CERT_REQUIRED

    return ctx

if __name__ == "__main__":
    asyncio.run(main())
