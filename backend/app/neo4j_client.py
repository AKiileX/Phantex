# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Neo4j Client.

Async Neo4j driver for investigation graph queries.
Provides connection, health check, and shutdown helpers.

All Cypher queries MUST include tenant_id parameter for isolation.
"""

from __future__ import annotations

import asyncio
from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase

from app.config import get_settings
from app.utils.logging import get_logger

logger = get_logger("phantex.neo4j")

_driver: AsyncDriver | None = None
_driver_lock = asyncio.Lock()

async def get_neo4j() -> AsyncDriver | None:
    """Return the shared async Neo4j driver, creating it on first call.

    Returns None if Neo4j is not configured (neo4j_uri is empty).
    Uses asyncio.Lock to prevent race conditions during lazy initialisation.
    """
    global _driver
    if _driver is not None:
        return _driver

    async with _driver_lock:
        # Double-check after acquiring the lock
        if _driver is not None:
            return _driver

        settings = get_settings()
        if not settings.neo4j_uri:
            logger.info("neo4j_disabled", reason="PHANTEX_NEO4J_URI not set")
            return None

        try:
            _driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                database=settings.neo4j_database,
                max_connection_pool_size=25,
                connection_acquisition_timeout=10.0,
                encrypted=settings.neo4j_tls_enabled,
            )
            # Verify connectivity
            await _driver.verify_connectivity()
            logger.info(
                "neo4j_connected",
                uri=settings.neo4j_uri,
                database=settings.neo4j_database,
            )
        except Exception as e:
            logger.warning("neo4j_connect_failed", error=str(e))
            _driver = None

        return _driver

async def close_neo4j() -> None:
    """Close the Neo4j driver."""
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None
        logger.info("neo4j_closed")

async def check_neo4j_health() -> dict[str, Any]:
    """Health check — returns version info."""
    driver = await get_neo4j()
    if driver is None:
        return {"status": "disabled"}
    try:
        info = await driver.get_server_info()
        return {
            "status": "healthy",
            "version": info.agent,
            "protocol_version": str(info.protocol_version),
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
