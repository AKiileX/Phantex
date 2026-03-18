# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — MCP Server Auto-Registrar Consumer.

Kafka consumer that detects MCP tool usage in events (TOOL_CALL events
with tool_category='mcp_tool' or tool_name starting with 'mcp_') and
auto-registers MCP servers in the PostgreSQL `mcp_servers` table.

This bridges the gap between the agent simulator's MCP tool calls and
the MCP Supply Chain inventory.

Server derivation:
    tool_name "mcp_filesystem_read"  → server_id "mcp_filesystem"
    tool_name "mcp_github_create_issue" → server_id "mcp_github"
    tool_name "mcp_slack_post_message"  → server_id "mcp_slack"
    tool_name "mcp_browser_navigate"    → server_id "mcp_browser"
    tool_name "mcp_memory_store"        → server_id "mcp_memory"

Uses ON CONFLICT (tenant_id, server_id) DO UPDATE for upsert semantics:
    - connection_count incremented
    - last_seen updated
    - updated_at updated

Batch: 500 events or 2s flush (same cadence as PG writer).
Consumer group: mcp-registrar
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.consumers.base_consumer import BaseStorageConsumer

logger = structlog.get_logger("phantex.consumer.mcp_registrar")

# Known MCP server display names
_MCP_SERVER_NAMES: dict[str, str] = {
    "mcp_filesystem": "Filesystem MCP Server",
    "mcp_github": "GitHub MCP Server",
    "mcp_slack": "Slack MCP Server",
    "mcp_browser": "Browser MCP Server",
    "mcp_memory": "Memory MCP Server",
    "mcp_code_exec": "Code Execution MCP Server",
}

def _derive_server_id(tool_name: str) -> str | None:
    """Derive the MCP server_id from a tool_name.

    Strategy: match against known server prefixes from longest to shortest,
    falling back to ``mcp_{second_segment}`` for unknown servers.

        mcp_filesystem_read     → mcp_filesystem
        mcp_github_create_issue → mcp_github
        mcp_slack_post_message  → mcp_slack
        mcp_browser_navigate    → mcp_browser
        mcp_memory_store        → mcp_memory
        mcp_code_exec_write     → mcp_code_exec   (compound name!)
    """
    if not tool_name or not tool_name.startswith("mcp_"):
        return None

    # Match known server prefixes (longest first to handle compound names)
    for prefix in sorted(_MCP_SERVER_NAMES.keys(), key=len, reverse=True):
        if tool_name == prefix or tool_name.startswith(prefix + "_"):
            return prefix

    # Fallback: mcp_{second_segment}
    parts = tool_name.split("_")
    if len(parts) < 3:
        return tool_name  # e.g., "mcp_tool" → "mcp_tool"

    return f"{parts[0]}_{parts[1]}"

class MCPRegistrarConsumer(BaseStorageConsumer):
    """Auto-register MCP servers from TOOL_CALL events."""

    def __init__(
        self,
        pool,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name="mcp-registrar",
            consumer_group="mcp-registrar",
            batch_size=500,
            flush_interval_seconds=2.0,
            **kwargs,
        )
        self._pool = pool

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Find MCP tool calls and upsert into mcp_servers."""
        if not events:
            return

        # Collect MCP server sightings: (tenant_id, server_id) → count
        sightings: dict[tuple[str, str], dict[str, Any]] = {}

        for e in events:
            event_type = e.get("event_type", "")
            if event_type != "TOOL_CALL":
                continue

            raw_data = e.get("raw_data") or {}
            tool_name = raw_data.get("tool_name") or e.get("tool_name", "")
            tool_category = raw_data.get("tool_category", "")

            # Only process MCP tools
            if tool_category != "mcp_tool" and not tool_name.startswith("mcp_"):
                continue

            tenant_id = e.get("tenant_id")
            if not tenant_id:
                continue

            server_id = _derive_server_id(tool_name)
            if not server_id:
                continue

            key = (tenant_id, server_id)
            if key not in sightings:
                sightings[key] = {
                    "tenant_id": tenant_id,
                    "server_id": server_id,
                    "name": _MCP_SERVER_NAMES.get(server_id, f"{server_id.replace('_', ' ').title()} Server"),
                    "count": 0,
                    "tools": set(),
                    "last_seen": e.get("timestamp", datetime.now(UTC).isoformat()),
                    "severity": e.get("severity", "info"),
                }
            sightings[key]["count"] += 1
            sightings[key]["tools"].add(tool_name)

        if not sightings:
            return

        # Upsert into mcp_servers
        async with self._pool.acquire() as conn:
            for (_tenant_id, _server_id), info in sightings.items():
                try:
                    # Convert tools set to list for JSONB
                    capabilities = list(info["tools"])
                    metadata = {
                        "auto_registered": True,
                        "source": "event_stream",
                        "tools": capabilities,
                    }

                    await conn.execute(
                        """
                        INSERT INTO mcp_servers (
                            tenant_id, server_id, name,
                            trust_level, risk_score, risk_level,
                            capabilities, metadata,
                            connection_count, last_seen,
                            first_seen, created_at, updated_at
                        ) VALUES (
                            $1::uuid, $2, $3,
                            'unknown', 0.0, 'minimal',
                            $4::jsonb, $5::jsonb,
                            $6, NOW(),
                            NOW(), NOW(), NOW()
                        )
                        ON CONFLICT (tenant_id, server_id) DO UPDATE SET
                            connection_count = mcp_servers.connection_count + $6,
                            last_seen = NOW(),
                            updated_at = NOW(),
                            capabilities = $4::jsonb,
                            metadata = mcp_servers.metadata || $5::jsonb
                        """,
                        info["tenant_id"],
                        info["server_id"],
                        info["name"],
                        __import__("json").dumps(capabilities),
                        __import__("json").dumps(metadata),
                        info["count"],
                    )
                except Exception as e:
                    logger.warning(
                        "mcp_registrar_upsert_error",
                        server_id=info["server_id"],
                        tenant_id=info["tenant_id"],
                        error=str(e),
                    )

        logger.debug(
            "mcp_registrar_batch",
            servers_upserted=len(sightings),
            total_events=len(events),
        )
