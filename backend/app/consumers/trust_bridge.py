# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Trust Engine Bridge Consumer.

Kafka consumer that forwards events to the Rust trust engine via gRPC,
populating the in-memory trust graph with Agent → Tool / NetworkDest / Resource
edges. This is the missing link between the data pipeline and the trust graph.

Pipeline:
    Simulator → Kafka → [PG Writer, CH Writer, Neo4j Writer, **Trust Bridge**]
                                                              ↓
                                                    Rust Trust Engine (gRPC)
                                                              ↓
                                                    In-memory trust graph
                                                              ↓
                                              GET /api/v1/trust-graph → Dashboard

Event mapping:
    TOOL_CALL        → source=agent (Agent), target=tool_name (Tool)
    NETWORK_CONNECT  → source=agent (Agent), target=dest_ip   (NetworkDest)
    FILE_READ/OPEN   → source=agent (Agent), target=file_path (Resource)
    PROCESS_EXEC     → source=agent (Agent), target=comm      (Resource)
    NETWORK_DNS      → source=agent (Agent), target=dns_name  (NetworkDest)

Batch: 200 events or 1s flush (fast — gRPC calls are lightweight).
Consumer group: trust-bridge (separate from storage writers so all events are seen).
"""

from __future__ import annotations

from typing import Any

import structlog

from app.consumers.base_consumer import BaseStorageConsumer

logger = structlog.get_logger("phantex.consumer.trust_bridge")

def _extract_edge(event: dict[str, Any]) -> tuple[str, str, str, str, str, str, int] | None:
    """Extract (source_id, source_type, target_id, target_type, event_type, severity, bytes) from event.

    Returns None if the event can't be mapped to a trust graph edge.
    """
    agent_id = event.get("agent_id")
    if not agent_id:
        return None

    event_type = event.get("event_type", "")
    severity = event.get("severity", "info")
    raw_data = event.get("raw_data") or {}

    if event_type == "TOOL_CALL":
        tool_name = raw_data.get("tool_name") or event.get("tool_name")
        if not tool_name:
            return None
        return (agent_id, "agent", tool_name, "tool", event_type, severity, 0)

    elif event_type == "NETWORK_CONNECT":
        network = raw_data.get("network") or {}
        dest_ip = network.get("dst_addr") or event.get("dest_ip")
        if not dest_ip:
            return None
        bytes_out = network.get("bytes_out", 0) or event.get("bytes_out", 0)
        return (agent_id, "agent", dest_ip, "network_dest", event_type, severity, int(bytes_out or 0))

    elif event_type in ("FILE_READ", "FILE_OPEN"):
        file_info = raw_data.get("file") or {}
        file_path = file_info.get("filename") or event.get("file_path")
        if not file_path:
            return None
        return (agent_id, "agent", file_path, "resource", event_type, severity, 0)

    elif event_type == "PROCESS_EXEC":
        proc = raw_data.get("process_exec") or {}
        comm = proc.get("comm") or ""
        if not comm:
            return None
        return (agent_id, "agent", comm, "resource", event_type, severity, 0)

    elif event_type == "NETWORK_DNS":
        dns = raw_data.get("dns") or {}
        query_name = dns.get("query_name")
        if not query_name:
            return None
        return (agent_id, "agent", query_name, "network_dest", event_type, severity, 0)

    return None

class TrustBridgeConsumer(BaseStorageConsumer):
    """Forward events to the Rust trust engine via gRPC."""

    def __init__(
        self,
        trust_client: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name="trust-bridge",
            consumer_group="trust-bridge",
            batch_size=200,
            flush_interval_seconds=1.0,
            **kwargs,
        )
        self._trust_client = trust_client

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Forward each event to the trust engine as a graph edge update."""
        if not events:
            return

        pushed = 0
        failed = 0
        skipped_grpc = 0

        for event in events:
            edge = _extract_edge(event)
            if edge is None:
                continue

            source_id, source_type, target_id, target_type, event_type, severity, bytes_count = edge

            # Extract tenant_id from the event
            tenant_id = event.get("tenant_id", "")

            try:
                src_score, tgt_score = await self._trust_client.update_event(
                    tenant_id=tenant_id,
                    source_id=source_id,
                    source_type=source_type,
                    target_id=target_id,
                    target_type=target_type,
                    event_type=event_type,
                    severity=severity,
                    bytes_count=bytes_count,
                )
                # Detect silent fallback: if both scores are exactly 0.5,
                # the trust client likely returned the neutral default
                # because gRPC is unavailable.
                if src_score == 0.5 and tgt_score == 0.5:
                    skipped_grpc += 1
                else:
                    pushed += 1
            except Exception as e:
                failed += 1
                if failed <= 3:
                    logger.warning(
                        "trust_bridge_event_error",
                        event_id=event.get("event_id"),
                        error=str(e),
                    )

        if pushed > 0 or failed > 0 or skipped_grpc > 0:
            logger.debug(
                "trust_bridge_batch",
                pushed=pushed,
                failed=failed,
                skipped_grpc=skipped_grpc,
                total=len(events),
            )
            if skipped_grpc > 0 and pushed == 0:
                logger.warning(
                    "trust_bridge_grpc_unavailable",
                    msg="All events returned neutral score — gRPC likely not connected",
                    skipped=skipped_grpc,
                )
