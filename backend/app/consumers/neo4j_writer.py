# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Neo4j Graph Writer.

Kafka consumer that transforms events into graph nodes + relationships
in Neo4j. Uses MERGE for idempotent writes.

Batch: 1000 events or 5s flush interval.
Consumer group: storage-writer-neo4j
"""

from __future__ import annotations

from typing import Any

import structlog

from app.consumers.base_consumer import BaseStorageConsumer
from app.services.graph_service import write_event_to_graph

logger = structlog.get_logger("phantex.consumer.neo4j")

class Neo4jWriter(BaseStorageConsumer):
    """Transform events into graph nodes/relationships in Neo4j."""

    def __init__(
        self,
        driver,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            name="neo4j-writer",
            consumer_group="storage-writer-neo4j",
            batch_size=1000,
            flush_interval_seconds=5.0,
            **kwargs,
        )
        self._driver = driver

    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Write events as graph nodes + relationships.

        Uses the graph_service.write_event_to_graph function which
        issues MERGE queries for idempotency.

        Individual event failures are isolated: only the failing events
        are skipped (and logged). If ALL events in the batch fail the
        exception is re-raised so the base consumer can retry / DLQ.
        """
        if not events:
            return

        failed: list[dict] = []
        for event in events:
            try:
                await write_event_to_graph(self._driver, event)
            except Exception as e:
                logger.warning(
                    "neo4j_event_write_error",
                    event_id=event.get("event_id"),
                    error=str(e),
                )
                failed.append(event)

        if failed and len(failed) == len(events):
            # Every single event failed — re-raise to trigger batch retry / DLQ
            raise RuntimeError(f"All {len(events)} events failed to write to Neo4j")

        if failed:
            logger.warning(
                "neo4j_partial_batch_failure",
                total=len(events),
                failed=len(failed),
                failed_ids=[e.get("event_id") for e in failed[:10]],
            )

        logger.debug(
            "neo4j_batch_written",
            count=len(events) - len(failed),
        )
