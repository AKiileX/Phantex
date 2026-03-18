# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Base Kafka Consumer.

Shared async Kafka consumer logic: connection setup, offset commit,
error handling, dead-letter queue routing, and graceful shutdown.

Supports dual-format deserialization: protobuf (from Go gateway) and JSON
(from Python simulator / SDK).  Tries protobuf first, falls back to JSON.

Subclasses implement `process_batch(events)` to write to their target store.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
import uuid as _uuid
from abc import ABC, abstractmethod
from typing import Any

import structlog

logger = structlog.get_logger("phantex.consumer")

# ---------------------------------------------------------------------------
# Protobuf deserialization (lazy-loaded — grpcio/protobuf may not be installed)
# ---------------------------------------------------------------------------
_proto_available = False
_PhantexEvent = None

try:
    import sys
    from pathlib import Path as _Path

    _this = _Path(__file__).resolve()
    _backend_root = str(_this.parents[2])  # /app or .../backend
    _project_root = str(_this.parents[3])  # / or .../PHANTEX
    for _p in [_backend_root, _project_root]:
        if _p not in sys.path:
            sys.path.insert(0, _p)
    for _pg in [
        _Path(_backend_root, "proto", "gen"),
        _Path(_project_root, "proto", "gen"),
    ]:
        if _pg.exists() and str(_pg) not in sys.path:
            sys.path.insert(0, str(_pg))

    from proto.gen.phantex.v1 import events_pb2  # type: ignore[import-untyped]

    _PhantexEvent = events_pb2.PhantexEvent
    _proto_available = True
    logger.info("consumer_proto_available", msg="Protobuf deserialization enabled")
except Exception:
    logger.info("consumer_proto_unavailable", msg="Protobuf stubs not found — JSON-only mode")

# Topic pattern: phantex.events.{tenant_id}
_TOPIC_TENANT_RE = re.compile(r"^phantex\.events\.(.+)$")

# Maximum raw Kafka message size accepted (1 MB).  Messages larger than
# this are discarded to prevent OOM from oversized payloads.
MAX_MESSAGE_BYTES = 1_048_576

# Event type enum → string mapping for protobuf messages
_EVENT_TYPE_MAP: dict[int, str] = {
    0: "UNSPECIFIED",
    1: "PROCESS_EXEC",
    2: "PROCESS_EXIT",
    10: "FILE_OPEN",
    11: "FILE_WRITE",
    12: "FILE_READ",
    20: "NETWORK_CONNECT",
    21: "NETWORK_ACCEPT",
    22: "NETWORK_DNS",
    30: "MEMORY_MMAP",
    40: "AGENT_DISCOVERED",
    41: "AGENT_TERMINATED",
    50: "TOOL_CALL",
    51: "TOOL_RESPONSE",
    60: "ALERT_FIRED",
}

_SEVERITY_MAP: dict[int, str] = {
    0: "UNSPECIFIED",
    1: "INFO",
    2: "LOW",
    3: "MEDIUM",
    4: "HIGH",
    5: "CRITICAL",
}

def _protobuf_to_dict(raw: bytes) -> dict[str, Any] | None:
    """Try to deserialize raw bytes as a PhantexEvent protobuf.

    Returns a JSON-compatible dict on success, None on failure.
    """
    if not _proto_available or _PhantexEvent is None:
        return None
    try:
        evt = _PhantexEvent()
        evt.ParseFromString(raw)
        # Sanity check — valid protobuf must have an event_id
        if not evt.event_id:
            return None

        result: dict[str, Any] = {
            "event_id": evt.event_id,
            "tenant_id": evt.tenant_id,
            "agent_id": evt.agent_id,
            "sensor_id": evt.sensor_id,
            "event_type": _EVENT_TYPE_MAP.get(evt.event_type, str(evt.event_type)),
            "severity": _SEVERITY_MAP.get(evt.severity, str(evt.severity)),
        }

        # Timestamp
        if evt.HasField("timestamp"):
            result["timestamp"] = evt.timestamp.ToJsonString()

        # Extract payload fields based on which oneof is set
        payload_field = evt.WhichOneof("payload")
        if payload_field:
            payload_msg = getattr(evt, payload_field)
            # Convert payload to dict — use protobuf's MessageToDict if available
            try:
                from google.protobuf.json_format import MessageToDict  # type: ignore

                payload_dict = MessageToDict(payload_msg, preserving_proto_field_name=True)
                result["raw_data"] = {payload_field: payload_dict}
            except ImportError:
                result["raw_data"] = {"payload_type": payload_field}

        return result
    except Exception:
        return None

class BaseStorageConsumer(ABC):
    """
    Async Kafka consumer with batched writes and dead-letter queue.

    Subclasses implement:
        - `process_batch(events)` -> None
        - `flush()` -> None (optional, for final buffer flush on shutdown)
    """

    def __init__(
        self,
        *,
        name: str,
        bootstrap_servers: str = "localhost:9092",
        consumer_group: str,
        topic_pattern: str = r"^phantex\.events\..+$",
        batch_size: int = 500,
        flush_interval_seconds: float = 2.0,
        max_retries: int = 3,
        dlq_topic: str = "phantex.dlq",
        ssl_context: Any | None = None,
    ) -> None:
        self.name = name
        self._bootstrap = bootstrap_servers
        self._consumer_group = consumer_group
        self._topic_pattern = topic_pattern
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._max_retries = max_retries
        self._dlq_topic = dlq_topic
        self._ssl_context = ssl_context

        self._consumer = None
        self._producer = None  # For DLQ writes
        self._running = False
        self._task: asyncio.Task | None = None
        self._buffer: list[dict[str, Any]] = []
        self._last_flush = time.monotonic()

        # Metrics
        self.events_consumed: int = 0
        self.events_written: int = 0
        self.events_dlq: int = 0
        self.batches_written: int = 0
        self.deserialization_errors: int = 0
        self.events_protobuf: int = 0  # successfully decoded from protobuf
        self.events_json: int = 0  # successfully decoded from JSON

    async def start(self) -> None:
        """Start the consumer loop as an asyncio task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume_loop(), name=f"consumer-{self.name}")
        logger.info(
            "consumer_starting",
            name=self.name,
            group=self._consumer_group,
            bootstrap=self._bootstrap,
            batch_size=self._batch_size,
            flush_interval=self._flush_interval,
        )

    async def stop(self) -> None:
        """Stop the consumer, flush remaining buffer, and close connections."""
        self._running = False

        # Flush any remaining events in buffer
        if self._buffer:
            try:
                await self._flush_buffer()
            except Exception as e:
                logger.error("consumer_final_flush_error", name=self.name, error=str(e))

        if self._consumer:
            try:
                await self._consumer.stop()
            except Exception as e:
                logger.warning("consumer_stop_error", name=self.name, error=str(e))

        if self._producer:
            try:
                await self._producer.stop()
            except Exception as e:
                logger.warning("producer_stop_error", name=self.name, error=str(e))

        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        logger.info(
            "consumer_stopped",
            name=self.name,
            events_consumed=self.events_consumed,
            events_written=self.events_written,
            events_dlq=self.events_dlq,
            batches_written=self.batches_written,
        )

    async def _consume_loop(self) -> None:
        """Main loop with automatic retry on Kafka connection failure."""
        while self._running:
            try:
                await self._run_consumer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(
                    "consumer_loop_error",
                    name=self.name,
                    error=str(e),
                    msg="Reconnecting in 5s",
                )
                await asyncio.sleep(5)

    async def _run_consumer(self) -> None:
        """Create consumer and read messages."""
        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        except ImportError:
            logger.error("aiokafka_not_installed", msg="pip install aiokafka")
            self._running = False
            return

        consumer_kwargs = dict(
            bootstrap_servers=self._bootstrap,
            group_id=self._consumer_group,
            auto_offset_reset="earliest",  # At-least-once: start from beginning if no offset
            enable_auto_commit=False,  # Manual commit after successful write
            value_deserializer=lambda x: x,  # Raw bytes — we deserialize manually
            max_poll_records=self._batch_size,
        )
        if self._ssl_context:
            consumer_kwargs["security_protocol"] = "SSL"
            consumer_kwargs["ssl_context"] = self._ssl_context

        self._consumer = AIOKafkaConsumer(**consumer_kwargs)
        await self._consumer.start()

        # Subscribe to topics matching pattern
        self._consumer.subscribe(pattern=self._topic_pattern)

        # DLQ producer
        producer_kwargs = dict(
            bootstrap_servers=self._bootstrap,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        if self._ssl_context:
            producer_kwargs["security_protocol"] = "SSL"
            producer_kwargs["ssl_context"] = self._ssl_context

        self._producer = AIOKafkaProducer(**producer_kwargs)
        await self._producer.start()

        logger.info("consumer_connected", name=self.name, group=self._consumer_group)

        try:
            async for msg in self._consumer:
                if not self._running:
                    break

                self.events_consumed += 1

                # F6: Guard against oversized messages to prevent OOM
                if msg.value is not None and len(msg.value) > MAX_MESSAGE_BYTES:
                    self.deserialization_errors += 1
                    logger.warning(
                        "consumer_msg_too_large",
                        name=self.name,
                        offset=msg.offset,
                        topic=msg.topic,
                        size=len(msg.value),
                        max_size=MAX_MESSAGE_BYTES,
                    )
                    continue

                # Deserialize — try protobuf first (gateway), JSON fallback (simulator)
                event: dict[str, Any] | None = None

                # Strategy: if the first byte is '{' it's almost certainly JSON.
                # Otherwise try protobuf first, then JSON as fallback.
                raw = msg.value
                if raw and raw[0:1] == b"{":
                    # Fast-path: JSON (most simulator messages)
                    try:
                        event = json.loads(raw)
                        self.events_json += 1
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass

                if event is None and raw:
                    # Try protobuf (gateway binary messages)
                    event = _protobuf_to_dict(raw)
                    if event is not None:
                        self.events_protobuf += 1

                if event is None and raw:
                    # Final fallback: try JSON anyway (handles edge cases)
                    try:
                        event = json.loads(raw)
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        self.deserialization_errors += 1
                        logger.warning(
                            "consumer_deser_error",
                            name=self.name,
                            offset=msg.offset,
                            topic=msg.topic,
                            error=str(e),
                            first_bytes=raw[:20].hex() if raw else "",
                        )
                        continue

                # Extract tenant from topic name and validate as UUID
                m = _TOPIC_TENANT_RE.match(msg.topic)
                if m:
                    raw_tenant = m.group(1)
                    try:
                        validated_tenant = str(_uuid.UUID(raw_tenant))
                    except (ValueError, AttributeError):
                        self.deserialization_errors += 1
                        logger.warning(
                            "consumer_invalid_tenant_id",
                            name=self.name,
                            topic=msg.topic,
                            raw_tenant=raw_tenant[:80],
                        )
                        continue
                    event.setdefault("tenant_id", validated_tenant)

                self._buffer.append(event)

                # Flush when batch is full or interval elapsed
                now = time.monotonic()
                if len(self._buffer) >= self._batch_size or (now - self._last_flush) >= self._flush_interval:
                    await self._flush_buffer()
                    # Commit offset only after successful write
                    await self._consumer.commit()

        finally:
            await self._consumer.stop()
            await self._producer.stop()
            self._consumer = None
            self._producer = None

    async def _flush_buffer(self) -> None:
        """Process the buffered events, retry on failure, DLQ on exhaustion."""
        if not self._buffer:
            return

        batch = self._buffer[:]
        self._buffer.clear()
        self._last_flush = time.monotonic()

        for attempt in range(1, self._max_retries + 1):
            try:
                await self.process_batch(batch)
                self.events_written += len(batch)
                self.batches_written += 1
                return
            except Exception as e:
                logger.warning(
                    "consumer_batch_error",
                    name=self.name,
                    attempt=attempt,
                    max_retries=self._max_retries,
                    batch_size=len(batch),
                    error=str(e),
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(min(2**attempt, 30))

        # All retries exhausted — send to DLQ
        await self._send_to_dlq(batch)

    async def _send_to_dlq(self, events: list[dict]) -> None:
        """Send failed events to the dead-letter queue topic."""
        for event in events:
            try:
                if self._producer:
                    dlq_msg = {
                        "consumer": self.name,
                        "error": "max_retries_exhausted",
                        "event": event,
                    }
                    await self._producer.send_and_wait(self._dlq_topic, value=dlq_msg)
                    self.events_dlq += 1
            except Exception as e:
                logger.error(
                    "dlq_send_error",
                    name=self.name,
                    error=str(e),
                )

    @abstractmethod
    async def process_batch(self, events: list[dict[str, Any]]) -> None:
        """Write a batch of events to the target storage.

        Must raise on failure (triggers retry). Must be idempotent.
        """
        ...

    async def flush(self) -> None:
        """Optional hook for subclasses to flush internal buffers on shutdown."""
        pass
