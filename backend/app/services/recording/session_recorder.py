# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Session Recorder.

Three-tier recording model per Phantex-draft.md Section 26:

  Level 1 (Audit Log)        — Always on. Metadata only (~100 bytes/event).
  Level 2 (Extended)         — Toggle. Adds full payloads + hashes (~500 bytes/event).
  Level 3 (Full DVR)         — Toggle. Adds LLM content + env snapshots (~2-5 KB/event).

Each tenant/agent can be configured independently. Higher tiers include all
fields from lower tiers.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

class RecordingLevel(IntEnum):
    """Recording depth tier. Higher includes all lower fields."""

    AUDIT = 1  # Always on — metadata only
    EXTENDED = 2  # Toggle — adds payloads + hashes
    FULL_DVR = 3  # Toggle — adds LLM content + env snapshots

@dataclass(frozen=True)
class RecordingConfig:
    """Per-agent or per-tenant recording configuration."""

    tenant_id: str
    agent_id: str | None = None  # None = tenant-wide default
    level: RecordingLevel = RecordingLevel.AUDIT
    enabled: bool = True

# ── Level 1 fields (always captured) ────────────────────────────────────

@dataclass
class AuditFields:
    """Level 1 — Metadata audit fields (~100 bytes/event)."""

    timestamp: str
    agent_id: str
    event_type: str  # tool_call, api_request, llm_invoke, etc.
    tool_name: str | None = None
    result: str = "success"  # success | blocked | error
    data_classification: str = "clean"  # clean | pii_detected | credentials_detected
    trust_score: float = 0.0
    rule_matched: str | None = None
    bytes_transferred: int = 0

# ── Level 2 fields (extended) ───────────────────────────────────────────

@dataclass
class ExtendedFields:
    """Level 2 — Full payloads + hashes (~500 bytes/event)."""

    tool_parameters: dict[str, Any] | None = None
    api_request_body: str | None = None
    api_response_body: str | None = None
    llm_prompt_hash: str | None = None
    inter_agent_metadata: dict[str, Any] | None = None
    env_key_hashes: dict[str, str] | None = None

# ── Level 3 fields (full DVR) ───────────────────────────────────────────

@dataclass
class DVRFields:
    """Level 3 — Full DVR content (~2-5 KB/event)."""

    llm_prompt_content: str | None = None
    llm_response_content: str | None = None
    rag_results: list[dict[str, Any]] | None = None
    system_prompt_snapshot: str | None = None
    environment_snapshot: dict[str, Any] | None = None
    timing_microseconds: int | None = None

# ── Composite recording event ───────────────────────────────────────────

@dataclass
class RecordingEvent:
    """A single recorded event with tier-appropriate fields."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    level: RecordingLevel = RecordingLevel.AUDIT
    tenant_id: str = ""

    # Level 1 — always present
    audit: AuditFields | None = None

    # Level 2 — present only when level >= EXTENDED
    extended: ExtendedFields | None = None

    # Level 3 — present only when level >= FULL_DVR
    dvr: DVRFields | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, omitting None tiers."""
        d: dict[str, Any] = {
            "id": self.id,
            "level": self.level.value,
            "tenant_id": self.tenant_id,
        }
        if self.audit:
            d["audit"] = asdict(self.audit)
        if self.extended:
            d["extended"] = asdict(self.extended)
        if self.dvr:
            d["dvr"] = asdict(self.dvr)
        return d

def _sha256(text: str) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

class SessionRecorder:
    """Three-tier session recorder.

    Records agent actions at the configured depth. Maintains per-tenant
    configuration and an in-memory event store (production: ClickHouse).
    """

    def __init__(self) -> None:
        self._configs: dict[str, RecordingConfig] = {}  # key = tenant_id or tenant_id:agent_id
        self._events: list[RecordingEvent] = []
        self._max_events = 200_000  # Memory guard — evict oldest beyond this

    # ── Configuration ────────────────────────────────────────────────

    def set_config(
        self,
        tenant_id: str,
        agent_id: str | None = None,
        level: RecordingLevel = RecordingLevel.AUDIT,
        *,
        enabled: bool = True,
    ) -> RecordingConfig:
        """Set recording level for a tenant or specific agent."""
        level = RecordingLevel(level)
        config = RecordingConfig(
            tenant_id=tenant_id,
            agent_id=agent_id,
            level=level,
            enabled=enabled,
        )
        key = f"{tenant_id}:{agent_id}" if agent_id else tenant_id
        self._configs[key] = config
        return config

    def get_config(self, tenant_id: str, agent_id: str | None = None) -> RecordingConfig:
        """Get recording config. Agent-level overrides tenant-level."""
        if agent_id:
            key = f"{tenant_id}:{agent_id}"
            if key in self._configs:
                return self._configs[key]
        return self._configs.get(tenant_id, RecordingConfig(tenant_id=tenant_id))

    def get_configs(self, tenant_id: str) -> list[RecordingConfig]:
        """Get all recording configs for a tenant."""
        return [c for c in self._configs.values() if c.tenant_id == tenant_id]

    # ── Recording ────────────────────────────────────────────────────

    def record(
        self,
        tenant_id: str,
        agent_id: str,
        event_type: str,
        *,
        tool_name: str | None = None,
        result: str = "success",
        data_classification: str = "clean",
        trust_score: float = 0.0,
        rule_matched: str | None = None,
        bytes_transferred: int = 0,
        # Level 2 fields
        tool_parameters: dict[str, Any] | None = None,
        api_request_body: str | None = None,
        api_response_body: str | None = None,
        llm_prompt: str | None = None,
        inter_agent_metadata: dict[str, Any] | None = None,
        env_keys: dict[str, str] | None = None,
        # Level 3 fields
        llm_prompt_content: str | None = None,
        llm_response_content: str | None = None,
        rag_results: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
        environment_snapshot: dict[str, Any] | None = None,
        timing_microseconds: int | None = None,
    ) -> RecordingEvent:
        """Record an agent action at the configured depth.

        Fields beyond the configured level are silently dropped.
        """
        config = self.get_config(tenant_id, agent_id)

        if not config.enabled:
            # Return a minimal event even when disabled — caller expects an event back
            return RecordingEvent(tenant_id=tenant_id, level=RecordingLevel.AUDIT)

        level = config.level

        # Level 1 — always captured
        audit = AuditFields(
            timestamp=datetime.now(UTC).isoformat(),
            agent_id=agent_id,
            event_type=event_type,
            tool_name=tool_name,
            result=result,
            data_classification=data_classification,
            trust_score=trust_score,
            rule_matched=rule_matched,
            bytes_transferred=bytes_transferred,
        )

        # Level 2 — extended payloads + hashes
        extended = None
        if level >= RecordingLevel.EXTENDED:
            extended = ExtendedFields(
                tool_parameters=tool_parameters,
                api_request_body=api_request_body,
                api_response_body=api_response_body,
                llm_prompt_hash=_sha256(llm_prompt) if llm_prompt else None,
                inter_agent_metadata=inter_agent_metadata,
                env_key_hashes={k: _sha256(v) for k, v in env_keys.items()} if env_keys else None,
            )

        # Level 3 — full DVR content
        dvr = None
        if level >= RecordingLevel.FULL_DVR:
            dvr = DVRFields(
                llm_prompt_content=llm_prompt_content,
                llm_response_content=llm_response_content,
                rag_results=rag_results,
                system_prompt_snapshot=system_prompt,
                environment_snapshot=environment_snapshot,
                timing_microseconds=timing_microseconds,
            )

        event = RecordingEvent(
            level=level,
            tenant_id=tenant_id,
            audit=audit,
            extended=extended,
            dvr=dvr,
        )
        self._events.append(event)

        # Memory guard — evict oldest events beyond cap
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events :]

        return event

    # ── Querying ─────────────────────────────────────────────────────

    def get_events(
        self,
        tenant_id: str,
        *,
        agent_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[RecordingEvent]:
        """Query recorded events for a tenant, with optional filters."""
        results = [e for e in self._events if e.tenant_id == tenant_id]
        if agent_id and results:
            results = [e for e in results if e.audit and e.audit.agent_id == agent_id]
        if event_type and results:
            results = [e for e in results if e.audit and e.audit.event_type == event_type]
        return results[-limit:]

    def get_session_timeline(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Build a timeline of events for a specific agent session."""
        events = self.get_events(tenant_id, agent_id=agent_id, limit=limit)
        return [e.to_dict() for e in events]

    def stats(self, tenant_id: str) -> dict[str, Any]:
        """Aggregate recording stats for a tenant."""
        events = [e for e in self._events if e.tenant_id == tenant_id]
        level_counts = {1: 0, 2: 0, 3: 0}
        for e in events:
            level_counts[e.level] = level_counts.get(e.level, 0) + 1
        return {
            "total_events": len(events),
            "by_level": level_counts,
            "configs": len(self.get_configs(tenant_id)),
        }
