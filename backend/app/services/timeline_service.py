# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Investigation Timeline Service (L1).

Assembles forensic event timelines from multiple data sources:
  - PostgreSQL: alerts, agent metadata
  - ClickHouse: full event history
  - Neo4j: relationship context (tools, files, network destinations)
  - Trust Engine: trust score enrichment

Graceful degradation: if a data source is unavailable, the timeline
returns partial data with a ``data_sources`` status field indicating
which sources contributed and which failed.

All queries are tenant-scoped.  All SQL/Cypher is parameterised.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.schemas.timeline import (
    DataSourceStatus,
    TimelineEvent,
    TimelineResponse,
    TimelineSession,
)
from app.services import mitre_service
from app.utils.logging import get_logger

logger = get_logger("phantex.timeline")

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_RANGE_HOURS = 72  # Cap query range to prevent full-history scraping
MAX_EVENTS_PER_PAGE = 500
SESSION_GAP_SECONDS = 300  # 5 minutes — events within this gap belong to the same session

_RANGE_MAP: dict[str, float] = {
    "1h": 1,
    "6h": 6,
    "12h": 12,
    "24h": 24,
    "48h": 48,
    "72h": 72,
}

def _parse_range(range_str: str) -> float:
    """Parse a range string to hours (capped at 72h)."""
    hours = _RANGE_MAP.get(range_str)
    if hours is None:
        try:
            hours = float(range_str.rstrip("h"))
        except (ValueError, AttributeError):
            hours = 24.0
    return min(hours, MAX_RANGE_HOURS)

def _generate_session_id(agent_id: str, start_ts: datetime) -> str:
    """Deterministic session ID from agent + start timestamp."""
    raw = f"{agent_id}:{start_ts.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

# ── ClickHouse Events ─────────────────────────────────────────────────────────

async def _fetch_clickhouse_events(
    ch_client: Any | None,
    tenant_id: uuid.UUID,
    *,
    agent_id: str | None = None,
    since: datetime,
    until: datetime | None = None,
    limit: int = MAX_EVENTS_PER_PAGE,
    cursor: str | None = None,
) -> tuple[list[TimelineEvent], DataSourceStatus]:
    """Fetch raw events from ClickHouse."""
    status = DataSourceStatus(source="clickhouse", available=False, event_count=0)
    events: list[TimelineEvent] = []

    if ch_client is None:
        status.error = "ClickHouse not configured"
        return events, status

    t0 = time.monotonic()
    try:
        query = """
            SELECT
                toString(event_id) AS id,
                event_type,
                severity,
                timestamp,
                toString(agent_id) AS agent_id,
                toString(tenant_id) AS tid
            FROM phantex.events
            WHERE tenant_id = {tid:UUID}
              AND timestamp >= {since:DateTime64(3)}
        """
        params: dict[str, Any] = {
            "tid": str(tenant_id),
            "since": since,
        }

        if until is not None:
            query += " AND timestamp <= {until:DateTime64(3)}"
            params["until"] = until

        if agent_id is not None:
            query += " AND agent_id = {agent_id:String}"
            params["agent_id"] = str(agent_id)

        if cursor:
            try:
                cursor_dt = datetime.fromisoformat(cursor)
            except (ValueError, TypeError):
                logger.warning("clickhouse_invalid_cursor", cursor=cursor[:64])
                cursor = None  # ignore bad cursor rather than 500
            else:
                query += " AND timestamp > {cursor_ts:DateTime64(3)}"
                params["cursor_ts"] = cursor_dt

        capped_limit = min(limit, MAX_EVENTS_PER_PAGE)
        query += " ORDER BY timestamp ASC LIMIT {lim:UInt32}"
        params["lim"] = capped_limit

        result = await ch_client.query(query, parameters=params)
        rows = result.result_rows if result else []

        for row in rows:
            events.append(
                TimelineEvent(
                    id=row[0],
                    source="clickhouse",
                    event_type=row[1],
                    severity=row[2] or "info",
                    timestamp=row[3],
                    agent_id=row[4],
                    description=f"{row[1]} event",
                )
            )

        status.available = True
        status.event_count = len(events)
        status.latency_ms = round((time.monotonic() - t0) * 1000, 1)
    except Exception as exc:
        status.error = str(exc)[:200]
        logger.warning("clickhouse_timeline_error", error=str(exc))

    return events, status

# ── PostgreSQL Alerts ─────────────────────────────────────────────────────────

async def _fetch_pg_alerts(
    session: Any | None,
    tenant_id: uuid.UUID,
    *,
    agent_id: str | None = None,
    alert_id: uuid.UUID | None = None,
    since: datetime,
    until: datetime | None = None,
    limit: int = MAX_EVENTS_PER_PAGE,
) -> tuple[list[TimelineEvent], DataSourceStatus]:
    """Fetch alerts from PostgreSQL as timeline events."""
    from sqlalchemy import text

    status = DataSourceStatus(source="postgres", available=False, event_count=0)
    events: list[TimelineEvent] = []

    if session is None:
        status.error = "PostgreSQL session not available"
        return events, status

    t0 = time.monotonic()
    try:
        query_parts = [
            "SELECT id, severity, title, description, status, context, created_at, "
            "agent_id, rule_id, event_id "
            "FROM alerts WHERE tenant_id = :tid AND created_at >= :since"
        ]
        params: dict[str, Any] = {"tid": str(tenant_id), "since": since}

        if until is not None:
            query_parts.append("AND created_at <= :until")
            params["until"] = until

        if agent_id is not None:
            query_parts.append("AND agent_id = :agent_id")
            params["agent_id"] = str(agent_id)

        if alert_id is not None:
            query_parts.append("AND id = :alert_id")
            params["alert_id"] = str(alert_id)

        capped_limit = min(limit, MAX_EVENTS_PER_PAGE)
        query_parts.append("ORDER BY created_at ASC LIMIT :lim")
        params["lim"] = capped_limit

        result = await session.execute(text(" ".join(query_parts)), params)
        rows = result.fetchall()

        for row in rows:
            context = row[5] if isinstance(row[5], dict) else {}
            # Enrich with ATLAS techniques from context
            rule_name = context.get("rule_name")
            attack_class = context.get("attack_class")
            enriched_context = mitre_service.enrich_alert_context(
                context,
                rule_name=rule_name,
                attack_class=attack_class,
            )
            atlas_techniques = enriched_context.get("atlas_techniques", [])

            events.append(
                TimelineEvent(
                    id=str(row[0]),
                    source="postgres",
                    event_type=f"alert:{row[4]}",  # alert:open, alert:resolved, etc.
                    severity=row[1],
                    timestamp=row[6],
                    agent_id=str(row[7]) if row[7] else None,
                    description=row[2] or "",
                    raw_data={
                        "title": row[2],
                        "description": row[3],
                        "status": row[4],
                        "rule_id": str(row[8]) if row[8] else None,
                        "event_id": str(row[9]) if row[9] else None,
                    },
                    atlas_techniques=atlas_techniques,
                )
            )

        status.available = True
        status.event_count = len(events)
        status.latency_ms = round((time.monotonic() - t0) * 1000, 1)
    except Exception as exc:
        status.error = str(exc)[:200]
        logger.warning("pg_timeline_error", error=str(exc))

    return events, status

# ── Neo4j Relationship Context ────────────────────────────────────────────────

async def _fetch_neo4j_context(
    neo4j_driver: Any | None,
    tenant_id: uuid.UUID,
    *,
    agent_id: str | None = None,
    alert_id: uuid.UUID | None = None,
    since: datetime,
    limit: int = 200,
) -> tuple[list[TimelineEvent], DataSourceStatus]:
    """Fetch relationship events from Neo4j (tools called, files accessed, etc.)."""
    status = DataSourceStatus(source="neo4j", available=False, event_count=0)
    events: list[TimelineEvent] = []

    if neo4j_driver is None:
        status.error = "Neo4j not configured"
        return events, status

    t0 = time.monotonic()
    try:
        async with neo4j_driver.session() as session:
            # Get events connected to agent or alert
            if alert_id is not None:
                result = await session.run(
                    """
                    MATCH (alert:Alert {alert_id: $alert_id, tenant_id: $tid})
                    OPTIONAL MATCH (alert)<-[:TRIGGERED]-(evt:Event {tenant_id: $tid})
                    OPTIONAL MATCH (evt)-[r]->(target)
                    WHERE target.tenant_id = $tid OR NOT exists(target.tenant_id)
                    RETURN
                        evt.event_id AS event_id,
                        type(r) AS rel_type,
                        labels(target) AS target_labels,
                        properties(target) AS target_props,
                        evt.timestamp AS ts
                    ORDER BY evt.timestamp
                    LIMIT $limit
                    """,
                    alert_id=str(alert_id),
                    tid=str(tenant_id),
                    limit=min(limit, 200),
                )
            elif agent_id is not None:
                result = await session.run(
                    """
                    MATCH (agent:Agent {paid: $agent_id, tenant_id: $tid})
                    OPTIONAL MATCH (agent)-[:PERFORMED]->(evt:Event {tenant_id: $tid})
                    WHERE evt.timestamp >= $since
                    OPTIONAL MATCH (evt)-[r]->(target)
                    WHERE target.tenant_id = $tid OR NOT exists(target.tenant_id)
                    RETURN
                        evt.event_id AS event_id,
                        type(r) AS rel_type,
                        labels(target) AS target_labels,
                        properties(target) AS target_props,
                        evt.timestamp AS ts
                    ORDER BY evt.timestamp
                    LIMIT $limit
                    """,
                    agent_id=str(agent_id),
                    tid=str(tenant_id),
                    since=since.isoformat(),
                    limit=min(limit, 200),
                )
            else:
                status.available = True
                return events, status

            records = [record async for record in result]

            for record in records:
                if record.get("event_id") is None:
                    continue
                rel_type = record.get("rel_type", "UNKNOWN")
                target_labels = record.get("target_labels", [])
                target_props = record.get("target_props", {})
                ts = record.get("ts")

                # Build description from relationship
                target_type = target_labels[0] if target_labels else "unknown"
                target_name = (
                    target_props.get("name")
                    or target_props.get("path")
                    or target_props.get("ip")
                    or target_props.get("url")
                    or str(target_props.get("id", ""))[:64]
                )
                description = f"{rel_type} → {target_type}"
                if target_name:
                    description += f": {target_name}"

                events.append(
                    TimelineEvent(
                        id=f"neo4j:{record['event_id']}:{rel_type}",
                        source="neo4j",
                        event_type=f"relationship:{rel_type.lower()}",
                        severity="info",
                        timestamp=datetime.fromisoformat(ts) if isinstance(ts, str) else (ts if ts else since),
                        description=description,
                        raw_data={
                            "relationship": rel_type,
                            "target_type": target_type,
                            "target_name": target_name,
                        },
                    )
                )

        status.available = True
        status.event_count = len(events)
        status.latency_ms = round((time.monotonic() - t0) * 1000, 1)
    except Exception as exc:
        status.error = str(exc)[:200]
        logger.warning("neo4j_timeline_error", error=str(exc))

    return events, status

# ── Trust Score Enrichment ────────────────────────────────────────────────────

async def _enrich_trust_scores(
    events: list[TimelineEvent],
    trust_client: Any | None,
    tenant_id: uuid.UUID,
) -> DataSourceStatus:
    """Annotate events with trust scores from the Rust trust engine."""
    status = DataSourceStatus(source="trust_engine", available=False, event_count=0)

    if trust_client is None:
        status.error = "Trust engine client not available"
        return status

    t0 = time.monotonic()
    try:
        # Collect unique agent IDs that need trust scores
        agent_ids: set[str] = set()
        for evt in events:
            if evt.agent_id:
                agent_ids.add(evt.agent_id)

        # Batch query trust scores (one per unique agent)
        scores: dict[str, float] = {}
        for aid in agent_ids:
            try:
                result = await trust_client.get_trust_score(
                    entity_id=aid,
                    entity_type="agent",
                    tenant_id=str(tenant_id),
                )
                scores[aid] = result.trust_score
                status.event_count += 1
            except Exception:
                scores[aid] = 0.5  # neutral fallback

        # Apply scores to events
        for evt in events:
            if evt.agent_id and evt.agent_id in scores:
                evt.trust_score = scores[evt.agent_id]

        status.available = True
        status.latency_ms = round((time.monotonic() - t0) * 1000, 1)
    except Exception as exc:
        status.error = str(exc)[:200]
        logger.warning("trust_enrichment_error", error=str(exc))

    return status

# ── Session Grouping ──────────────────────────────────────────────────────────

def _group_into_sessions(events: list[TimelineEvent]) -> list[TimelineSession]:
    """Group consecutive events into sessions (< 5 min gap)."""
    if not events:
        return []

    sessions: list[TimelineSession] = []
    current_events: list[TimelineEvent] = [events[0]]

    for evt in events[1:]:
        prev_ts = current_events[-1].timestamp
        gap = (evt.timestamp - prev_ts).total_seconds()
        if gap > SESSION_GAP_SECONDS:
            # Close current session, start new one
            sessions.append(_make_session(current_events))
            current_events = [evt]
        else:
            current_events.append(evt)

    # Close last session
    if current_events:
        sessions.append(_make_session(current_events))

    return sessions

def _make_session(events: list[TimelineEvent]) -> TimelineSession:
    """Build a TimelineSession from a list of events."""
    agent_id = events[0].agent_id or "unknown"
    severities: dict[str, int] = {}
    for evt in events:
        sev = evt.severity
        severities[sev] = severities.get(sev, 0) + 1

    return TimelineSession(
        session_id=_generate_session_id(agent_id, events[0].timestamp),
        start=events[0].timestamp,
        end=events[-1].timestamp,
        event_count=len(events),
        severities=severities,
    )

# ── ATLAS Enrichment for ClickHouse events ────────────────────────────────────

def _enrich_events_with_atlas(events: list[TimelineEvent]) -> None:
    """Add ATLAS technique metadata to events based on their type."""
    for evt in events:
        if evt.atlas_techniques:
            continue  # already enriched (e.g., from PG alert)
        # For raw ClickHouse events, try to map event_type to a technique
        attack_class = evt.raw_data.get("attack_class", "")
        if attack_class:
            techniques = mitre_service.techniques_for_attack_class(attack_class)
            if techniques:
                tech_data = mitre_service.get_all_techniques()
                evt.atlas_techniques = [
                    {
                        "id": tid,
                        "name": tech_data.get(tid, {}).get("name", tid),
                        "url": tech_data.get(tid, {}).get("url", ""),
                    }
                    for tid in techniques
                ]

# ── Public API ────────────────────────────────────────────────────────────────

async def get_agent_timeline(
    tenant_id: uuid.UUID,
    agent_id: str,
    *,
    range_str: str = "24h",
    limit: int = MAX_EVENTS_PER_PAGE,
    cursor: str | None = None,
    ch_client: Any | None = None,
    pg_session: Any | None = None,
    neo4j_driver: Any | None = None,
    trust_client: Any | None = None,
) -> TimelineResponse:
    """Assemble a forensic timeline for an agent.

    Queries all configured data sources in parallel (where possible),
    merges results chronologically, enriches with trust scores and
    ATLAS techniques.
    """
    hours = _parse_range(range_str)
    since = datetime.now(UTC) - timedelta(hours=hours)
    capped_limit = min(limit, MAX_EVENTS_PER_PAGE)

    # Gather events from all sources
    all_events: list[TimelineEvent] = []
    data_sources: list[DataSourceStatus] = []

    # ClickHouse: raw events
    ch_events, ch_status = await _fetch_clickhouse_events(
        ch_client,
        tenant_id,
        agent_id=agent_id,
        since=since,
        limit=capped_limit,
        cursor=cursor,
    )
    all_events.extend(ch_events)
    data_sources.append(ch_status)

    # PostgreSQL: alerts
    pg_events, pg_status = await _fetch_pg_alerts(
        pg_session,
        tenant_id,
        agent_id=agent_id,
        since=since,
        limit=capped_limit,
    )
    all_events.extend(pg_events)
    data_sources.append(pg_status)

    # Neo4j: relationship context
    neo4j_events, neo4j_status = await _fetch_neo4j_context(
        neo4j_driver,
        tenant_id,
        agent_id=agent_id,
        since=since,
    )
    all_events.extend(neo4j_events)
    data_sources.append(neo4j_status)

    # Sort chronologically
    all_events.sort(key=lambda e: e.timestamp)

    # ATLAS enrichment for raw events
    _enrich_events_with_atlas(all_events)

    # Trust score enrichment
    trust_status = await _enrich_trust_scores(all_events, trust_client, tenant_id)
    data_sources.append(trust_status)

    # Pagination
    has_more = len(all_events) > capped_limit
    if has_more:
        all_events = all_events[:capped_limit]

    next_cursor = all_events[-1].timestamp.isoformat() if has_more and all_events else None

    # Session grouping
    sessions = _group_into_sessions(all_events)

    return TimelineResponse(
        agent_id=str(agent_id),
        range_hours=hours,
        total_events=len(all_events),
        events=all_events,
        sessions=sessions,
        data_sources=data_sources,
        has_more=has_more,
        next_cursor=next_cursor,
    )

async def get_alert_timeline(
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    *,
    limit: int = MAX_EVENTS_PER_PAGE,
    ch_client: Any | None = None,
    pg_session: Any | None = None,
    neo4j_driver: Any | None = None,
    trust_client: Any | None = None,
) -> TimelineResponse:
    """Assemble a forensic timeline for an alert.

    Retrieves the alert, then fetches events in a ±5 min window around
    the alert timestamp from all data sources.
    """
    capped_limit = min(limit, MAX_EVENTS_PER_PAGE)

    # First, get the alert itself from PG to find its timestamp and agent
    alert_events, pg_status = await _fetch_pg_alerts(
        pg_session,
        tenant_id,
        alert_id=alert_id,
        since=datetime(2020, 1, 1, tzinfo=UTC),  # no lower bound for alert lookup
        limit=1,
    )

    if not alert_events:
        # Return empty timeline with PG status
        return TimelineResponse(
            alert_id=str(alert_id),
            range_hours=0,
            total_events=0,
            events=[],
            data_sources=[pg_status],
        )

    alert_event = alert_events[0]
    alert_ts = alert_event.timestamp
    alert_agent_id = alert_event.agent_id

    # Query ±5 minutes around the alert
    window_minutes = 5
    since = alert_ts - timedelta(minutes=window_minutes)
    until = alert_ts + timedelta(minutes=window_minutes)

    all_events: list[TimelineEvent] = []
    data_sources: list[DataSourceStatus] = [pg_status]

    # ClickHouse: events in window
    if alert_agent_id:
        agent_filter: str | None = alert_agent_id
    else:
        agent_filter = None
    ch_events, ch_status = await _fetch_clickhouse_events(
        ch_client,
        tenant_id,
        agent_id=agent_filter,
        since=since,
        until=until,
        limit=capped_limit,
    )
    all_events.extend(ch_events)
    data_sources.append(ch_status)

    # Neo4j: relationship context for the alert
    neo4j_events, neo4j_status = await _fetch_neo4j_context(
        neo4j_driver,
        tenant_id,
        agent_id=agent_filter,
        alert_id=alert_id,
        since=since,
    )
    all_events.extend(neo4j_events)
    data_sources.append(neo4j_status)

    # Include the alert itself
    all_events.append(alert_event)

    # Sort chronologically
    all_events.sort(key=lambda e: e.timestamp)

    # ATLAS enrichment
    _enrich_events_with_atlas(all_events)

    # Trust score enrichment
    trust_status = await _enrich_trust_scores(all_events, trust_client, tenant_id)
    data_sources.append(trust_status)

    # Pagination
    has_more = len(all_events) > capped_limit
    if has_more:
        all_events = all_events[:capped_limit]

    sessions = _group_into_sessions(all_events)

    return TimelineResponse(
        alert_id=str(alert_id),
        range_hours=round(window_minutes * 2 / 60, 2),
        total_events=len(all_events),
        events=all_events,
        sessions=sessions,
        data_sources=data_sources,
        has_more=has_more,
        next_cursor=all_events[-1].timestamp.isoformat() if has_more and all_events else None,
    )
