# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Graph Service (I3).

Cypher query builder for investigation endpoints.
All queries are tenant-scoped — tenant_id is a required parameter in
every query, never inferred from user input.

Uses parameterized queries only — no string interpolation in Cypher.
"""

from __future__ import annotations

import uuid
from typing import Any

from neo4j import AsyncDriver

from app.utils.logging import get_logger

logger = get_logger("phantex.graph")

# ── Agent Neighborhood Graph ─────────────────────────────────────────────────

async def agent_graph(
    driver: AsyncDriver,
    tenant_id: uuid.UUID,
    *,
    agent_id: str,
    depth: int = 2,
) -> dict[str, Any]:
    """Return an agent's N-hop neighborhood including events, tools, files, network.

    Returns a graph structure: { nodes: [...], edges: [...] }
    """
    depth = max(1, min(depth, 3))  # Clamp to 1-3 to prevent excessive traversal

    # Neo4j does not allow parameters in relationship length patterns,
    # so we interpolate the clamped integer directly (safe: bounded 1-3).
    cypher = f"""
            MATCH path = (a:Agent {{paid: $agent_id, tenant_id: $tid}})-[*1..{depth}]-(connected)
            WHERE connected.tenant_id = $tid OR connected.tenant_id IS NULL
            WITH nodes(path) AS ns, relationships(path) AS rs
            UNWIND ns AS n
            WITH collect(DISTINCT n) AS nodes,
                 [r IN reduce(acc = [], p IN collect(rs) | acc + p) |
                  {{type: type(r), start: id(startNode(r)), end: id(endNode(r))}}
                 ] AS raw_edges
            RETURN
                [n IN nodes | {{
                    id: id(n),
                    labels: labels(n),
                    properties: properties(n)
                }}] AS nodes,
                raw_edges AS edges
            """

    async with driver.session() as session:
        result = await session.run(
            cypher,
            agent_id=str(agent_id),
            tid=str(tenant_id),
        )
        record = await result.single()
        if record is None:
            return {"nodes": [], "edges": []}

        return {
            "nodes": record["nodes"],
            "edges": _dedupe_edges(record["edges"]),
        }

# ── Alert Blast Radius ───────────────────────────────────────────────────────

async def alert_blast_radius(
    driver: AsyncDriver,
    tenant_id: uuid.UUID,
    *,
    alert_id: uuid.UUID,
) -> dict[str, Any]:
    """All agents and resources affected by an alert's attack chain.

    Traverses: Alert <-[:TRIGGERED]- Event <-[:PERFORMED]- Agent
               and Event -[:CONNECTED_TO|READ_FILE|CALLED_TOOL]-> resources
    """
    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (alert:Alert {alert_id: $alert_id, tenant_id: $tid})
            OPTIONAL MATCH (alert)<-[:TRIGGERED]-(evt:Event {tenant_id: $tid})
            OPTIONAL MATCH (evt)<-[:PERFORMED]-(agent:Agent {tenant_id: $tid})
            OPTIONAL MATCH (evt)-[:CONNECTED_TO|READ_FILE|CALLED_TOOL]->(resource)
            WHERE resource.tenant_id = $tid OR resource.tenant_id IS NULL
            RETURN
                properties(alert) AS alert,
                collect(DISTINCT properties(agent)) AS agents,
                collect(DISTINCT properties(evt)) AS events,
                collect(DISTINCT {labels: labels(resource), props: properties(resource)}) AS resources
            """,
            alert_id=str(alert_id),
            tid=str(tenant_id),
        )
        record = await result.single()
        if record is None:
            return {"alert": None, "agents": [], "events": [], "resources": []}

        return {
            "alert": record["alert"],
            "agents": record["agents"],
            "events": record["events"],
            "resources": [r for r in record["resources"] if r["props"]],
        }

# ── Shortest Path ────────────────────────────────────────────────────────────

async def shortest_path(
    driver: AsyncDriver,
    tenant_id: uuid.UUID,
    *,
    from_agent_id: str,
    to_ip: str,
) -> list[dict[str, Any]]:
    """Shortest path between an agent and a network destination.

    Returns ordered list of nodes and relationships in the path.
    """
    # Validate IP format (basic check — prevent Cypher injection via parameter)
    if not to_ip or len(to_ip) > 45:
        return []

    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (start:Agent {paid: $from_agent, tenant_id: $tid}),
                  (end:NetworkDest {ip: $to_ip, tenant_id: $tid}),
                  path = shortestPath((start)-[*..10]-(end))
            RETURN
                [n IN nodes(path) | {
                    id: id(n),
                    labels: labels(n),
                    properties: properties(n)
                }] AS nodes,
                [r IN relationships(path) | {
                    type: type(r),
                    start: id(startNode(r)),
                    end: id(endNode(r))
                }] AS edges
            """,
            from_agent=str(from_agent_id),
            to_ip=to_ip,
            tid=str(tenant_id),
        )
        record = await result.single()
        if record is None:
            return []

        return {
            "nodes": record["nodes"],
            "edges": record["edges"],
        }

# ── Lateral Movement ─────────────────────────────────────────────────────────

async def lateral_movement(
    driver: AsyncDriver,
    tenant_id: uuid.UUID,
    *,
    hours: int = 24,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Cross-agent connection patterns suggesting lateral movement.

    Finds agents that share network destinations with other agents
    within the specified time window.
    """
    hours = max(1, min(hours, 168))  # 1h to 7d
    limit = max(1, min(limit, 100))

    async with driver.session() as session:
        result = await session.run(
            """
            MATCH (a1:Agent {tenant_id: $tid})-[:PERFORMED]->(e1:Event)-[:CONNECTED_TO]->(dest:NetworkDest),
                  (a2:Agent {tenant_id: $tid})-[:PERFORMED]->(e2:Event)-[:CONNECTED_TO]->(dest)
            WHERE a1 <> a2
              AND e1.timestamp > datetime() - duration({hours: $hours})
              AND e2.timestamp > datetime() - duration({hours: $hours})
            RETURN
                properties(a1) AS agent_1,
                properties(a2) AS agent_2,
                properties(dest) AS shared_destination,
                count(*) AS connection_count,
                max(e1.timestamp) AS latest_connection
            ORDER BY connection_count DESC
            LIMIT $limit
            """,
            tid=str(tenant_id),
            hours=hours,
            limit=limit,
        )
        records = [record async for record in result]
        return [
            {
                "agent_1": r["agent_1"],
                "agent_2": r["agent_2"],
                "shared_destination": r["shared_destination"],
                "connection_count": r["connection_count"],
                "latest_connection": str(r["latest_connection"]) if r["latest_connection"] else None,
            }
            for r in records
        ]

# ── Graph Writer (used by I4 consumer) ───────────────────────────────────────

async def write_event_to_graph(
    driver: AsyncDriver,
    event: dict[str, Any],
) -> None:
    """Transform a raw event dict into graph nodes + relationships.

    Called by the Neo4j storage-writer consumer (I4).
    Uses MERGE to ensure idempotency.
    """
    tenant_id = event.get("tenant_id")
    agent_id = event.get("agent_id")
    event_id = event.get("event_id")
    event_type = event.get("event_type", "")

    if not all([tenant_id, agent_id, event_id]):
        return

    async with driver.session() as session:
        # Always create Agent + Event + PERFORMED
        await session.run(
            """
            MERGE (a:Agent {paid: $agent_id, tenant_id: $tid})
            ON CREATE SET a.name = $agent_name,
                          a.framework = $framework,
                          a.created_at = datetime()
            MERGE (e:Event {event_id: $event_id})
            ON CREATE SET e.tenant_id = $tid,
                          e.event_type = $event_type,
                          e.severity = $severity,
                          e.timestamp = datetime($timestamp),
                          e.attack_class = $attack_class
            MERGE (a)-[:PERFORMED]->(e)
            """,
            tid=tenant_id,
            agent_id=agent_id,
            event_id=event_id,
            agent_name=event.get("agent_name", ""),
            framework=event.get("framework", ""),
            event_type=event_type,
            severity=event.get("severity", "info"),
            timestamp=event.get("timestamp", ""),
            attack_class=event.get("attack_class"),
        )

        # Event-type specific relationships
        if event_type == "NETWORK_CONNECT" and event.get("dest_ip"):
            await session.run(
                """
                MATCH (e:Event {event_id: $event_id})
                MERGE (d:NetworkDest {ip: $ip, port: $port, tenant_id: $tid})
                MERGE (e)-[:CONNECTED_TO]->(d)
                """,
                event_id=event_id,
                ip=event["dest_ip"],
                port=event.get("dest_port", 0),
                tid=tenant_id,
            )

        elif event_type == "FILE_READ" and event.get("file_path"):
            await session.run(
                """
                MATCH (e:Event {event_id: $event_id})
                MERGE (f:File {path: $path, tenant_id: $tid})
                MERGE (e)-[:READ_FILE]->(f)
                """,
                event_id=event_id,
                path=event["file_path"],
                tid=tenant_id,
            )

        elif event_type == "TOOL_CALL" and event.get("tool_name"):
            await session.run(
                """
                MATCH (e:Event {event_id: $event_id})
                MERGE (t:Tool {name: $name, tenant_id: $tid})
                MERGE (e)-[:CALLED_TOOL]->(t)
                """,
                event_id=event_id,
                name=event["tool_name"],
                tid=tenant_id,
            )

async def write_alert_to_graph(
    driver: AsyncDriver,
    alert: dict[str, Any],
) -> None:
    """Write an alert node and link to its triggering event."""
    alert_id = alert.get("alert_id")
    event_id = alert.get("event_id")
    tenant_id = alert.get("tenant_id")

    if not all([alert_id, tenant_id]):
        return

    async with driver.session() as session:
        await session.run(
            """
            MERGE (a:Alert {alert_id: $alert_id})
            ON CREATE SET a.tenant_id = $tid,
                          a.rule = $rule,
                          a.severity = $severity,
                          a.status = $status,
                          a.created_at = datetime()
            """,
            alert_id=alert_id,
            tid=tenant_id,
            rule=alert.get("rule_name", ""),
            severity=alert.get("severity", "info"),
            status=alert.get("status", "new"),
        )

        if event_id:
            await session.run(
                """
                MATCH (e:Event {event_id: $event_id}),
                      (a:Alert {alert_id: $alert_id})
                MERGE (e)-[:TRIGGERED]->(a)
                """,
                event_id=event_id,
                alert_id=alert_id,
            )

# ── Helpers ──────────────────────────────────────────────────────────────────

def _dedupe_edges(edges: list[dict]) -> list[dict]:
    """Remove duplicate edges from collected path results."""
    seen = set()
    result = []
    for e in edges:
        key = (e.get("type"), e.get("start"), e.get("end"))
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result
