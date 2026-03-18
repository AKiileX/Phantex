# Neo4j Infrastructure

## Overview

Neo4j is the graph database for investigation capabilities. It models
relationships between agents, events, network destinations, files, tools,
and alerts as a property graph.

## Graph Model

```
(:Agent {paid, name, framework, tenant_id})
    -[:PERFORMED]->    (:Event {event_id, type, timestamp, severity})
    -[:CONNECTED_TO]-> (:NetworkDest {ip, port, hostname})
    -[:READ_FILE]->    (:File {path, hash})
    -[:CALLED_TOOL]->  (:Tool {name, mcp_server})
    -[:TRIGGERED]->    (:Alert {alert_id, rule, severity, status})
    -[:TRUSTS]->       (:Agent)   -- cross-agent trust relationship
```

## Schema Files

| File | Contents |
|------|----------|
| `schema/constraints.cypher` | Unique constraints + indexes for all node types |

## Dev Usage

Neo4j is started as part of `docker-compose.dev.yml`.

Standalone:
```bash
docker compose -f infra/neo4j/docker-compose.neo4j.yml up -d
```

Browser: http://localhost:7474 (login: neo4j / phantex-dev-password)

Cypher shell:
```bash
docker exec -it phantex-neo4j cypher-shell -u neo4j -p phantex-dev-password
```

## Key Design Decisions

- **Community Edition** — sufficient for single-node dev/staging; Enterprise for production HA
- **Constraints** per tenant_id + natural key — prevents cross-tenant data contamination
- **Indexes** on tenant_id for every node type — all queries must include tenant scope
- **Bolt protocol** (port 7687) — used by the Python `neo4j` async driver
- **90-day TTL** — batch delete of old nodes via scheduled Cypher query (not built-in Neo4j TTL)
