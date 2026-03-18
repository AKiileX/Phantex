// ============================================================================
// Phantex Neo4j — Constraints & Indexes
//
// Run via: cypher-shell -u neo4j -p <password> -f constraints.cypher
// Or auto-applied by the graph_writer service on startup.
// ============================================================================

// ── Uniqueness constraints (also create indexes) ────────────────────────────

CREATE CONSTRAINT agent_paid_unique IF NOT EXISTS
FOR (a:Agent) REQUIRE (a.tenant_id, a.paid) IS UNIQUE;

CREATE CONSTRAINT event_id_unique IF NOT EXISTS
FOR (e:Event) REQUIRE e.event_id IS UNIQUE;

CREATE CONSTRAINT network_dest_unique IF NOT EXISTS
FOR (n:NetworkDest) REQUIRE (n.tenant_id, n.ip, n.port) IS UNIQUE;

CREATE CONSTRAINT file_path_unique IF NOT EXISTS
FOR (f:File) REQUIRE (f.tenant_id, f.path) IS UNIQUE;

CREATE CONSTRAINT tool_name_unique IF NOT EXISTS
FOR (t:Tool) REQUIRE (t.tenant_id, t.name) IS UNIQUE;

CREATE CONSTRAINT alert_id_unique IF NOT EXISTS
FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE;

// ── Additional indexes for traversal queries ────────────────────────────────

CREATE INDEX agent_tenant IF NOT EXISTS
FOR (a:Agent) ON (a.tenant_id);

CREATE INDEX event_tenant IF NOT EXISTS
FOR (e:Event) ON (e.tenant_id);

CREATE INDEX event_timestamp IF NOT EXISTS
FOR (e:Event) ON (e.timestamp);

CREATE INDEX event_type IF NOT EXISTS
FOR (e:Event) ON (e.event_type);

CREATE INDEX alert_tenant IF NOT EXISTS
FOR (a:Alert) ON (a.tenant_id);

CREATE INDEX network_dest_tenant IF NOT EXISTS
FOR (n:NetworkDest) ON (n.tenant_id);

CREATE INDEX file_tenant IF NOT EXISTS
FOR (f:File) ON (f.tenant_id);

CREATE INDEX tool_tenant IF NOT EXISTS
FOR (t:Tool) ON (t.tenant_id);
