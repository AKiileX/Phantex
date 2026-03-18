-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 019: MCP Supply Chain Tables
-- Creates persistent tables for MCP server inventory, scan results,
-- behavioral anomalies, and risk assessments.

BEGIN;

-- ── 1. mcp_servers — persistent MCP server registry ─────────────────────────
CREATE TABLE IF NOT EXISTS mcp_servers (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    server_id       TEXT        NOT NULL,
    name            TEXT,
    trust_level     TEXT        NOT NULL DEFAULT 'unknown'
                                CHECK (trust_level IN ('verified','known','unknown','suspicious','blocked')),
    risk_score      REAL        NOT NULL DEFAULT 0.0,
    risk_level      TEXT        NOT NULL DEFAULT 'minimal'
                                CHECK (risk_level IN ('critical','high','medium','low','minimal')),
    content_hash    TEXT,
    protocol_version TEXT,
    capabilities    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    connection_count INTEGER    NOT NULL DEFAULT 0,
    anomaly_count   INTEGER     NOT NULL DEFAULT 0,
    error_rate      REAL        NOT NULL DEFAULT 0.0,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    blocked_at      TIMESTAMPTZ,
    blocked_reason  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, server_id)
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_trust  ON mcp_servers(tenant_id, trust_level);
CREATE INDEX IF NOT EXISTS idx_mcp_servers_risk   ON mcp_servers(tenant_id, risk_level);

-- ── 2. mcp_scan_results — package scan history ──────────────────────────────
CREATE TABLE IF NOT EXISTS mcp_scan_results (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    server_id       TEXT        NOT NULL,
    scan_type       TEXT        NOT NULL DEFAULT 'package'
                                CHECK (scan_type IN ('package','protocol','behavioral','full')),
    ecosystem       TEXT,
    total_packages  INTEGER     NOT NULL DEFAULT 0,
    clean_packages  INTEGER     NOT NULL DEFAULT 0,
    vulnerable      INTEGER     NOT NULL DEFAULT 0,
    malicious       INTEGER     NOT NULL DEFAULT 0,
    typosquat       INTEGER     NOT NULL DEFAULT 0,
    reputation_avg  REAL        NOT NULL DEFAULT 1.0,
    findings        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mcp_scans_tenant ON mcp_scan_results(tenant_id, server_id);
CREATE INDEX IF NOT EXISTS idx_mcp_scans_time   ON mcp_scan_results(scanned_at DESC);

-- ── 3. mcp_anomalies — behavioral + protocol anomaly log ────────────────────
CREATE TABLE IF NOT EXISTS mcp_anomalies (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    server_id       TEXT        NOT NULL,
    anomaly_type    TEXT        NOT NULL,
    severity        TEXT        NOT NULL DEFAULT 'medium'
                                CHECK (severity IN ('critical','high','medium','low','info')),
    detail          TEXT        NOT NULL,
    raw_evidence    TEXT,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mcp_anomalies_tenant ON mcp_anomalies(tenant_id, server_id);
CREATE INDEX IF NOT EXISTS idx_mcp_anomalies_sev    ON mcp_anomalies(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_mcp_anomalies_time   ON mcp_anomalies(detected_at DESC);

-- ── 4. RLS Policies ─────────────────────────────────────────────────────────
ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_anomalies ENABLE ROW LEVEL SECURITY;

CREATE POLICY rls_mcp_servers ON mcp_servers
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY rls_mcp_scan_results ON mcp_scan_results
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY rls_mcp_anomalies ON mcp_anomalies
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- ── 5. Grants ───────────────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE mcp_servers TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE mcp_scan_results TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE mcp_anomalies TO phantex_app;

-- ── 6. ABAC permissions ──────────────────────────────────────────────────────
INSERT INTO permissions (resource, action, description) VALUES
  ('mcp', 'read',  'View MCP server inventory, scan results, anomalies'),
  ('mcp', 'write', 'Block/unblock MCP servers, trigger scans')
ON CONFLICT (resource, action) DO NOTHING;

-- admin gets read+write
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.resource = 'mcp'
ON CONFLICT DO NOTHING;

-- analyst gets read only
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'analyst' AND p.resource = 'mcp' AND p.action = 'read'
ON CONFLICT DO NOTHING;

-- ── 7. Record migration ─────────────────────────────────────────────────────
INSERT INTO schema_migrations (version, description)
VALUES (19, 'MCP Supply Chain tables')
ON CONFLICT (version) DO NOTHING;

COMMIT;
