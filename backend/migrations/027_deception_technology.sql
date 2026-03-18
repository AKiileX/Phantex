-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 027: Deception Technology Tables
-- ============================================================================
-- Tables:
--   decoy_agents         — Fake AI agents deployed as honeypots
--   canary_mcp_servers   — Fake MCP tool servers (honeypots)
--   canary_tokens        — Fake API keys, credentials, DNS, URLs
--   honeypot_events      — Interaction log (zero-FP alerts)
--
-- Security:
--   - RLS on ALL tables (tenant isolation)
--   - INSERT-only on honeypot_events (append-only audit trail)
--   - Strict grants (phantex_app only)
--   - Ed25519 key material stored for decoy agents
--   - Canary token values stored as SHA-256 hashes
-- ============================================================================

BEGIN;

-- ── 1. Decoy Agents ─────────────────────────────────────────────────────────
-- Fake AI agents that appear real in agent discovery but are honeypot traps.
-- Any interaction from a real agent triggers a zero-FP critical alert.

CREATE TABLE IF NOT EXISTS decoy_agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    -- Agent identity fields (mimic the agents table)
    paid            VARCHAR(128) NOT NULL,             -- Phantex Agent ID
    framework       VARCHAR(64)  NOT NULL DEFAULT 'langchain',
    framework_ver   VARCHAR(32)  NOT NULL DEFAULT '0.1.0',
    -- Cryptographic identity
    public_key      TEXT,                              -- Ed25519 public key (PEM)
    private_key_enc TEXT,                              -- Ed25519 private key (encrypted at rest)
    -- Decoy configuration
    decoy_profile   JSONB NOT NULL DEFAULT '{}',       -- behavior scripts, response templates
    network_config  JSONB NOT NULL DEFAULT '{}',       -- listening address, port, protocol
    -- Metadata
    enabled         BOOLEAN NOT NULL DEFAULT true,
    interaction_count BIGINT NOT NULL DEFAULT 0,
    last_triggered  TIMESTAMPTZ,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT decoy_agents_name_tenant_uq UNIQUE (tenant_id, name),
    CONSTRAINT decoy_agents_paid_tenant_uq UNIQUE (tenant_id, paid)
);

CREATE INDEX idx_decoy_agents_tenant    ON decoy_agents (tenant_id) WHERE enabled = true;
CREATE INDEX idx_decoy_agents_paid      ON decoy_agents (paid);

ALTER TABLE decoy_agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY decoy_agents_tenant_isolation ON decoy_agents
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 2. Canary MCP Servers ────────────────────────────────────────────────────
-- Fake MCP tool servers advertising enticing tools (e.g., admin_database_query).
-- Any agent connecting to a canary MCP server triggers an instant critical alert.

CREATE TABLE IF NOT EXISTS canary_mcp_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    -- MCP server configuration
    server_url      TEXT NOT NULL,                     -- listener URL
    advertised_tools JSONB NOT NULL DEFAULT '[]',      -- [{name, description, schema}]
    protocol        VARCHAR(16) NOT NULL DEFAULT 'sse', -- sse | stdio | streamable-http
    -- TLS configuration
    tls_enabled     BOOLEAN NOT NULL DEFAULT true,
    tls_cert_pem    TEXT,                              -- auto-generated self-signed cert
    -- Identity rotation
    rotate_identity BOOLEAN NOT NULL DEFAULT false,
    rotation_interval_hours INTEGER NOT NULL DEFAULT 168, -- 7 days
    last_rotated    TIMESTAMPTZ,
    -- Metadata
    enabled         BOOLEAN NOT NULL DEFAULT true,
    interaction_count BIGINT NOT NULL DEFAULT 0,
    last_triggered  TIMESTAMPTZ,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT canary_mcp_name_tenant_uq UNIQUE (tenant_id, name)
);

CREATE INDEX idx_canary_mcp_tenant ON canary_mcp_servers (tenant_id) WHERE enabled = true;

ALTER TABLE canary_mcp_servers ENABLE ROW LEVEL SECURITY;
CREATE POLICY canary_mcp_tenant_isolation ON canary_mcp_servers
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 3. Canary Tokens ─────────────────────────────────────────────────────────
-- Fake API keys, credentials, PII, DNS names, and URLs planted in the env.
-- If any agent uses/resolves/fetches a canary token → exfiltration detected.

CREATE TABLE IF NOT EXISTS canary_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    -- Token type and value
    token_type      VARCHAR(32) NOT NULL,              -- api_key | credential | pii | dns | url
    token_value_hash VARCHAR(128) NOT NULL,            -- SHA-256 of actual value (never stored raw)
    token_hint      VARCHAR(64),                       -- partial reveal for admin (e.g., "sk-...3f2a")
    -- Placement metadata
    placement       JSONB NOT NULL DEFAULT '{}',       -- where it was planted: {location, file, env_var, etc.}
    -- Monitoring config
    alert_on_read   BOOLEAN NOT NULL DEFAULT false,    -- alert when value is READ (not just used externally)
    alert_on_use    BOOLEAN NOT NULL DEFAULT true,     -- alert when value is USED (API call, DNS query, etc.)
    -- Metadata
    enabled         BOOLEAN NOT NULL DEFAULT true,
    trigger_count   BIGINT NOT NULL DEFAULT 0,
    last_triggered  TIMESTAMPTZ,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT canary_tokens_name_tenant_uq UNIQUE (tenant_id, name),
    CONSTRAINT canary_tokens_type_ck CHECK (token_type IN ('api_key', 'credential', 'pii', 'dns', 'url'))
);

CREATE INDEX idx_canary_tokens_tenant   ON canary_tokens (tenant_id) WHERE enabled = true;
CREATE INDEX idx_canary_tokens_hash     ON canary_tokens (token_value_hash);

ALTER TABLE canary_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY canary_tokens_tenant_isolation ON canary_tokens
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 4. Honeypot Events (Append-Only Audit Trail) ────────────────────────────
-- Every interaction with a decoy/canary is logged here.
-- Zero false positives — no legitimate reason to interact with deception assets.

CREATE TABLE IF NOT EXISTS honeypot_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Source of the event
    source_type     VARCHAR(32) NOT NULL,              -- decoy_agent | canary_mcp | canary_token
    source_id       UUID NOT NULL,                     -- FK to the specific deception asset
    source_name     VARCHAR(200) NOT NULL,             -- human-readable name for quick display
    -- Interacting agent
    agent_id        UUID,                              -- the real agent that interacted (if identified)
    agent_paid      VARCHAR(128),                      -- PAID of the interacting agent
    source_ip       INET,                              -- source IP if available
    -- Interaction details
    interaction_type VARCHAR(64) NOT NULL,             -- connect | query | tool_call | resolve | fetch | authenticate
    interaction_data JSONB NOT NULL DEFAULT '{}',      -- full transcript / request details
    -- Classification
    severity        VARCHAR(16) NOT NULL DEFAULT 'critical',
    attack_class    VARCHAR(64),                       -- e.g., lateral_movement, exfiltration, impersonation
    mitre_tactic    VARCHAR(64),                       -- MITRE ATT&CK tactic
    mitre_technique VARCHAR(64),                       -- MITRE ATT&CK technique
    -- Auto-response actions taken
    auto_response   JSONB NOT NULL DEFAULT '{}',       -- {isolated: bool, alert_id: uuid, ...}
    -- Timestamps
    triggered_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_honeypot_events_tenant     ON honeypot_events (tenant_id, triggered_at DESC);
CREATE INDEX idx_honeypot_events_source     ON honeypot_events (source_type, source_id);
CREATE INDEX idx_honeypot_events_agent      ON honeypot_events (agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX idx_honeypot_events_severity   ON honeypot_events (tenant_id, severity);

ALTER TABLE honeypot_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY honeypot_events_tenant_isolation ON honeypot_events
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── INSERT-only policy on honeypot_events (tamper-proof audit log) ───────────
CREATE POLICY honeypot_events_insert_only ON honeypot_events
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Block UPDATE/DELETE on honeypot_events for phantex_app role
-- (only superadmin can modify — defense in depth for forensic integrity)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'honeypot_events' AND policyname = 'honeypot_events_no_update'
    ) THEN
        CREATE POLICY honeypot_events_no_update ON honeypot_events
            FOR UPDATE USING (false);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'honeypot_events' AND policyname = 'honeypot_events_no_delete'
    ) THEN
        CREATE POLICY honeypot_events_no_delete ON honeypot_events
            FOR DELETE USING (false);
    END IF;
END $$;

-- ── 5. Deception Dashboard Stats (materialized summary) ─────────────────────
-- Lightweight summary table refreshed periodically for fast dashboard queries.

CREATE TABLE IF NOT EXISTS deception_stats (
    tenant_id               UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    total_decoy_agents      INTEGER NOT NULL DEFAULT 0,
    total_canary_mcp        INTEGER NOT NULL DEFAULT 0,
    total_canary_tokens     INTEGER NOT NULL DEFAULT 0,
    total_honeypot_events   BIGINT  NOT NULL DEFAULT 0,
    events_last_24h         INTEGER NOT NULL DEFAULT 0,
    events_last_7d          INTEGER NOT NULL DEFAULT 0,
    last_event_at           TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE deception_stats ENABLE ROW LEVEL SECURITY;
CREATE POLICY deception_stats_tenant_isolation ON deception_stats
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 6. Permissions ───────────────────────────────────────────────────────────
-- Add deception-specific permissions to the existing permissions table.

INSERT INTO permissions (id, resource, action, description)
VALUES
    (gen_random_uuid(), 'deception', 'read',   'View deception assets and honeypot events'),
    (gen_random_uuid(), 'deception', 'manage', 'Create, update, delete deception assets'),
    (gen_random_uuid(), 'deception', 'deploy', 'Deploy and activate deception assets')
ON CONFLICT (resource, action) DO NOTHING;

-- Grant deception permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.resource = 'deception'
  AND p.action IN ('read', 'manage', 'deploy')
ON CONFLICT DO NOTHING;

-- Grant read-only to analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'analyst'
  AND p.resource = 'deception'
  AND p.action = 'read'
ON CONFLICT DO NOTHING;

-- ── 7. Grants ────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON decoy_agents      TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON canary_mcp_servers TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON canary_tokens      TO phantex_app;
GRANT SELECT, INSERT                 ON honeypot_events    TO phantex_app;  -- INSERT only
GRANT SELECT, INSERT, UPDATE         ON deception_stats    TO phantex_app;

COMMIT;
