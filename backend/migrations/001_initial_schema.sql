-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex — Initial Database Schema
-- Migration: 001_initial_schema.sql
-- PostgreSQL 16+ required
--
-- Tables: tenants, users, agents, events, alerts, rules, audit_log
-- Security: Row-Level Security (RLS) on all tenant-scoped tables
-- App role: phantex_app (SELECT/INSERT/UPDATE only — no DROP/ALTER/DELETE*)
--   * soft-delete pattern used where needed
--
-- Run with superuser (phantex_admin):
--   psql -U phantex_admin -d phantex -f 001_initial_schema.sql
-- ============================================================================

-- ─── Extensions ──────────────────────────────────────────────────────────────
-- Run OUTSIDE the transaction block — CREATE EXTENSION inside BEGIN can cause
-- "duplicate key on pg_extension_name_index" on postgres restarts with existing
-- data, even with IF NOT EXISTS, due to MVCC visibility of system catalog entries.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";           -- gen_random_uuid(), crypt()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";            -- trigram index for text search
-- pg_stat_statements requires shared_preload_libraries — skip if not available
DO $$ BEGIN
  CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pg_stat_statements not available (needs shared_preload_libraries) — skipping';
END $$;

-- ─── App Role ────────────────────────────────────────────────────────────────
-- Run OUTSIDE the transaction block — CREATE ROLE modifies pg_authid, a shared
-- catalog. Same MVCC visibility issue as CREATE EXTENSION: IF NOT EXISTS check
-- can see stale state inside BEGIN, causing duplicate key on pg_authid_rolname_index.
-- The application connects as phantex_app, NEVER as phantex_admin.
-- phantex_app can SELECT, INSERT, UPDATE — but NOT DROP, ALTER, TRUNCATE, DELETE.
-- This limits damage from SQL injection or application compromise.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'phantex_app') THEN
        CREATE ROLE phantex_app WITH LOGIN PASSWORD 'phantex-app-dev-password';
    END IF;
END
$$;

BEGIN;

-- Grant connect + usage
GRANT CONNECT ON DATABASE phantex TO phantex_app;

-- ─── Schema ──────────────────────────────────────────────────────────────────
-- All Phantex tables live in the 'public' schema
-- Phase 2+: consider per-tenant schemas for stronger isolation.

-- ─── 1. Tenants ──────────────────────────────────────────────────────────────

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT UNIQUE NOT NULL,        -- used in PAID: ptx-{slug}-...
    plan            TEXT NOT NULL DEFAULT 'community',  -- community, team, business, enterprise
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenants IS 'Organizations using Phantex. Every row of data belongs to exactly one tenant.';
COMMENT ON COLUMN tenants.slug IS 'URL-safe identifier, used in PAID generation: ptx-{slug}-{env}-{hash}';
COMMENT ON COLUMN tenants.plan IS 'Pricing tier: community, team, business, enterprise';

-- ─── 2. Users ────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    password_hash   TEXT NOT NULL,               -- bcrypt cost 12
    role            TEXT NOT NULL DEFAULT 'viewer',  -- admin, analyst, viewer
    name            TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login      TIMESTAMPTZ,

    -- Email unique per tenant (same email can exist in different tenants)
    CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email),
    CONSTRAINT chk_users_role CHECK (role IN ('admin', 'analyst', 'viewer'))
);

COMMENT ON TABLE users IS 'Human users who access the Phantex dashboard/API.';
COMMENT ON COLUMN users.password_hash IS 'bcrypt hash with cost factor 12. NEVER store plaintext.';
COMMENT ON COLUMN users.role IS 'RBAC role: admin (full), analyst (read + rules + alerts), viewer (read only)';

-- ─── 3. Agents ───────────────────────────────────────────────────────────────

CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    paid            TEXT UNIQUE NOT NULL,        -- ptx-{tenant}-{env}-{hash}
    name            TEXT,                        -- human-friendly (auto or user-set)
    framework       TEXT,                        -- langchain, autogen, crewai, custom
    framework_ver   TEXT,                        -- version string
    process_pid     INT,
    exe_path        TEXT,                        -- executable path from /proc
    cmdline         TEXT,                        -- full command line
    container_id    TEXT,
    container_image TEXT,
    host_id         TEXT,                        -- sensor host identifier
    sensor_id       TEXT,                        -- which sensor discovered this agent
    status          TEXT NOT NULL DEFAULT 'active',  -- active, terminated, quarantined
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata        JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT chk_agents_status CHECK (status IN ('active', 'terminated', 'quarantined'))
);

COMMENT ON TABLE agents IS 'AI agents discovered by Phantex sensors. Each agent gets a unique PAID.';
COMMENT ON COLUMN agents.paid IS 'Phantex Agent ID: ptx-{tenant_slug}-{env}-{sha256[:12]}. Deterministic, stable across restarts.';

-- ─── 4. Events ───────────────────────────────────────────────────────────────
-- Events are the highest-volume table. Partitioned by month for performance.
-- Each partition is auto-created. Old partitions can be detached for archival.

CREATE TABLE events (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,              -- FK enforced at app layer (partitioned tables + FK = complex)
    agent_id        UUID,                       -- NULL for events before agent association
    sensor_id       TEXT,                        -- which sensor produced this event
    event_type      TEXT NOT NULL,              -- PROCESS_EXEC, FILE_OPEN, NETWORK_CONNECT, etc.
    severity        TEXT NOT NULL DEFAULT 'info',
    timestamp       TIMESTAMPTZ NOT NULL,       -- when the event occurred (kernel time)
    raw_data        JSONB NOT NULL,             -- full protobuf event serialized as JSON
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Composite PK required for range partitioning
    PRIMARY KEY (id, timestamp),
    CONSTRAINT chk_events_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
) PARTITION BY RANGE (timestamp);

COMMENT ON TABLE events IS 'All security events from sensors. Partitioned by month for query performance and retention management.';
COMMENT ON COLUMN events.raw_data IS 'Full protobuf event payload as JSON. Queryable with JSONB operators.';
COMMENT ON COLUMN events.timestamp IS 'Kernel-reported event time (not ingestion time). Used for partitioning.';

-- Create partitions for current month + 3 months ahead
-- In production, pg_partman or a cron job handles this automatically.
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    part_name TEXT;
    i INT;
BEGIN
    FOR i IN 0..3 LOOP
        start_date := date_trunc('month', CURRENT_DATE + (i || ' months')::INTERVAL)::DATE;
        end_date := (start_date + INTERVAL '1 month')::DATE;
        part_name := 'events_' || to_char(start_date, 'YYYY_MM');

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
            part_name, start_date, end_date
        );

        RAISE NOTICE 'Created partition: % (% to %)', part_name, start_date, end_date;
    END LOOP;
END
$$;

-- ─── 5. Rules ────────────────────────────────────────────────────────────────

CREATE TABLE rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = global (Phantex-provided)
    name            TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL DEFAULT 'medium',
    attack_class    TEXT,                       -- prompt_injection, exfiltration, dos, etc.
    prl_source      TEXT NOT NULL,              -- raw PRL rule text
    compiled        JSONB,                      -- compiled AST or condition tree
    enabled         BOOLEAN NOT NULL DEFAULT true,
    version         INT NOT NULL DEFAULT 1,
    author          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_rules_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

COMMENT ON TABLE rules IS 'PRL detection rules. tenant_id=NULL means global (shipped with Phantex).';
COMMENT ON COLUMN rules.prl_source IS 'Raw PRL (Phantex Rule Language) source text.';
COMMENT ON COLUMN rules.compiled IS 'Pre-compiled rule AST for fast evaluation by the detection engine.';

-- ─── 6. Alerts ───────────────────────────────────────────────────────────────

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    event_id        UUID,                       -- can't FK to partitioned events easily
    rule_id         UUID REFERENCES rules(id) ON DELETE SET NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'open',   -- open, acknowledged, resolved, false_positive
    context         JSONB NOT NULL DEFAULT '{}',    -- additional alert context (matched fields, scores)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT chk_alerts_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_alerts_status CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive'))
);

COMMENT ON TABLE alerts IS 'Security alerts fired by the detection engine when a rule matches an event.';

-- ─── 7. Audit Log ───────────────────────────────────────────────────────────
-- Tracks who did what. Immutable — INSERT only, no UPDATE/DELETE.

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,              -- alert.acknowledged, rule.created, agent.quarantined, user.login, etc.
    resource_type   TEXT,                       -- alert, rule, agent, user, tenant
    resource_id     UUID,
    details         JSONB NOT NULL DEFAULT '{}',
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE audit_log IS 'Immutable audit trail. INSERT only — the app role cannot UPDATE or DELETE rows.';

-- ─── 8. Refresh Tokens ─────────────────────────────────────────────────────
-- Opaque refresh tokens for JWT auth. Single-use, rotated on refresh.

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,       -- SHA-256 hash of the opaque token
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked         BOOLEAN NOT NULL DEFAULT false
);

COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens. Hashed, single-use, 7-day expiry.';

-- ─── Indexes ─────────────────────────────────────────────────────────────────
-- Designed around the actual query patterns from the API spec.

-- Agents
CREATE INDEX idx_agents_tenant_status ON agents (tenant_id, status);
CREATE INDEX idx_agents_paid ON agents (paid);
CREATE INDEX idx_agents_tenant_last_seen ON agents (tenant_id, last_seen DESC);

-- Events (indexes are per-partition, created on each partition automatically)
CREATE INDEX idx_events_tenant_time ON events (tenant_id, timestamp DESC);
CREATE INDEX idx_events_agent_time ON events (agent_id, timestamp DESC);
CREATE INDEX idx_events_type_time ON events (event_type, timestamp DESC);
CREATE INDEX idx_events_tenant_type ON events (tenant_id, event_type);

-- Alerts
CREATE INDEX idx_alerts_tenant_status ON alerts (tenant_id, status, created_at DESC);
CREATE INDEX idx_alerts_tenant_severity ON alerts (tenant_id, severity, created_at DESC);
CREATE INDEX idx_alerts_agent ON alerts (agent_id, created_at DESC);

-- Rules
CREATE INDEX idx_rules_tenant_enabled ON rules (tenant_id, enabled) WHERE enabled = true;

-- Users
CREATE INDEX idx_users_tenant ON users (tenant_id);
CREATE INDEX idx_users_email ON users (email);

-- Audit log
CREATE INDEX idx_audit_tenant_time ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_id);

-- Refresh tokens
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id) WHERE revoked = false;
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens (expires_at) WHERE revoked = false;

-- ─── Triggers ────────────────────────────────────────────────────────────────
-- Auto-update updated_at on row modification.

CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER trg_agents_updated_at BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER trg_rules_updated_at BEFORE UPDATE ON rules
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER trg_alerts_updated_at BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- ─── Row-Level Security (RLS) ───────────────────────────────────────────────
-- Every query through phantex_app is automatically filtered by tenant_id.
-- The app sets: SET app.current_tenant = '<tenant_id>' on each request.
-- This is a defense-in-depth layer — the application ALSO filters by tenant_id.

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules  ENABLE ROW LEVEL SECURITY;
ALTER TABLE users  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Policies: phantex_app can only see rows matching current_setting('app.current_tenant')
-- The superuser (phantex_admin) bypasses RLS by default.

CREATE POLICY tenant_isolation_agents ON agents
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_events ON events
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_alerts ON alerts
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- Rules: tenant-specific + global (tenant_id IS NULL)
CREATE POLICY tenant_isolation_rules ON rules
    FOR ALL TO phantex_app
    USING (
        tenant_id::text = current_setting('app.current_tenant', true)
        OR tenant_id IS NULL  -- global rules visible to all tenants
    );

CREATE POLICY tenant_isolation_users ON users
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_audit ON audit_log
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_tokens ON refresh_tokens
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- ─── App Role Grants ─────────────────────────────────────────────────────────
-- phantex_app gets SELECT + INSERT + UPDATE on all tables.
-- DELETE is NOT granted (soft-delete pattern: update status or revoked flag).
-- Exception: audit_log gets INSERT only (immutable).

GRANT USAGE ON SCHEMA public TO phantex_app;

GRANT SELECT, INSERT, UPDATE ON tenants TO phantex_app;
GRANT SELECT, INSERT, UPDATE ON users TO phantex_app;
GRANT SELECT, INSERT, UPDATE ON agents TO phantex_app;
GRANT SELECT, INSERT, UPDATE ON alerts TO phantex_app;
GRANT SELECT, INSERT, UPDATE ON rules TO phantex_app;
GRANT SELECT, INSERT         ON audit_log TO phantex_app;  -- no UPDATE on audit log
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO phantex_app;

-- Grant on event partitions (current + future)
GRANT SELECT, INSERT, UPDATE ON events TO phantex_app;

-- Allow phantex_app to set the tenant context variable
-- (This is set by the application on each request/connection)
ALTER ROLE phantex_app SET search_path TO public;

-- ─── Migration Tracking ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    description TEXT
);

INSERT INTO schema_migrations (version, description)
VALUES ('001', 'Initial schema: tenants, users, agents, events (partitioned), alerts, rules, audit_log, refresh_tokens, RLS, app role');

COMMIT;

-- ============================================================================
-- Migration 001 complete.
-- 
-- Tables created: 8 (+ event partitions)
-- Indexes created: 15
-- RLS policies: 7 (one per tenant-scoped table)
-- Triggers: 5 (updated_at auto-update)
-- Roles: phantex_app (restricted — no DELETE/DROP/ALTER)
-- 
-- Next: Run 002_bootstrap.sql for the default tenant and admin user.
-- ============================================================================
