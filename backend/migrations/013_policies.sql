-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 013: Policy Editor Backend (N4)
-- Policies table with versioning, soft-delete, and tenant isolation (RLS)

BEGIN;

-- ── Policies table ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policies (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    description     TEXT        DEFAULT '',
    version         INTEGER     NOT NULL DEFAULT 1,
    enabled         BOOLEAN     NOT NULL DEFAULT true,

    -- Policy definition (JSON — parsed from YAML on ingest)
    definition      JSONB       NOT NULL DEFAULT '{}',

    -- Scope: which agents/frameworks this policy applies to
    scope_agent_tags    TEXT[]      DEFAULT '{}',
    scope_frameworks    TEXT[]      DEFAULT '{}',

    -- Soft delete
    deleted         BOOLEAN     NOT NULL DEFAULT false,
    deleted_at      TIMESTAMPTZ,
    deleted_by      UUID,

    -- Audit
    created_by      UUID        NOT NULL,
    updated_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()

    -- No UNIQUE constraint on (tenant_id, name) — soft-delete makes it
    -- impossible to reuse names.  Use a partial unique index instead.
    -- (see below)
);

-- Unique name per tenant — active policies only (allows soft-deleted reuse)
CREATE UNIQUE INDEX IF NOT EXISTS uq_policies_tenant_name_active
    ON policies (tenant_id, name) WHERE NOT deleted;

-- Index for fast tenant + enabled lookups
CREATE INDEX IF NOT EXISTS idx_policies_tenant_enabled
    ON policies (tenant_id, enabled) WHERE NOT deleted;

-- Index for agent tag matching
CREATE INDEX IF NOT EXISTS idx_policies_scope_tags
    ON policies USING GIN (scope_agent_tags) WHERE NOT deleted;

-- ── Policy versions (audit trail) ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_versions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID        NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version         INTEGER     NOT NULL,
    definition      JSONB       NOT NULL,
    change_summary  TEXT        DEFAULT '',
    created_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_policy_version UNIQUE (policy_id, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_policy
    ON policy_versions (policy_id, version DESC);

-- ── Row-Level Security ──────────────────────────────────────────────────────

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;

-- Policies: tenant isolation
CREATE POLICY policies_tenant_isolation ON policies
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Policy versions: tenant isolation
CREATE POLICY policy_versions_tenant_isolation ON policy_versions
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ── Trigger: auto-update updated_at ─────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_policies_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_policies_updated_at();

COMMIT;
