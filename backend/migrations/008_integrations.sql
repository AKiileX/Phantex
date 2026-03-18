-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Phantex Migration 008: SIEM/XDR Integrations Table (N1)
--
-- Stores per-tenant integration configurations.
-- Config field contains JSON with platform-specific credentials
-- (encrypted at rest via Vault Transit in production).

BEGIN;

CREATE TABLE IF NOT EXISTS integrations (
    id              TEXT PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    platform        TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    config          JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    rate_limit_per_min INTEGER NOT NULL DEFAULT 1000,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Each tenant can have multiple integrations of same platform
    -- but names must be unique per tenant
    CONSTRAINT uq_integration_tenant_name UNIQUE (tenant_id, name)
);

-- Fast lookup by tenant
CREATE INDEX IF NOT EXISTS idx_integrations_tenant
    ON integrations (tenant_id)
    WHERE enabled = true;

-- Platform filter
CREATE INDEX IF NOT EXISTS idx_integrations_platform
    ON integrations (platform);

-- Audit: updated_at auto-update trigger
CREATE OR REPLACE FUNCTION update_integrations_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_integrations_updated ON integrations;
CREATE TRIGGER trg_integrations_updated
    BEFORE UPDATE ON integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_integrations_timestamp();

-- Row-level security: strict tenant isolation
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;

-- Policy: tenants can only access their own integrations
CREATE POLICY integrations_tenant_isolation ON integrations
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMIT;
