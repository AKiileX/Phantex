-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 021: Copilot AI Configuration
-- Stores per-tenant LLM provider settings for the Phantex Copilot.
-- API keys are encrypted using Fernet (derived from JWT secret).
-- Default: local provider pointing to host.docker.internal:1234 (LM Studio).

BEGIN;

-- ── Copilot configuration table ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS copilot_config (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Provider settings
    provider        TEXT NOT NULL DEFAULT 'local'
        CHECK (provider IN ('local', 'openai', 'anthropic', 'custom')),
    base_url        TEXT NOT NULL DEFAULT 'http://host.docker.internal:1234/v1',
    model           TEXT NOT NULL DEFAULT 'mistral',
    api_key_enc     TEXT,            -- Fernet-encrypted API key (NULL for local)
    max_tokens      INTEGER NOT NULL DEFAULT 4096
        CHECK (max_tokens >= 256 AND max_tokens <= 32768),
    temperature     REAL NOT NULL DEFAULT 0.3
        CHECK (temperature >= 0.0 AND temperature <= 2.0),

    -- Security policy
    data_policy     TEXT NOT NULL DEFAULT 'local_only'
        CHECK (data_policy IN ('local_only', 'allow_cloud')),
    enabled         BOOLEAN NOT NULL DEFAULT true,

    -- Audit
    updated_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One config per tenant
    UNIQUE (tenant_id)
);

-- Enable RLS
ALTER TABLE copilot_config ENABLE ROW LEVEL SECURITY;

-- RLS policies: tenant isolation
CREATE POLICY copilot_config_tenant_isolation ON copilot_config
    USING (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY copilot_config_tenant_insert ON copilot_config
    FOR INSERT WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

-- Indexes
CREATE INDEX IF NOT EXISTS idx_copilot_config_tenant ON copilot_config (tenant_id);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_copilot_config_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_copilot_config_updated
    BEFORE UPDATE ON copilot_config
    FOR EACH ROW EXECUTE FUNCTION update_copilot_config_timestamp();

-- ── Seed default config for dev tenant ──────────────────────────────────────
-- Uses the dev tenant from 002_bootstrap.sql
INSERT INTO copilot_config (tenant_id, provider, base_url, model, data_policy)
SELECT
    id,
    'local',
    'http://host.docker.internal:1234/v1',
    'mistral',
    'local_only'
FROM tenants
WHERE slug = 'phantex-dev'
ON CONFLICT (tenant_id) DO NOTHING;

-- ── Grant permissions ───────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE ON copilot_config TO phantex_admin;

COMMIT;
