-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- 010_agent_baselines.sql
-- Behavioral baseline profiles per agent (J4).
-- Each agent accumulates a statistical profile during a LEARNING phase
-- and transitions to ACTIVE after the configured learning_days period.

BEGIN;

CREATE TABLE IF NOT EXISTS agent_baselines (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    agent_id        TEXT        NOT NULL,
    mode            TEXT        NOT NULL DEFAULT 'LEARNING'
                        CHECK (mode IN ('LEARNING', 'ACTIVE', 'STALE')),
    profile_data    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, agent_id)
);

-- Index for fast lookups by agent
CREATE INDEX IF NOT EXISTS idx_agent_baselines_agent
    ON agent_baselines (tenant_id, agent_id);

-- Index for stale detection sweep
CREATE INDEX IF NOT EXISTS idx_agent_baselines_updated
    ON agent_baselines (updated_at)
    WHERE mode != 'STALE';

-- ── Row-Level Security ──────────────────────────────────────────────────────
ALTER TABLE agent_baselines ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_baselines_tenant_isolation ON agent_baselines
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));

COMMIT;
