-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 028: Agent Drift Detection + ABOM
-- ============================================================================
-- Tables:
--   1. agent_config_snapshots  — point-in-time agent configuration captures
--   2. agent_drift_events      — detected configuration changes (diffs)
--   3. agent_aboms             — Agent Bill of Materials (versioned)
--   4. drift_approval_log      — change approval/rejection audit trail (append-only)
--   5. drift_policy            — per-tenant drift detection policy (strict/standard/learning)
--
-- Security:
--   - RLS on every table (tenant isolation)
--   - drift_approval_log is INSERT-only (immutable audit trail)
--   - ABAC permissions: drift.read, drift.manage, drift.approve
--   - Indexes for hot query paths
-- ============================================================================

BEGIN;

-- ── 1. agent_config_snapshots ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_config_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    agent_id        VARCHAR(255) NOT NULL,          -- PAID or internal agent identifier
    version         INTEGER NOT NULL DEFAULT 1,     -- monotonic per agent
    -- Tracked configuration elements (Section 31.1)
    model_provider  VARCHAR(128),                   -- e.g. "openai", "anthropic", "local"
    model_name      VARCHAR(255),                   -- e.g. "gpt-4o", "claude-3.5-sonnet"
    model_version   VARCHAR(128),                   -- specific model version
    prompt_hash     VARCHAR(64),                    -- SHA-256 of system prompt
    tool_list       JSONB NOT NULL DEFAULT '[]',    -- ordered list of tools/MCP servers
    permissions     JSONB NOT NULL DEFAULT '{}',    -- file, network, API permissions
    env_var_hashes  JSONB NOT NULL DEFAULT '{}',    -- key name → SHA-256 of value
    dependencies    JSONB NOT NULL DEFAULT '[]',    -- [{name, version, ecosystem}]
    rag_sources     JSONB NOT NULL DEFAULT '[]',    -- [{type, endpoint, collection}]
    temperature     REAL,                           -- LLM sampling temperature
    framework_name  VARCHAR(128),                   -- "langchain", "autogen", "crewai"
    framework_version VARCHAR(64),                  -- exact framework version
    -- Metadata
    snapshot_trigger VARCHAR(32) NOT NULL DEFAULT 'discovery', -- discovery | change | manual | scheduled
    captured_by     VARCHAR(255),                   -- sensor ID or "manual"
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_snapshots_tenant_agent
    ON agent_config_snapshots (tenant_id, agent_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_created
    ON agent_config_snapshots (tenant_id, created_at DESC);
-- Defence-in-depth: prevent duplicate versions under concurrent inserts
CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_unique_version
    ON agent_config_snapshots (tenant_id, agent_id, version);

ALTER TABLE agent_config_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY snapshots_tenant_isolation ON agent_config_snapshots
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY snapshots_insert ON agent_config_snapshots
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── 2. agent_drift_events ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_drift_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    agent_id            VARCHAR(255) NOT NULL,
    -- What changed
    drift_type          VARCHAR(64) NOT NULL,       -- model_swap | prompt_change | tool_added | tool_removed | permission_escalation | dependency_change | rag_change | config_change
    severity            VARCHAR(16) NOT NULL DEFAULT 'medium',  -- critical | high | medium | low
    field_name          VARCHAR(128) NOT NULL,       -- which config field drifted
    old_value           TEXT,                         -- previous value (or hash)
    new_value           TEXT,                         -- current value (or hash)
    -- Snapshot references
    baseline_snapshot_id UUID NOT NULL REFERENCES agent_config_snapshots(id),
    current_snapshot_id  UUID NOT NULL REFERENCES agent_config_snapshots(id),
    -- Resolution
    status              VARCHAR(24) NOT NULL DEFAULT 'open', -- open | approved | rejected | auto_reverted
    resolved_by         UUID,                        -- user_id who resolved
    resolved_at         TIMESTAMPTZ,
    resolution_reason   TEXT,
    -- Metadata
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_drift_tenant_agent
    ON agent_drift_events (tenant_id, agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_tenant_status
    ON agent_drift_events (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_severity
    ON agent_drift_events (tenant_id, severity, created_at DESC);

ALTER TABLE agent_drift_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY drift_tenant_isolation ON agent_drift_events
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY drift_insert ON agent_drift_events
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY drift_update ON agent_drift_events
    FOR UPDATE USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── 3. agent_aboms ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_aboms (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    agent_id        VARCHAR(255) NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    -- ABOM contents (Section 34.1)
    snapshot_id     UUID NOT NULL REFERENCES agent_config_snapshots(id),
    components      JSONB NOT NULL DEFAULT '{}',    -- full ABOM breakdown
    risk_score      REAL NOT NULL DEFAULT 0.0,      -- 0.0–100.0 composite risk
    risk_factors    JSONB NOT NULL DEFAULT '[]',    -- [{factor, weight, value, contribution}]
    compliance_tags JSONB NOT NULL DEFAULT '[]',    -- ["handles_pii", "financial_data"]
    vulnerability_count INTEGER NOT NULL DEFAULT 0, -- known CVEs in deps
    -- Export cache
    cyclonedx_json  JSONB,                          -- CycloneDX SBOM extension
    -- Metadata
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_abom_tenant_agent
    ON agent_aboms (tenant_id, agent_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_abom_risk
    ON agent_aboms (tenant_id, risk_score DESC);
-- Defence-in-depth: prevent duplicate versions under concurrent inserts
CREATE UNIQUE INDEX IF NOT EXISTS idx_abom_unique_version
    ON agent_aboms (tenant_id, agent_id, version);

ALTER TABLE agent_aboms ENABLE ROW LEVEL SECURITY;

CREATE POLICY abom_tenant_isolation ON agent_aboms
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY abom_insert ON agent_aboms
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY abom_update ON agent_aboms
    FOR UPDATE USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── 4. drift_approval_log (append-only audit trail) ──────────────────────

CREATE TABLE IF NOT EXISTS drift_approval_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    drift_event_id  UUID NOT NULL REFERENCES agent_drift_events(id),
    action          VARCHAR(24) NOT NULL,           -- approved | rejected | escalated | auto_reverted
    user_id         UUID NOT NULL,
    reason          TEXT NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approval_tenant
    ON drift_approval_log (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_drift
    ON drift_approval_log (drift_event_id, created_at DESC);

ALTER TABLE drift_approval_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY approval_tenant_read ON drift_approval_log
    FOR SELECT USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- INSERT-ONLY: no UPDATE or DELETE policies — immutable audit trail
CREATE POLICY approval_tenant_insert ON drift_approval_log
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── 5. drift_policy (per-tenant configuration) ───────────────────────────

CREATE TABLE IF NOT EXISTS drift_policy (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL UNIQUE,           -- one policy per tenant
    mode            VARCHAR(16) NOT NULL DEFAULT 'learning', -- strict | standard | learning
    learning_ends_at TIMESTAMPTZ,                   -- auto-switch to standard after this
    alert_on_model_swap     BOOLEAN NOT NULL DEFAULT true,
    alert_on_prompt_change  BOOLEAN NOT NULL DEFAULT true,
    alert_on_tool_change    BOOLEAN NOT NULL DEFAULT true,
    alert_on_permission_escalation BOOLEAN NOT NULL DEFAULT true,
    alert_on_dependency_change     BOOLEAN NOT NULL DEFAULT false,
    alert_on_rag_change            BOOLEAN NOT NULL DEFAULT true,
    auto_revert_enabled     BOOLEAN NOT NULL DEFAULT false,
    -- Maintenance windows (changes during these times are expected)
    maintenance_windows     JSONB NOT NULL DEFAULT '[]', -- [{day_of_week, start_hour, end_hour}]
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE drift_policy ENABLE ROW LEVEL SECURITY;

CREATE POLICY drift_policy_tenant ON drift_policy
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY drift_policy_insert ON drift_policy
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY drift_policy_update ON drift_policy
    FOR UPDATE USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── ABAC Permissions ──────────────────────────────────────────────────────

INSERT INTO permissions (resource, action, description) VALUES
    ('drift', 'read',    'View agent config snapshots, drift events, and ABOMs'),
    ('drift', 'manage',  'Create snapshots, configure drift policy'),
    ('drift', 'approve', 'Approve or reject configuration drift events')
ON CONFLICT (resource, action) DO NOTHING;

-- Auto-assign drift permissions to the admin role for immediate access
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin' AND p.resource = 'drift'
ON CONFLICT DO NOTHING;

-- ── Grants for phantex_app role ───────────────────────────────────────────

GRANT SELECT, INSERT          ON agent_config_snapshots TO phantex_app;
GRANT SELECT, INSERT, UPDATE  ON agent_drift_events     TO phantex_app;
GRANT SELECT, INSERT, UPDATE  ON agent_aboms            TO phantex_app;
GRANT SELECT, INSERT          ON drift_approval_log     TO phantex_app;
GRANT SELECT, INSERT, UPDATE  ON drift_policy           TO phantex_app;

COMMIT;
