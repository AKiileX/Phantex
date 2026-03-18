-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 014: Agent Tagging & Policy
-- Adds agent tags, exemptions, alert routing rules, and maintenance windows.

BEGIN;

-- ══════════════════════════════════════════════════════════════════════════════
--  P1: Agent Tags
-- ══════════════════════════════════════════════════════════════════════════════

-- Add tags JSONB column to agents (key-value pairs like {"team": "data-eng"})
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '{}';

-- GIN index for fast tag-based queries
CREATE INDEX IF NOT EXISTS idx_agents_tags ON agents USING GIN (tags);

-- ══════════════════════════════════════════════════════════════════════════════
--  P2: Rule Exemptions
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS rule_exemptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name   TEXT NOT NULL,                    -- PRL rule name to exempt
    match_tags  JSONB NOT NULL DEFAULT '{}',      -- {"agent.tag.role": "ci-runner"}
    reason      TEXT NOT NULL,                    -- mandatory: why this exemption exists
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at  TIMESTAMPTZ,                      -- NULL = never expires
    hit_count   BIGINT NOT NULL DEFAULT 0,
    last_hit_at TIMESTAMPTZ,
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE rule_exemptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY rule_exemptions_tenant ON rule_exemptions
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE INDEX IF NOT EXISTS idx_rule_exemptions_tenant
    ON rule_exemptions (tenant_id) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_rule_exemptions_rule
    ON rule_exemptions (tenant_id, rule_name) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_rule_exemptions_match_tags
    ON rule_exemptions USING GIN (match_tags);

-- ══════════════════════════════════════════════════════════════════════════════
--  P3: Alert Routing Rules
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS alert_routing_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    match_tags     JSONB NOT NULL DEFAULT '{}',    -- {"agent.tag.team": "infra"}
    severity_min   TEXT NOT NULL DEFAULT 'info',   -- minimum severity to route
    channels       TEXT[] NOT NULL DEFAULT '{}',   -- channel IDs from notification_channels
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    priority       INTEGER NOT NULL DEFAULT 0,     -- lower = evaluated first
    created_by     UUID NOT NULL REFERENCES users(id),
    updated_by     UUID REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_routing_severity CHECK (
        severity_min IN ('info', 'low', 'medium', 'high', 'critical')
    )
);

ALTER TABLE alert_routing_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY alert_routing_rules_tenant ON alert_routing_rules
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE INDEX IF NOT EXISTS idx_alert_routing_tenant
    ON alert_routing_rules (tenant_id, priority) WHERE enabled = TRUE;

-- Unique name per tenant
CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_routing_tenant_name
    ON alert_routing_rules (tenant_id, name);

-- ══════════════════════════════════════════════════════════════════════════════
--  P4: Maintenance Windows
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    cron_schedule    TEXT NOT NULL,                  -- 5-field cron expression
    duration_minutes INTEGER NOT NULL,               -- how long the window lasts
    rules            TEXT[] NOT NULL DEFAULT '{}',   -- PRL rule names to suppress
    match_tags       JSONB NOT NULL DEFAULT '{}',    -- {"agent.tag.team": "backup"}
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    next_start       TIMESTAMPTZ,                    -- computed next activation
    last_started_at  TIMESTAMPTZ,
    last_ended_at    TIMESTAMPTZ,
    force_ended_by   UUID REFERENCES users(id),     -- admin who ended it early
    created_by       UUID NOT NULL REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_mw_duration CHECK (duration_minutes >= 1 AND duration_minutes <= 1440)
);

ALTER TABLE maintenance_windows ENABLE ROW LEVEL SECURITY;
CREATE POLICY maintenance_windows_tenant ON maintenance_windows
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE INDEX IF NOT EXISTS idx_maintenance_windows_tenant
    ON maintenance_windows (tenant_id) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_next
    ON maintenance_windows (next_start) WHERE enabled = TRUE;

-- Unique name per tenant
CREATE UNIQUE INDEX IF NOT EXISTS uq_maintenance_windows_tenant_name
    ON maintenance_windows (tenant_id, name);

-- auto-update updated_at trigger (reuse existing function if available)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at') THEN
        CREATE FUNCTION update_updated_at()
        RETURNS TRIGGER AS $func$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $func$ LANGUAGE plpgsql;
    END IF;
END;
$$;

CREATE TRIGGER trg_rule_exemptions_updated_at
    BEFORE UPDATE ON rule_exemptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_alert_routing_updated_at
    BEFORE UPDATE ON alert_routing_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_maintenance_windows_updated_at
    BEFORE UPDATE ON maintenance_windows
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMIT;
