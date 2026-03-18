-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- 025: Automated Response Engine — decision-layer tables.
--
-- Tables:
--   response_policies      — per-tenant policies mapping alert conditions → actions
--   response_config        — per-tenant config: shadow mode, kill switch, escalation
--   response_action_log    — immutable log of auto-response decisions
--   escalation_state       — per-agent escalation ladder state
--
-- All tables carry tenant_id + RLS for multi-tenant isolation.

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════
-- 1. response_policies — defines when / what auto-response triggers
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS response_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    description     TEXT DEFAULT '',
    -- match conditions (all must match — AND logic)
    severity        VARCHAR(20)[] NOT NULL DEFAULT '{}',          -- e.g. {"critical","high"}
    attack_class    VARCHAR(100)[] NOT NULL DEFAULT '{}',         -- e.g. {"credential_theft"}
    event_type      VARCHAR(100)[] NOT NULL DEFAULT '{}',         -- e.g. {"process_exec"}
    min_confidence  REAL NOT NULL DEFAULT 0.0,                     -- ML confidence threshold
    -- action to take
    action          VARCHAR(60) NOT NULL,                          -- isolate_agent, block_ip, etc.
    action_params   JSONB NOT NULL DEFAULT '{}',                   -- extra params for action
    -- controls
    enabled         BOOLEAN NOT NULL DEFAULT true,
    priority        INTEGER NOT NULL DEFAULT 100,                  -- lower = higher priority
    cooldown_sec    INTEGER NOT NULL DEFAULT 300,                  -- min seconds between re-fires
    require_shadow  BOOLEAN NOT NULL DEFAULT true,                 -- must pass shadow period first
    -- audit
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_rp_severity CHECK (array_length(severity, 1) IS NULL OR array_length(severity, 1) <= 10),
    CONSTRAINT chk_rp_cooldown CHECK (cooldown_sec >= 0 AND cooldown_sec <= 86400),
    CONSTRAINT chk_rp_priority CHECK (priority >= 0 AND priority <= 10000),
    CONSTRAINT chk_rp_min_confidence CHECK (min_confidence >= 0.0 AND min_confidence <= 1.0)
);

-- RLS
ALTER TABLE response_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY rp_tenant_isolation ON response_policies
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY rp_tenant_insert ON response_policies
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Indexes
CREATE INDEX idx_rp_tenant_enabled ON response_policies (tenant_id, enabled) WHERE enabled = true;
CREATE INDEX idx_rp_priority ON response_policies (tenant_id, priority);

GRANT SELECT, INSERT, UPDATE ON response_policies TO phantex_app;

-- ═══════════════════════════════════════════════════════════════════════════
-- 2. response_config — per-tenant auto-response configuration
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS response_config (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    -- kill switch: disable all auto-response for this tenant
    kill_switch         BOOLEAN NOT NULL DEFAULT false,
    kill_switch_reason  TEXT DEFAULT '',
    kill_switch_set_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    kill_switch_set_at  TIMESTAMPTZ,
    -- shadow mode: log actions but don't enforce
    shadow_mode         BOOLEAN NOT NULL DEFAULT true,            -- default ON for safety
    shadow_expires_at   TIMESTAMPTZ,                              -- NULL = indefinite
    shadow_set_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    -- escalation ladder defaults
    escalation_enabled  BOOLEAN NOT NULL DEFAULT true,
    escalation_window   INTEGER NOT NULL DEFAULT 3600,            -- seconds to track offenses
    escalation_steps    JSONB NOT NULL DEFAULT '[
        {"level": 1, "action": "log_only", "label": "Monitor"},
        {"level": 2, "action": "throttle",  "label": "Throttle", "params": {"rate_limit": 10}},
        {"level": 3, "action": "isolate_agent", "label": "Isolate"},
        {"level": 4, "action": "block_ip",  "label": "Block + Alert SOC"}
    ]',
    -- rate limiting for auto-response
    max_actions_per_hour INTEGER NOT NULL DEFAULT 50,
    -- audit
    updated_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_rc_escalation_window CHECK (escalation_window >= 60 AND escalation_window <= 86400),
    CONSTRAINT chk_rc_max_actions CHECK (max_actions_per_hour >= 1 AND max_actions_per_hour <= 1000)
);

-- RLS
ALTER TABLE response_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY rc_tenant_isolation ON response_config
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY rc_tenant_insert ON response_config
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

GRANT SELECT, INSERT, UPDATE ON response_config TO phantex_app;

-- ═══════════════════════════════════════════════════════════════════════════
-- 3. response_action_log — immutable log of every auto-response decision
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS response_action_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id        UUID,                                         -- which alert triggered this
    policy_id       UUID REFERENCES response_policies(id) ON DELETE SET NULL,
    agent_id        UUID,
    -- what happened
    action          VARCHAR(60) NOT NULL,
    action_params   JSONB NOT NULL DEFAULT '{}',
    decision        VARCHAR(20) NOT NULL,                         -- "executed", "shadow", "blocked_kill_switch", "cooldown_skip", "escalated", "overridden"
    escalation_level INTEGER,
    -- context snapshot (immutable)
    alert_severity  VARCHAR(20),
    alert_confidence REAL,
    attack_class    VARCHAR(100),
    event_type      VARCHAR(100),
    -- override info
    overridden_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    override_reason TEXT DEFAULT '',
    -- timing
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    executed_at     TIMESTAMPTZ,
    CONSTRAINT chk_ral_decision CHECK (decision IN (
        'executed', 'shadow', 'blocked_kill_switch', 'cooldown_skip',
        'escalated', 'overridden', 'rate_limited', 'error'
    ))
);

-- RLS
ALTER TABLE response_action_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY ral_tenant_isolation ON response_action_log
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY ral_tenant_insert ON response_action_log
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- Indexes
CREATE INDEX idx_ral_tenant_created ON response_action_log (tenant_id, created_at DESC);
CREATE INDEX idx_ral_alert ON response_action_log (alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX idx_ral_agent ON response_action_log (tenant_id, agent_id, created_at DESC) WHERE agent_id IS NOT NULL;

-- INSERT-only for phantex_app (immutable audit trail)
GRANT SELECT, INSERT ON response_action_log TO phantex_app;

-- ═══════════════════════════════════════════════════════════════════════════
-- 4. escalation_state — tracks per-agent offense count for escalation ladder
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS escalation_state (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL,
    current_level   INTEGER NOT NULL DEFAULT 0,
    offense_count   INTEGER NOT NULL DEFAULT 0,
    first_offense   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_offense    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reset_at        TIMESTAMPTZ,                                  -- when window expires
    -- unique per agent per tenant
    CONSTRAINT uq_escalation_agent UNIQUE (tenant_id, agent_id)
);

-- RLS
ALTER TABLE escalation_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY es_tenant_isolation ON escalation_state
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
CREATE POLICY es_tenant_insert ON escalation_state
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX idx_es_agent ON escalation_state (tenant_id, agent_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON escalation_state TO phantex_app;

-- ═══════════════════════════════════════════════════════════════════════════
-- 5. Permissions for the response engine
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO permissions (resource, action, description) VALUES
    ('response', 'read',        'View auto-response policies and logs'),
    ('response', 'write',       'Create/update auto-response policies'),
    ('response', 'kill_switch', 'Toggle the auto-response kill switch'),
    ('response', 'override',    'Override/undo auto-response actions')
ON CONFLICT DO NOTHING;

-- Grant to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
  AND p.resource = 'response'
ON CONFLICT DO NOTHING;

-- Grant read-only to analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'analyst'
  AND p.resource = 'response'
  AND p.action = 'read'
ON CONFLICT DO NOTHING;

COMMIT;
