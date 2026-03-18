-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 026: SOAR Integration Tables
-- ============================================================================
-- Tables:
--   soar_api_keys        — API keys for SOAR platform authentication
--   soar_webhook_subs    — Outbound webhook subscriptions (Phantex → SOAR)
--   soar_webhook_logs    — Delivery log for outbound webhooks
--   soar_action_log      — Inbound action log (SOAR → Phantex)
--   soar_integrations    — SOAR platform configs (XSOAR, Phantom, Tines)
--
-- Security:
--   - RLS on ALL tables (tenant isolation)
--   - API keys stored as SHA-256 hashes (never plaintext)
--   - Webhook secrets encrypted at rest
--   - INSERT-only audit logs (no UPDATE/DELETE)
--   - Strict grants (phantex_app only)
-- ============================================================================

BEGIN;

-- ── 1. SOAR API Keys ────────────────────────────────────────────────────────
-- External SOAR platforms authenticate with these keys via X-Phantex-Api-Key.
-- Keys are stored as SHA-256 hashes — the raw key is shown once at creation.

CREATE TABLE IF NOT EXISTS soar_api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    key_hash        VARCHAR(128) NOT NULL,           -- SHA-256 of the raw key
    key_prefix      VARCHAR(12)  NOT NULL,            -- "phx_sk_..." for identification
    scopes          TEXT[]       NOT NULL DEFAULT '{}', -- allowed actions
    expires_at      TIMESTAMPTZ,                      -- NULL = never expires
    last_used_at    TIMESTAMPTZ,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,                      -- soft-delete
    CONSTRAINT soar_api_keys_name_tenant_uq UNIQUE (tenant_id, name)
);

CREATE INDEX idx_soar_api_keys_tenant   ON soar_api_keys (tenant_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_soar_api_keys_hash     ON soar_api_keys (key_hash)  WHERE revoked_at IS NULL;

ALTER TABLE soar_api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY soar_api_keys_tenant_isolation ON soar_api_keys
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 2. Outbound Webhook Subscriptions ────────────────────────────────────────
-- Phantex pushes alerts/events to SOAR platforms via webhooks.

CREATE TABLE IF NOT EXISTS soar_webhook_subs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    url             TEXT NOT NULL,                     -- HTTPS only (validated in app)
    secret          TEXT,                              -- HMAC signing secret (encrypted)
    event_types     TEXT[] NOT NULL DEFAULT '{alert.created}',
    -- Supported event types:
    --   alert.created, alert.updated, alert.resolved
    --   action.executed, action.shadow
    --   escalation.triggered, escalation.reset
    --   agent.isolated, agent.trust_changed
    severity_filter TEXT[] DEFAULT NULL,               -- NULL = all severities
    enabled         BOOLEAN NOT NULL DEFAULT true,
    retry_count     INTEGER NOT NULL DEFAULT 3,
    retry_delay_sec INTEGER NOT NULL DEFAULT 30,
    timeout_sec     INTEGER NOT NULL DEFAULT 15,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT soar_webhook_subs_name_tenant_uq UNIQUE (tenant_id, name),
    CONSTRAINT soar_webhook_subs_retry_count_ck CHECK (retry_count BETWEEN 0 AND 10),
    CONSTRAINT soar_webhook_subs_retry_delay_ck CHECK (retry_delay_sec BETWEEN 1 AND 3600),
    CONSTRAINT soar_webhook_subs_timeout_ck     CHECK (timeout_sec BETWEEN 1 AND 120)
);

CREATE INDEX idx_soar_webhook_subs_tenant ON soar_webhook_subs (tenant_id) WHERE enabled = true;

ALTER TABLE soar_webhook_subs ENABLE ROW LEVEL SECURITY;
CREATE POLICY soar_webhook_subs_tenant_isolation ON soar_webhook_subs
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 3. Webhook Delivery Log ──────────────────────────────────────────────────
-- Append-only audit trail of every webhook delivery attempt.

CREATE TABLE IF NOT EXISTS soar_webhook_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    subscription_id UUID NOT NULL REFERENCES soar_webhook_subs(id) ON DELETE CASCADE,
    event_type      VARCHAR(100) NOT NULL,
    event_id        UUID,                             -- alert_id or action_id
    status_code     INTEGER,
    response_ms     INTEGER,
    attempt         INTEGER NOT NULL DEFAULT 1,
    success         BOOLEAN NOT NULL DEFAULT false,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_soar_webhook_logs_sub     ON soar_webhook_logs (subscription_id, created_at DESC);
CREATE INDEX idx_soar_webhook_logs_tenant  ON soar_webhook_logs (tenant_id, created_at DESC);

ALTER TABLE soar_webhook_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY soar_webhook_logs_tenant_isolation ON soar_webhook_logs
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Prevent UPDATE/DELETE on logs (append-only)
CREATE RULE soar_webhook_logs_no_update AS ON UPDATE TO soar_webhook_logs DO INSTEAD NOTHING;
CREATE RULE soar_webhook_logs_no_delete AS ON DELETE TO soar_webhook_logs DO INSTEAD NOTHING;

-- ── 4. Inbound Action Log ────────────────────────────────────────────────────
-- Records every action a SOAR platform sends to Phantex.

CREATE TABLE IF NOT EXISTS soar_action_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    api_key_id      UUID NOT NULL REFERENCES soar_api_keys(id),
    action          VARCHAR(100) NOT NULL,            -- isolate, dismiss, escalate, create_rule
    target_type     VARCHAR(50)  NOT NULL,            -- alert, agent, rule
    target_id       UUID,
    request_body    JSONB,
    result          VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, success, error
    error           TEXT,
    source_ip       INET,
    user_agent      VARCHAR(500),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_soar_action_log_tenant  ON soar_action_log (tenant_id, created_at DESC);
CREATE INDEX idx_soar_action_log_key     ON soar_action_log (api_key_id, created_at DESC);

ALTER TABLE soar_action_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY soar_action_log_tenant_isolation ON soar_action_log
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Append-only
CREATE RULE soar_action_log_no_update AS ON UPDATE TO soar_action_log DO INSTEAD NOTHING;
CREATE RULE soar_action_log_no_delete AS ON DELETE TO soar_action_log DO INSTEAD NOTHING;

-- ── 5. SOAR Platform Integrations ───────────────────────────────────────────
-- Tracks configured SOAR platform connections (XSOAR, Phantom, Tines).

CREATE TABLE IF NOT EXISTS soar_integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    platform        VARCHAR(50)  NOT NULL,            -- xsoar, phantom, tines, generic
    name            VARCHAR(200) NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}',      -- platform-specific config (encrypted secrets)
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_sync_at    TIMESTAMPTZ,
    last_error      TEXT,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT soar_integrations_name_tenant_uq UNIQUE (tenant_id, name),
    CONSTRAINT soar_integrations_platform_ck CHECK (platform IN ('xsoar', 'phantom', 'tines', 'generic'))
);

CREATE INDEX idx_soar_integrations_tenant ON soar_integrations (tenant_id) WHERE enabled = true;

ALTER TABLE soar_integrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY soar_integrations_tenant_isolation ON soar_integrations
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- ── 6. Permissions ───────────────────────────────────────────────────────────

INSERT INTO permissions (id, resource, action, description) VALUES
    (gen_random_uuid(), 'soar', 'manage',   'Manage SOAR integrations, API keys, and webhooks'),
    (gen_random_uuid(), 'soar', 'view',     'View SOAR integrations and webhook logs'),
    (gen_random_uuid(), 'soar', 'execute',  'Execute actions via SOAR API (inbound)')
ON CONFLICT DO NOTHING;

-- Grant soar.manage + soar.view to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name = 'admin'
  AND p.resource = 'soar'
  AND p.action IN ('manage', 'view', 'execute')
ON CONFLICT DO NOTHING;

-- Grant soar.view to analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name = 'analyst'
  AND p.resource = 'soar'
  AND p.action = 'view'
ON CONFLICT DO NOTHING;

-- ── 7. Grants ────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON soar_api_keys      TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_webhook_subs  TO phantex_app;
GRANT SELECT, INSERT                 ON soar_webhook_logs  TO phantex_app;
GRANT SELECT, INSERT                 ON soar_action_log    TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_integrations  TO phantex_app;

COMMIT;
