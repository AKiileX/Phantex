-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 015: Enterprise Auth — ABAC + SSO + SCIM + Tenant Management
--
-- Phase 3, Block S: Enterprise Auth
-- Adds:
--   1. roles / permissions / role_permissions tables (ABAC)
--   2. sso_configs table (SAML + OIDC per tenant)
--   3. scim_tokens table (SCIM bearer auth per tenant)
--   4. user_roles junction (users can have multiple custom roles)
--   5. Relaxes the CHECK constraint on users.role to allow custom role names
--   6. Tenant onboarding fields
-- ============================================================================

BEGIN;

-- ── 1. Custom Roles ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_builtin  BOOLEAN NOT NULL DEFAULT false,
    policy      JSONB NOT NULL DEFAULT '{}',   -- ABAC policy document
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, name)
);

-- ── 2. Permissions ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    TEXT NOT NULL,          -- e.g. 'alerts', 'rules', 'agents'
    action      TEXT NOT NULL,          -- e.g. 'read', 'write', 'manage', 'delete'
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(resource, action)
);

-- ── 3. Role ↔ Permission mapping ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    conditions    JSONB NOT NULL DEFAULT '{}',  -- ABAC conditions (time, IP, resource tags)
    PRIMARY KEY (role_id, permission_id)
);

-- ── 4. User ↔ Role junction ─────────────────────────────────────────────────
-- Users can have multiple roles. The legacy users.role column is kept for
-- backward compatibility but new code resolves via this table.

CREATE TABLE IF NOT EXISTS user_roles (
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id   UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- ── 5. SSO Configurations (per tenant) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS sso_configs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_type  TEXT NOT NULL CHECK (provider_type IN ('saml', 'oidc')),
    name           TEXT NOT NULL DEFAULT '',
    is_enabled     BOOLEAN NOT NULL DEFAULT false,

    -- SAML fields
    idp_entity_id     TEXT,
    idp_sso_url       TEXT,
    idp_slo_url       TEXT,
    idp_certificate   TEXT,         -- PEM-encoded X.509 cert
    sp_entity_id      TEXT,
    sp_acs_url        TEXT,

    -- OIDC fields
    oidc_issuer       TEXT,
    oidc_client_id    TEXT,
    oidc_client_secret TEXT,       -- encrypted at rest (Vault or app-level)
    oidc_scopes       TEXT NOT NULL DEFAULT 'openid email profile',

    -- Common
    attribute_mapping JSONB NOT NULL DEFAULT '{}',  -- IdP attrs → Phantex fields
    default_role      TEXT NOT NULL DEFAULT 'viewer',
    jit_provisioning  BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, provider_type, name)
);

-- ── 6. SCIM Tokens (per tenant) ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scim_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,             -- SHA-256 hash of bearer token
    description TEXT NOT NULL DEFAULT '',
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,               -- NULL = never expires
    UNIQUE(token_hash)
);

-- ── 7. SSO Assertion IDs (replay protection) ────────────────────────────────

CREATE TABLE IF NOT EXISTS sso_assertion_ids (
    assertion_id TEXT PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    consumed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);

-- Clean up expired assertion IDs periodically
CREATE INDEX IF NOT EXISTS idx_sso_assertion_expires ON sso_assertion_ids(expires_at);

-- ── 8. Relax users.role CHECK constraint ─────────────────────────────────────
-- Drop the Phase 2 hardcoded 3-role constraint.
-- New code uses the roles + user_roles tables; legacy column kept for compat.

ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_role;

-- Add SSO provider tracking to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT;         -- 'saml', 'oidc', NULL (local)
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject_id TEXT;       -- IdP subject identifier
ALTER TABLE users ADD COLUMN IF NOT EXISTS scim_external_id TEXT;     -- SCIM externalId

-- ── 9. Tenant onboarding fields ──────────────────────────────────────────────

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS onboarded_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_users INTEGER NOT NULL DEFAULT 100;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_agents INTEGER NOT NULL DEFAULT 50;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_events_per_day BIGINT NOT NULL DEFAULT 10000000;

-- ── 10. RLS on new tables ────────────────────────────────────────────────────

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_assertion_ids ENABLE ROW LEVEL SECURITY;

-- Roles: tenant isolation
CREATE POLICY roles_tenant_isolation ON roles
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- Role permissions: via role's tenant
CREATE POLICY role_perms_tenant_isolation ON role_permissions
    USING (role_id IN (
        SELECT id FROM roles
        WHERE tenant_id::text = current_setting('app.current_tenant', true)
    ));

-- User roles: via user's tenant
CREATE POLICY user_roles_tenant_isolation ON user_roles
    USING (user_id IN (
        SELECT id FROM users
        WHERE tenant_id::text = current_setting('app.current_tenant', true)
    ));

-- SSO configs: tenant isolation
CREATE POLICY sso_configs_tenant_isolation ON sso_configs
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- SCIM tokens: tenant isolation
CREATE POLICY scim_tokens_tenant_isolation ON scim_tokens
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- SSO assertion IDs: tenant isolation
CREATE POLICY sso_assertions_tenant_isolation ON sso_assertion_ids
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- ── 11. Grant access to app role ─────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE ON roles TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON role_permissions TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_roles TO phantex_app;
GRANT SELECT, INSERT, UPDATE ON sso_configs TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_tokens TO phantex_app;
GRANT SELECT, INSERT, DELETE ON sso_assertion_ids TO phantex_app;
GRANT SELECT, INSERT, UPDATE ON permissions TO phantex_app;

-- ── 12. Seed built-in permissions ────────────────────────────────────────────

INSERT INTO permissions (resource, action, description) VALUES
    -- Agents
    ('agents', 'read', 'View agents and their status'),
    ('agents', 'write', 'Create, update, quarantine agents'),
    ('agents', 'delete', 'Delete agents'),
    -- Alerts
    ('alerts', 'read', 'View alerts'),
    ('alerts', 'acknowledge', 'Acknowledge/resolve alerts'),
    ('alerts', 'delete', 'Delete alerts'),
    -- Rules
    ('rules', 'read', 'View PRL rules'),
    ('rules', 'write', 'Create and update PRL rules'),
    ('rules', 'delete', 'Delete PRL rules'),
    -- Events
    ('events', 'read', 'View events and event details'),
    -- Dashboard
    ('dashboard', 'view', 'View dashboard stats'),
    -- Analytics
    ('analytics', 'view', 'View analytics and reports'),
    -- Investigation
    ('investigation', 'run', 'Run investigations'),
    -- Timeline
    ('timeline', 'read', 'View investigation timelines'),
    -- ML
    ('ml', 'view', 'View ML model status'),
    ('ml', 'manage', 'Train, deploy, configure ML models'),
    -- Trust
    ('trust', 'read', 'View trust graph'),
    ('trust', 'compute', 'Trigger trust computations'),
    -- Policies
    ('policies', 'read', 'View policies'),
    ('policies', 'write', 'Create and update policies'),
    -- Users
    ('users', 'read', 'View users'),
    ('users', 'manage', 'Create, update, deactivate users'),
    -- Integrations
    ('integrations', 'manage', 'Configure SIEM/notification integrations'),
    -- Notifications
    ('notifications', 'manage', 'Configure notification channels'),
    -- Exports
    ('exports', 'generate', 'Generate data exports'),
    -- Telemetry
    ('telemetry', 'read', 'View telemetry data'),
    -- Cloud Telemetry
    ('cloud_telemetry', 'manage', 'Manage cloud telemetry ingestion'),
    -- Agent Policy
    ('agent_policy', 'manage', 'Manage agent tags, exemptions, routing, maintenance'),
    -- WebSocket
    ('ws', 'subscribe', 'Subscribe to WebSocket alert feeds'),
    -- Auth management
    ('auth', 'manage', 'Manage auth settings, SSO, SCIM'),
    -- Tenant management (super-admin only)
    ('tenants', 'read', 'View tenant information'),
    ('tenants', 'manage', 'Create, update, suspend tenants')
ON CONFLICT (resource, action) DO NOTHING;

-- ── 13. Seed built-in roles for existing tenant ──────────────────────────────
-- Create admin/analyst/viewer built-in roles for the seed tenant.

DO $$
DECLARE
    _tenant_id UUID := 'a0000000-0000-0000-0000-000000000001';
    _admin_role_id UUID;
    _analyst_role_id UUID;
    _viewer_role_id UUID;
    _perm RECORD;
BEGIN
    -- Create built-in roles
    INSERT INTO roles (tenant_id, name, description, is_builtin)
    VALUES (_tenant_id, 'admin', 'Full administrative access', true)
    ON CONFLICT (tenant_id, name) DO NOTHING
    RETURNING id INTO _admin_role_id;

    IF _admin_role_id IS NULL THEN
        SELECT id INTO _admin_role_id FROM roles WHERE tenant_id = _tenant_id AND name = 'admin';
    END IF;

    INSERT INTO roles (tenant_id, name, description, is_builtin)
    VALUES (_tenant_id, 'analyst', 'Security analyst — investigate and respond', true)
    ON CONFLICT (tenant_id, name) DO NOTHING
    RETURNING id INTO _analyst_role_id;

    IF _analyst_role_id IS NULL THEN
        SELECT id INTO _analyst_role_id FROM roles WHERE tenant_id = _tenant_id AND name = 'analyst';
    END IF;

    INSERT INTO roles (tenant_id, name, description, is_builtin)
    VALUES (_tenant_id, 'viewer', 'Read-only dashboard access', true)
    ON CONFLICT (tenant_id, name) DO NOTHING
    RETURNING id INTO _viewer_role_id;

    IF _viewer_role_id IS NULL THEN
        SELECT id INTO _viewer_role_id FROM roles WHERE tenant_id = _tenant_id AND name = 'viewer';
    END IF;

    -- Admin gets ALL permissions
    FOR _perm IN SELECT id FROM permissions LOOP
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES (_admin_role_id, _perm.id)
        ON CONFLICT DO NOTHING;
    END LOOP;

    -- Analyst permissions
    FOR _perm IN
        SELECT id FROM permissions WHERE
            (resource, action) IN (
                ('agents','read'), ('agents','write'),
                ('alerts','read'), ('alerts','acknowledge'),
                ('rules','read'), ('rules','write'),
                ('events','read'),
                ('dashboard','view'),
                ('analytics','view'),
                ('investigation','run'),
                ('timeline','read'),
                ('ml','view'),
                ('trust','read'), ('trust','compute'),
                ('policies','read'),
                ('exports','generate'),
                ('telemetry','read'),
                ('agent_policy','manage'),
                ('ws','subscribe'),
                ('notifications','manage')
            )
    LOOP
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES (_analyst_role_id, _perm.id)
        ON CONFLICT DO NOTHING;
    END LOOP;

    -- Viewer permissions (read-only)
    FOR _perm IN
        SELECT id FROM permissions WHERE
            (resource, action) IN (
                ('agents','read'),
                ('alerts','read'),
                ('rules','read'),
                ('events','read'),
                ('dashboard','view'),
                ('analytics','view'),
                ('timeline','read'),
                ('trust','read'),
                ('policies','read'),
                ('telemetry','read'),
                ('ws','subscribe')
            )
    LOOP
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES (_viewer_role_id, _perm.id)
        ON CONFLICT DO NOTHING;
    END LOOP;

    -- Assign existing users to their corresponding built-in roles
    INSERT INTO user_roles (user_id, role_id)
    SELECT u.id,
           CASE u.role
               WHEN 'admin' THEN _admin_role_id
               WHEN 'analyst' THEN _analyst_role_id
               WHEN 'viewer' THEN _viewer_role_id
           END
    FROM users u WHERE u.tenant_id = _tenant_id
    ON CONFLICT DO NOTHING;
END $$;

COMMIT;
