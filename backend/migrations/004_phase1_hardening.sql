-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ─── Phase 1 Hardening Migration ────────────────────────────────────────────
-- Adds RLS to tenants table and other security improvements.
-- Applied after 003_auth_hardening.sql.

-- 1. Enable RLS on tenants table
-- phantex_app can only see their own tenant row.
BEGIN;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_tenants ON tenants;
CREATE POLICY tenant_isolation_tenants ON tenants
    FOR ALL TO phantex_app
    USING (id::text = current_setting('app.current_tenant', true));

-- 2. Add index for failed login audit queries  
CREATE INDEX IF NOT EXISTS idx_audit_log_action_type
    ON audit_log (action) WHERE action IN ('user.login_failed', 'user.login', 'user.logout');

-- Record migration
INSERT INTO schema_migrations (version, description)
VALUES ('004', 'Phase 1 hardening: RLS on tenants, audit log index')
ON CONFLICT (version) DO NOTHING;

COMMIT;
