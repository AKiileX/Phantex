-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex — Bootstrap Data (runs in ALL environments)
--
-- Creates the minimum required data for Phantex to operate:
--   - 1 default tenant
--   - 1 admin user (password: "changeme" — forced to change on first login)
--
-- This migration runs in both dev and production. The admin user password
-- is intentionally weak because the must_change_password flag (migration 029)
-- forces an immediate password change on first login.
--
-- Run AFTER 001_initial_schema.sql.
-- Idempotent: uses ON CONFLICT DO NOTHING.
-- ============================================================================

BEGIN;

DO $$
DECLARE
    v_tenant_id  UUID := 'a0000000-0000-0000-0000-000000000001';
    v_admin_id   UUID := 'b0000000-0000-0000-0000-000000000001';
BEGIN

    -- ─── Default Tenant ──────────────────────────────────────────────────
    INSERT INTO tenants (id, name, slug, plan, settings) VALUES
    (v_tenant_id, 'Phantex', 'default-tenant', 'enterprise',
     '{"max_agents": 100, "retention_days": 90}')
    ON CONFLICT (id) DO NOTHING;

    RAISE NOTICE 'Bootstrap: default tenant created';

    -- ─── Admin User ──────────────────────────────────────────────────────
    -- Password "changeme" — user MUST change on first login (migration 029).
    INSERT INTO users (id, tenant_id, email, password_hash, role, name) VALUES
    (v_admin_id, v_tenant_id, 'admin@phantex.dev',
     crypt('changeme', gen_salt('bf', 12)),
     'admin', 'Admin')
    ON CONFLICT (id) DO NOTHING;

    RAISE NOTICE 'Bootstrap: admin user created (admin@phantex.dev)';

END
$$;

-- Mark migration
INSERT INTO schema_migrations (version, description)
VALUES ('002', 'Bootstrap: default tenant + admin user')
ON CONFLICT (version) DO UPDATE SET description = 'Bootstrap: default tenant + admin user';

COMMIT;
