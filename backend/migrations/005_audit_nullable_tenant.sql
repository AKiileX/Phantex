-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ─── 005: Make audit_log.tenant_id nullable ─────────────────────────────────
-- Failed login attempts are logged before we know the tenant (user doesn't
-- exist or hasn't authenticated yet). tenant_id must be nullable so the
-- audit INSERT succeeds without a tenant context.
--
-- RLS on audit_log already handles visibility: rows with NULL tenant_id are
-- invisible to phantex_app (NULL != any current_setting), so they can only
-- be read by the admin role. This is the desired behavior.
--
-- Also update the RLS policy to explicitly handle NULL tenant_id rows:
-- allow the admin role to see them, keep phantex_app isolated.

BEGIN;

-- Drop NOT NULL constraint on tenant_id
ALTER TABLE audit_log ALTER COLUMN tenant_id DROP NOT NULL;

-- Update the RLS policy to also show null-tenant rows to the admin (optional,
-- admin already bypasses RLS). We update the phantex_app policy to be explicit:
DROP POLICY IF EXISTS tenant_isolation_audit ON audit_log;
CREATE POLICY tenant_isolation_audit ON audit_log
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- Record migration
INSERT INTO schema_migrations (version, description)
VALUES ('005', 'Make audit_log.tenant_id nullable for pre-auth audit entries');

COMMIT;
