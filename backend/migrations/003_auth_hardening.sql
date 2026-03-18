-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex — Migration 003: Auth Hardening
--
-- Adds account lockout fields to users table:
--   - failed_login_attempts: counter for consecutive failed logins
--   - locked_until: timestamp when account lockout expires
--
-- Run AFTER 002_bootstrap.sql:
--   psql -U phantex_admin -d phantex -f 003_auth_hardening.sql
-- ============================================================================

BEGIN;

-- Check if migration already applied
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM schema_migrations WHERE version = '003') THEN
        RAISE NOTICE 'Migration 003 already applied — skipping';
        RETURN;
    END IF;

    -- ── Add lockout fields ───────────────────────────────────────────────
    ALTER TABLE users
        ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

    RAISE NOTICE 'Added failed_login_attempts and locked_until to users';

    -- ── Grant UPDATE on new columns to phantex_app ───────────────────────
    -- phantex_app already has UPDATE on users; new columns inherited.

    -- ── Record migration ─────────────────────────────────────────────────
    INSERT INTO schema_migrations (version, description)
    VALUES ('003', 'Auth hardening — account lockout fields on users');

    RAISE NOTICE 'Migration 003 applied successfully';
END $$;

COMMIT;
