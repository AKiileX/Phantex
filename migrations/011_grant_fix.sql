-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 011: Fix missing GRANT for phantex_app on tables added in later migrations.
-- Tables added in migrations 008-010 were missing GRANT for the phantex_app role,
-- causing "permission denied" errors at runtime.

BEGIN;

-- ── PDR Channels (L3) ───────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pdr_channels TO phantex_app;

-- ── Integrations (N1) ───────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE integrations TO phantex_app;

-- ── Notifications (N2) ──────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE notification_channels TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE notification_routing_rules TO phantex_app;

-- ── Agent Baselines (P) ─────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE agent_baselines TO phantex_app;

-- ── Event Partitions ─────────────────────────────────────────────────────────
-- Grant on all current monthly partitions + set default for future ones.
DO $$
DECLARE
    part TEXT;
BEGIN
    FOR part IN
        SELECT inhrelid::regclass::text
        FROM pg_inherits
        WHERE inhparent = 'events'::regclass
    LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I TO phantex_app', part);
    END LOOP;
END $$;

-- ── Default Privileges for Future Tables ─────────────────────────────────────
ALTER DEFAULT PRIVILEGES FOR ROLE phantex_admin IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO phantex_app;

-- ── Record migration ─────────────────────────────────────────────────────────
INSERT INTO schema_migrations (version, description)
VALUES (11, 'Fix missing GRANT for phantex_app on L3/N1/N2/P tables')
ON CONFLICT (version) DO NOTHING;

COMMIT;
