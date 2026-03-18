-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 035: Add 'stale' and 'offline' to agent status constraint
-- Enables automatic agent staleness detection (5 min → stale, 15 min → offline)
-- Previously agents stayed "active" forever regardless of last_seen age.

BEGIN;

-- Drop the old constraint and recreate with new values
ALTER TABLE agents DROP CONSTRAINT IF EXISTS chk_agents_status;
ALTER TABLE agents ADD CONSTRAINT chk_agents_status
    CHECK (status IN ('active', 'stale', 'offline', 'terminated', 'quarantined'));

-- Track migration
INSERT INTO schema_migrations (version, description)
VALUES ('035', 'Add stale and offline to agent status constraint')
ON CONFLICT (version) DO NOTHING;

COMMIT;
