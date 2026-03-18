-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 031: Change agent_id from UUID to TEXT
--
-- The sensor sends PAID (Phantex Agent ID) format strings like
-- "ptx-default-dev-f23bb1c5b0f9" which are NOT valid UUIDs.
-- The proto definition (events.proto) declares agent_id as string (PAID).
-- Later migrations (010, 028) already use TEXT for agent_id in newer tables.
-- This migration aligns the original tables.
-- ============================================================================

-- 1. Drop the FK constraint on alerts.agent_id → agents.id
--    (The PAID is not the agents.id UUID; it maps to agents.paid instead.)
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_agent_id_fkey;

-- 2. Change events.agent_id from UUID to TEXT
ALTER TABLE events ALTER COLUMN agent_id TYPE TEXT USING agent_id::TEXT;

-- 3. Change alerts.agent_id from UUID to TEXT
ALTER TABLE alerts ALTER COLUMN agent_id TYPE TEXT USING agent_id::TEXT;

-- 4. Add an index for joining alerts to agents via PAID
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts (agent_id);
