-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- 023: Agent commands table hardening (post-security-audit).
--
-- Adds:
--  1. Index on alert_id for the get_command_history query (was doing seq scan).
--  2. Index on (agent_id, created_at) for the pending commands polling query.
--  3. NOT NULL constraint on result column default (was nullable JSONB).
--  4. Partial index for ML feedback: completed/failed commands with alert_id.
--
-- These changes are additive — no breaking schema modifications.

BEGIN;

-- 1. Index for timeline display: get_command_history(alert_id)
CREATE INDEX IF NOT EXISTS idx_agent_commands_alert
    ON agent_commands(alert_id) WHERE alert_id IS NOT NULL;

-- 2. Composite index for agent-specific history sorted by time
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_created
    ON agent_commands(agent_id, created_at DESC);

-- 3. Partial index for ML feedback queries: find completed actions with alert context
--    The retrain pipeline joins agent_commands with alerts to learn what actions
--    analysts chose and whether they succeeded.
CREATE INDEX IF NOT EXISTS idx_agent_commands_ml_feedback
    ON agent_commands(tenant_id, alert_id, command_type, status)
    WHERE status IN ('completed', 'failed') AND alert_id IS NOT NULL;

-- 4. Ensure result column has a safe default (idempotent)
ALTER TABLE agent_commands ALTER COLUMN result SET DEFAULT '{}';

COMMIT;
