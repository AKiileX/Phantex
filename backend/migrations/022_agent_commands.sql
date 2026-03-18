-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- 022: Agent command queue for SOC response actions.
--
-- When an analyst triggers a response action (isolate, block IP, kill process, etc.),
-- the command is queued here. The gateway polls for pending commands and relays them
-- to the target sensor via heartbeat responses or the event stream.
--
-- Command lifecycle: pending → dispatched → acknowledged → completed | failed
--
-- The ML pipeline reads analyst actions from this table + audit_log to learn
-- which alerts warrant which response actions.

BEGIN;

CREATE TABLE IF NOT EXISTS agent_commands (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    agent_id        UUID NOT NULL,                          -- target agent/sensor
    alert_id        UUID REFERENCES alerts(id),             -- originating alert (nullable)
    command_type    TEXT NOT NULL,                           -- isolate_host, block_ip, kill_process, etc.
    parameters      JSONB NOT NULL DEFAULT '{}',            -- action-specific params
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'dispatched', 'acknowledged', 'completed', 'failed', 'cancelled')),
    issued_by       UUID REFERENCES users(id),              -- analyst who ordered the action
    reason          TEXT DEFAULT '',                         -- analyst justification
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at   TIMESTAMPTZ,                            -- when sent to gateway
    completed_at    TIMESTAMPTZ,                            -- when sensor acknowledged
    result          JSONB DEFAULT '{}'                       -- execution result from sensor
);

-- Index for gateway polling: find pending commands for a tenant
CREATE INDEX IF NOT EXISTS idx_agent_commands_pending
    ON agent_commands(tenant_id, status) WHERE status IN ('pending', 'dispatched');

-- Index for agent-specific lookup
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent
    ON agent_commands(agent_id, status);

-- RLS: tenant isolation
ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_commands_tenant_read ON agent_commands
    FOR SELECT USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE POLICY agent_commands_tenant_insert ON agent_commands
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE POLICY agent_commands_tenant_update ON agent_commands
    FOR UPDATE USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Grant to app role
GRANT SELECT, INSERT, UPDATE ON agent_commands TO phantex_app;

COMMIT;
