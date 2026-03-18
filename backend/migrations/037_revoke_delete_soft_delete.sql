-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 037: Revoke DELETE from phantex_app, enforce soft-delete pattern
--
-- The README claims "App role has no DROP/ALTER/DELETE permission — data
-- preserved for audit". Phase 2+ migrations granted DELETE on feature tables.
-- This migration corrects that by:
--   1. Adding deleted_at columns for soft-delete support
--   2. Revoking DELETE from phantex_app on ALL affected tables
--   3. Adding partial indexes for query performance (WHERE deleted_at IS NULL)
--
-- Idempotent: all operations use IF NOT EXISTS / safe REVOKE.

BEGIN;

-- ── 1. Add soft-delete columns ──────────────────────────────────────────────

-- role_permissions (015_enterprise_auth)
ALTER TABLE role_permissions
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- user_roles (015_enterprise_auth)
ALTER TABLE user_roles
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- scim_tokens (015_enterprise_auth)
ALTER TABLE scim_tokens
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- sso_assertion_ids (015_enterprise_auth)
ALTER TABLE sso_assertion_ids
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- roles (016_block_s_hardening)
ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- compliance_reports (018_compliance_hardening)
ALTER TABLE compliance_reports
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- mcp_servers (019_mcp_supply_chain)
ALTER TABLE mcp_servers
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- mcp_scan_results (019_mcp_supply_chain)
ALTER TABLE mcp_scan_results
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- mcp_anomalies (019_mcp_supply_chain)
ALTER TABLE mcp_anomalies
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- escalation_state (025_response_engine)
ALTER TABLE escalation_state
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- soar_api_keys (026_soar_integration)
ALTER TABLE soar_api_keys
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- soar_webhook_subs (026_soar_integration)
ALTER TABLE soar_webhook_subs
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- soar_integrations (026_soar_integration)
ALTER TABLE soar_integrations
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- decoy_agents (027_deception_technology)
ALTER TABLE decoy_agents
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- canary_mcp_servers (027_deception_technology)
ALTER TABLE canary_mcp_servers
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- canary_tokens (027_deception_technology)
ALTER TABLE canary_tokens
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;

-- pdr_export_schedules (033_pdr_export_schedules)
ALTER TABLE pdr_export_schedules
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ DEFAULT NULL;


-- ── 2. Partial indexes for soft-delete performance ──────────────────────────
-- Queries that filter deleted_at IS NULL benefit from these partial indexes.

CREATE INDEX IF NOT EXISTS idx_role_permissions_active
    ON role_permissions (role_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_roles_active
    ON user_roles (user_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_active
    ON roles (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_servers_active
    ON mcp_servers (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_soar_webhook_subs_active
    ON soar_webhook_subs (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_soar_integrations_active
    ON soar_integrations (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_decoy_agents_active
    ON decoy_agents (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_canary_mcp_servers_active
    ON canary_mcp_servers (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_canary_tokens_active
    ON canary_tokens (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_pdr_export_schedules_active
    ON pdr_export_schedules (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_escalation_state_active
    ON escalation_state (tenant_id, agent_id) WHERE deleted_at IS NULL;


-- ── 3. Revoke DELETE from phantex_app on ALL affected tables ────────────────

REVOKE DELETE ON role_permissions FROM phantex_app;
REVOKE DELETE ON user_roles FROM phantex_app;
REVOKE DELETE ON scim_tokens FROM phantex_app;
REVOKE DELETE ON sso_assertion_ids FROM phantex_app;
REVOKE DELETE ON roles FROM phantex_app;
REVOKE DELETE ON compliance_reports FROM phantex_app;
REVOKE DELETE ON mcp_servers FROM phantex_app;
REVOKE DELETE ON mcp_scan_results FROM phantex_app;
REVOKE DELETE ON mcp_anomalies FROM phantex_app;
REVOKE DELETE ON escalation_state FROM phantex_app;
REVOKE DELETE ON soar_api_keys FROM phantex_app;
REVOKE DELETE ON soar_webhook_subs FROM phantex_app;
REVOKE DELETE ON soar_integrations FROM phantex_app;
REVOKE DELETE ON decoy_agents FROM phantex_app;
REVOKE DELETE ON canary_mcp_servers FROM phantex_app;
REVOKE DELETE ON canary_tokens FROM phantex_app;
REVOKE DELETE ON pdr_export_schedules FROM phantex_app;

COMMIT;
