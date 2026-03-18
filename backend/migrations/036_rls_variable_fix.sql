-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 036: RLS Policy Variable Fix + Missing RLS Enablement
-- ============================================================================
-- Problem 1: Migrations 012, 013, 014, 026, 027 used 'app.tenant_id' or
--            'app.current_tenant_id' in RLS policies, but the middleware
--            (database.py / tenant.py) sets 'app.current_tenant'.
--            Result: these RLS policies silently match nothing.
--
-- Problem 2: pdr_channels (011) and pdr_export_schedules (033) have
--            tenant_id columns but no RLS enabled.
--
-- Fix: DROP each broken policy and recreate with the correct variable name.
--      Enable RLS and add policies for the two missing tables.
-- ============================================================================

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════
-- Part 1: Fix variable name — 'app.tenant_id' → 'app.current_tenant'
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Migration 012: telemetry tables ─────────────────────────────────────────

DROP POLICY IF EXISTS telemetry_config_tenant_isolation ON telemetry_config;
CREATE POLICY telemetry_config_tenant_isolation ON telemetry_config
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS telemetry_export_log_tenant_isolation ON telemetry_export_log;
CREATE POLICY telemetry_export_log_tenant_isolation ON telemetry_export_log
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── Migration 013: policies tables ──────────────────────────────────────────

DROP POLICY IF EXISTS policies_tenant_isolation ON policies;
CREATE POLICY policies_tenant_isolation ON policies
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS policy_versions_tenant_isolation ON policy_versions;
CREATE POLICY policy_versions_tenant_isolation ON policy_versions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ═══════════════════════════════════════════════════════════════════════════
-- Part 2: Fix variable name — 'app.current_tenant_id' → 'app.current_tenant'
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Migration 014: agent tagging tables ─────────────────────────────────────

DROP POLICY IF EXISTS rule_exemptions_tenant ON rule_exemptions;
CREATE POLICY rule_exemptions_tenant ON rule_exemptions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS alert_routing_rules_tenant ON alert_routing_rules;
CREATE POLICY alert_routing_rules_tenant ON alert_routing_rules
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS maintenance_windows_tenant ON maintenance_windows;
CREATE POLICY maintenance_windows_tenant ON maintenance_windows
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ═══════════════════════════════════════════════════════════════════════════
-- Part 3: Fix variable name — 'app.tenant_id' → 'app.current_tenant'
--         (Migrations 026 + 027, these had 'true' fallback but wrong var)
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Migration 026: SOAR integration tables ──────────────────────────────────

DROP POLICY IF EXISTS soar_api_keys_tenant_isolation ON soar_api_keys;
CREATE POLICY soar_api_keys_tenant_isolation ON soar_api_keys
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS soar_webhook_subs_tenant_isolation ON soar_webhook_subs;
CREATE POLICY soar_webhook_subs_tenant_isolation ON soar_webhook_subs
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS soar_webhook_logs_tenant_isolation ON soar_webhook_logs;
CREATE POLICY soar_webhook_logs_tenant_isolation ON soar_webhook_logs
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS soar_action_log_tenant_isolation ON soar_action_log;
CREATE POLICY soar_action_log_tenant_isolation ON soar_action_log
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS soar_integrations_tenant_isolation ON soar_integrations;
CREATE POLICY soar_integrations_tenant_isolation ON soar_integrations
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── Migration 027: deception technology tables ──────────────────────────────

DROP POLICY IF EXISTS decoy_agents_tenant_isolation ON decoy_agents;
CREATE POLICY decoy_agents_tenant_isolation ON decoy_agents
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS canary_mcp_tenant_isolation ON canary_mcp_servers;
CREATE POLICY canary_mcp_tenant_isolation ON canary_mcp_servers
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS canary_tokens_tenant_isolation ON canary_tokens;
CREATE POLICY canary_tokens_tenant_isolation ON canary_tokens
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS honeypot_events_tenant_isolation ON honeypot_events;
CREATE POLICY honeypot_events_tenant_isolation ON honeypot_events
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS honeypot_events_insert_only ON honeypot_events;
CREATE POLICY honeypot_events_insert_only ON honeypot_events
    FOR INSERT WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS deception_stats_tenant_isolation ON deception_stats;
CREATE POLICY deception_stats_tenant_isolation ON deception_stats
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ═══════════════════════════════════════════════════════════════════════════
-- Part 4: Add missing RLS on pdr_channels and pdr_export_schedules
-- ═══════════════════════════════════════════════════════════════════════════

-- ── pdr_channels (migration 011 — RLS never enabled) ────────────────────────

ALTER TABLE pdr_channels ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pdr_channels_tenant_isolation ON pdr_channels;
CREATE POLICY pdr_channels_tenant_isolation ON pdr_channels
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── pdr_export_schedules (migration 033 — RLS never enabled) ────────────────

ALTER TABLE pdr_export_schedules ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pdr_export_schedules_tenant_isolation ON pdr_export_schedules;
CREATE POLICY pdr_export_schedules_tenant_isolation ON pdr_export_schedules
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ═══════════════════════════════════════════════════════════════════════════
-- Migration tracking
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO schema_migrations (version, description)
VALUES ('036', 'Fix RLS policy variable names (app.current_tenant) + enable RLS on pdr_channels/pdr_export_schedules')
ON CONFLICT (version) DO NOTHING;

COMMIT;
