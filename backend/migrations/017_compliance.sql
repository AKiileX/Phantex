-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 017: Compliance Reports
-- Stores generated compliance reports with JSON data for historical tracking.

BEGIN;

CREATE TABLE IF NOT EXISTS compliance_reports (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID            NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    frameworks      TEXT[]          NOT NULL DEFAULT '{}',
    overall_score   NUMERIC(5,4)    NOT NULL DEFAULT 0.0,
    report_data     JSONB           NOT NULL DEFAULT '{}',
    created_by      UUID            REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

-- Index for listing reports by tenant, ordered by date
CREATE INDEX IF NOT EXISTS idx_compliance_reports_tenant_date
    ON compliance_reports (tenant_id, created_at DESC);

-- Index for drift detection (latest two by tenant)
CREATE INDEX IF NOT EXISTS idx_compliance_reports_tenant_score
    ON compliance_reports (tenant_id, overall_score);

-- RLS policy
ALTER TABLE compliance_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY compliance_reports_tenant_isolation ON compliance_reports
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Grant to application role
GRANT SELECT, INSERT ON compliance_reports TO phantex_app;

-- Scan configuration table (per-tenant)
CREATE TABLE IF NOT EXISTS compliance_scan_config (
    tenant_id           UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled             BOOLEAN     NOT NULL DEFAULT false,
    quick_scan_cron     TEXT        NOT NULL DEFAULT '0 6 * * *',
    full_scan_cron      TEXT        NOT NULL DEFAULT '0 2 * * 0',
    drift_threshold     NUMERIC(3,2) NOT NULL DEFAULT 0.05,
    last_quick_scan     TIMESTAMPTZ,
    last_full_scan      TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE compliance_scan_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY compliance_scan_config_tenant_isolation ON compliance_scan_config
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

GRANT SELECT, INSERT, UPDATE ON compliance_scan_config TO phantex_app;

COMMIT;
