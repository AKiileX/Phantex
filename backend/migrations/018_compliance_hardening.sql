-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 018: Compliance Hardening (Block T Security Audit)
-- T-8: Add DELETE grant for report retention/purge
-- T-1: Ensure scan_config upsert works properly

BEGIN;

-- T-8: Allow application to delete old compliance reports (data retention)
GRANT DELETE ON compliance_reports TO phantex_app;

-- Ensure the upsert ON CONFLICT works — primary key already exists on tenant_id
-- Add updated_at default trigger if missing
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'compliance_scan_config' AND column_name = 'updated_at'
  ) THEN
    ALTER TABLE compliance_scan_config ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
  END IF;
END $$;

COMMIT;
