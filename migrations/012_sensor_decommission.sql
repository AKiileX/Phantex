-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 012: Add sensor decommission support.
-- - Expands status CHECK to include 'decommissioned'
-- - Adds decommission audit trail columns

BEGIN;

-- Drop old CHECK and replace with expanded one
ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_status;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_status
  CHECK (status IN ('online', 'degraded', 'offline', 'decommissioned'));

-- Decommission audit trail
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS decommissioned_at TIMESTAMPTZ;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS decommissioned_by TEXT;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS decommission_reason TEXT;

COMMIT;
