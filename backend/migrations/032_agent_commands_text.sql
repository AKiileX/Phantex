-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Migration 032: Align agent_commands.agent_id to TEXT (PAID format)
--
-- agent_commands.agent_id stores the PAID string from the sensor
-- (e.g. "ptx-default-dev-fc66c4b32052"), not a UUID.
-- This aligns with migration 031 which did the same for events/alerts.
-- ============================================================================

ALTER TABLE agent_commands ALTER COLUMN agent_id TYPE TEXT USING agent_id::TEXT;
