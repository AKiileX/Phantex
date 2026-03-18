-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 020: Add host enrichment fields to agents table.
-- Adds IP address, hostname, OS type/version, and resource usage columns
-- for richer XDR-grade agent inventory display.
-- ──────────────────────────────────────────────────────────────────────

BEGIN;

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS ip_address    TEXT,
    ADD COLUMN IF NOT EXISTS hostname      TEXT,
    ADD COLUMN IF NOT EXISTS os_type       TEXT,
    ADD COLUMN IF NOT EXISTS os_version    TEXT,
    ADD COLUMN IF NOT EXISTS cpu_usage_pct DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS memory_mb     INTEGER;

-- Constrain os_type to known values (nullable)
ALTER TABLE agents
    ADD CONSTRAINT chk_agents_os_type
    CHECK (os_type IS NULL OR os_type IN ('windows', 'linux', 'macos'));

-- Index for filtering agents by OS type / IP
CREATE INDEX IF NOT EXISTS ix_agents_os_type    ON agents (os_type)    WHERE os_type IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_agents_ip_address ON agents (ip_address) WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_agents_hostname   ON agents (hostname)   WHERE hostname IS NOT NULL;

COMMENT ON COLUMN agents.ip_address    IS 'Host machine primary IP address reported by sensor';
COMMENT ON COLUMN agents.hostname      IS 'Host machine hostname reported by sensor';
COMMENT ON COLUMN agents.os_type       IS 'Operating system: windows, linux, macos';
COMMENT ON COLUMN agents.os_version    IS 'OS version string (e.g. Windows 11 23H2, Ubuntu 24.04)';
COMMENT ON COLUMN agents.cpu_usage_pct IS 'Last observed CPU usage percentage of agent process';
COMMENT ON COLUMN agents.memory_mb     IS 'Last observed RSS memory in MB of agent process';

COMMIT;
