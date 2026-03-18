-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 030: Sensors Fleet Management
--
-- Adds the sensors table for tracking deployed sensor instances.
-- Each sensor registers on startup via the gateway and sends periodic
-- heartbeats with health metrics. This table persists that data so the
-- backend API and dashboard can surface fleet health.
--
-- Security:
--   - RLS enabled (tenant isolation)
--   - phantex_app gets SELECT + INSERT + UPDATE only (no DELETE)
--   - sensor_id is TEXT (not user-controlled UUID) — validated with regex
--   - CHECK constraints on status values

BEGIN;

-- ─── 1. Sensors Table ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sensors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id       TEXT NOT NULL,                -- sensor-assigned identifier (validated by gateway)
    hostname        TEXT,
    ip_address      TEXT,
    kernel          TEXT,                          -- kernel version (uname -r)
    arch            TEXT,                          -- CPU architecture (amd64, arm64)
    version         TEXT,                          -- sensor binary version
    os_type         TEXT,                          -- linux, windows, macos
    status          TEXT NOT NULL DEFAULT 'online',

    -- Health metrics (updated on each heartbeat)
    probes_loaded   INT NOT NULL DEFAULT 0,
    probes_total    INT NOT NULL DEFAULT 0,
    events_read     BIGINT NOT NULL DEFAULT 0,
    events_sent     BIGINT NOT NULL DEFAULT 0,
    events_dropped  BIGINT NOT NULL DEFAULT 0,
    parse_errors    BIGINT NOT NULL DEFAULT 0,
    agents_tracked  INT NOT NULL DEFAULT 0,
    uptime_seconds  BIGINT NOT NULL DEFAULT 0,
    cpu_percent     REAL,
    memory_bytes    BIGINT,
    buffer_used     BIGINT NOT NULL DEFAULT 0,

    -- Timestamps
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Decommission audit trail
    decommissioned_at     TIMESTAMPTZ,
    decommissioned_by     TEXT,
    decommission_reason   TEXT,

    -- Metadata
    tags            JSONB NOT NULL DEFAULT '{}',
    metadata        JSONB NOT NULL DEFAULT '{}',

    -- Constraints
    CONSTRAINT uq_sensors_tenant_sensor UNIQUE (tenant_id, sensor_id),
    CONSTRAINT chk_sensors_status CHECK (status IN ('online', 'degraded', 'offline', 'decommissioned'))
);

COMMENT ON TABLE sensors IS 'Deployed sensor instances. Registered via gateway, updated by heartbeats.';
COMMENT ON COLUMN sensors.sensor_id IS 'Sensor-assigned ID (e.g. sensor-wsl-dev-001). Unique per tenant.';
COMMENT ON COLUMN sensors.status IS 'online = heartbeat within 2 min, degraded = heartbeat within 5 min, offline = stale.';

-- ─── 2. Indexes ──────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_sensors_tenant_id ON sensors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sensors_status ON sensors(status);
CREATE INDEX IF NOT EXISTS idx_sensors_last_heartbeat ON sensors(last_heartbeat DESC);

-- ─── 3. Row-Level Security ───────────────────────────────────────────────────

ALTER TABLE sensors ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_sensors ON sensors
    FOR ALL TO phantex_app
    USING (tenant_id::text = current_setting('app.current_tenant', true));

-- ─── 4. App Role Grants ─────────────────────────────────────────────────────
-- SELECT + INSERT + UPDATE only (no DELETE — soft-delete via status='offline')

GRANT SELECT, INSERT, UPDATE ON sensors TO phantex_app;

-- ─── 5. Migration Tracking ────────────────────────────────────────────────────

INSERT INTO schema_migrations (version, description)
VALUES ('030', 'sensors fleet management')
ON CONFLICT (version) DO NOTHING;

COMMIT;
