-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Phantex Migration 033: Scheduled PDR Exports

BEGIN;

CREATE TABLE IF NOT EXISTS pdr_export_schedules (
    id                TEXT PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    channel_id        TEXT NOT NULL REFERENCES pdr_channels(id) ON DELETE CASCADE,
    name              TEXT NOT NULL DEFAULT '',
    cron_schedule     TEXT NOT NULL,
    lookback_minutes  INTEGER NOT NULL DEFAULT 60 CHECK (lookback_minutes BETWEEN 1 AND 10080),
    event_types       JSONB,
    max_events        INTEGER NOT NULL DEFAULT 1000 CHECK (max_events BETWEEN 1 AND 10000),
    enabled           BOOLEAN NOT NULL DEFAULT true,
    next_run_at       TIMESTAMPTZ,
    last_run_at       TIMESTAMPTZ,
    last_run_status   TEXT,
    last_run_message  TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_pdr_export_schedule_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_pdr_export_schedules_tenant_enabled_next
    ON pdr_export_schedules (tenant_id, next_run_at)
    WHERE enabled = true;

CREATE OR REPLACE FUNCTION update_pdr_export_schedule_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_pdr_export_schedule_updated ON pdr_export_schedules;
CREATE TRIGGER trg_pdr_export_schedule_updated
    BEFORE UPDATE ON pdr_export_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_pdr_export_schedule_timestamp();

-- ─── App Role Grants ────────────────────────────────────────────────────────
-- SELECT + INSERT + UPDATE + DELETE (schedules can be removed by operators)

GRANT SELECT, INSERT, UPDATE, DELETE ON pdr_export_schedules TO phantex_app;

-- ─── Migration Tracking ─────────────────────────────────────────────────────

INSERT INTO schema_migrations (version, description)
VALUES ('033', 'scheduled PDR exports')
ON CONFLICT (version) DO NOTHING;

COMMIT;