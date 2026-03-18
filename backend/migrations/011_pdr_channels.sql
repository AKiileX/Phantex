-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Phantex Migration 011: PDR Export Channels (L3)

BEGIN;

-- PDR (Phantex Data Relay) export channels: S3, Webhook, Kafka mirror
CREATE TABLE IF NOT EXISTS pdr_channels (
    id              TEXT PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    channel_type    TEXT NOT NULL CHECK (channel_type IN ('s3', 'webhook', 'kafka_mirror')),
    config          JSONB NOT NULL DEFAULT '{}',
    pii_fields      JSONB,           -- List of dotted-path fields to redact
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_pdr_channel_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_pdr_channels_tenant
    ON pdr_channels (tenant_id)
    WHERE enabled = true;

-- Auto-update timestamps
CREATE OR REPLACE FUNCTION update_pdr_channel_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_pdr_channel_updated ON pdr_channels;
CREATE TRIGGER trg_pdr_channel_updated
    BEFORE UPDATE ON pdr_channels
    FOR EACH ROW
    EXECUTE FUNCTION update_pdr_channel_timestamp();

-- Audit log for PDR config changes (reuse existing audit_log table)
-- No new table needed, just ensure we log from the router.

COMMIT;
