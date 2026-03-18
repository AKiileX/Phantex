-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Phantex Migration 009: Notification Channels + Routing Rules (N2)

BEGIN;

-- Notification channels (Slack, PagerDuty, Webhook, Email)
CREATE TABLE IF NOT EXISTS notification_channels (
    id              TEXT PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    channel_type    TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    config          JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    rate_limit_per_min INTEGER NOT NULL DEFAULT 60,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_notif_channel_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_notif_channels_tenant
    ON notification_channels (tenant_id)
    WHERE enabled = true;

-- Routing rules (per tenant, one row with ordered rule list)
CREATE TABLE IF NOT EXISTS notification_routing_rules (
    tenant_id   UUID PRIMARY KEY,
    rules       JSONB NOT NULL DEFAULT '[]',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Auto-update timestamps
CREATE OR REPLACE FUNCTION update_notif_channel_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notif_channel_updated ON notification_channels;
CREATE TRIGGER trg_notif_channel_updated
    BEFORE UPDATE ON notification_channels
    FOR EACH ROW
    EXECUTE FUNCTION update_notif_channel_timestamp();

-- Row-level security
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_routing_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY notif_channels_tenant_isolation ON notification_channels
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY notif_rules_tenant_isolation ON notification_routing_rules
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMIT;
