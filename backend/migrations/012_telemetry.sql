-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 012: Telemetry Export Configuration (Q3) + Cloud Ingestion (Q4)
--
-- Q3: Per-tenant telemetry export opt-in config
-- Q4: ClickHouse schema for cloud-side telemetry storage
-- ──────────────────────────────────────────────────────────────────────

-- ── Q3: Tenant Telemetry Config ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS telemetry_config (
    tenant_id   UUID        NOT NULL PRIMARY KEY,
    enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    dp_epsilon  DOUBLE PRECISION NOT NULL DEFAULT 2.0
        CHECK (dp_epsilon >= 0.1 AND dp_epsilon <= 10.0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  telemetry_config IS 'Q3: Per-tenant anonymized telemetry export opt-in configuration';
COMMENT ON COLUMN telemetry_config.enabled IS 'Opt-in flag — default FALSE (nothing exported unless explicitly enabled)';
COMMENT ON COLUMN telemetry_config.dp_epsilon IS 'Differential privacy epsilon for feature vector noise (lower = more privacy)';

-- Auto-update updated_at trigger
CREATE OR REPLACE FUNCTION trg_telemetry_config_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS telemetry_config_updated_at ON telemetry_config;
CREATE TRIGGER telemetry_config_updated_at
    BEFORE UPDATE ON telemetry_config
    FOR EACH ROW
    EXECUTE FUNCTION trg_telemetry_config_updated_at();

-- RLS: Tenants can only see/modify their own config
ALTER TABLE telemetry_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY telemetry_config_tenant_isolation ON telemetry_config
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

-- Grant access to the app role
GRANT SELECT, INSERT, UPDATE ON telemetry_config TO phantex_app;

-- ── Q3: Telemetry Export Audit Log ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS telemetry_export_log (
    id              BIGSERIAL       PRIMARY KEY,
    tenant_id       UUID            NOT NULL,
    batch_size      INT             NOT NULL,
    exported_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    destination     TEXT            NOT NULL,
    success         BOOLEAN         NOT NULL,
    error_message   TEXT,
    body_bytes      BIGINT
);

CREATE INDEX IF NOT EXISTS idx_telemetry_export_log_tenant
    ON telemetry_export_log (tenant_id, exported_at DESC);

COMMENT ON TABLE telemetry_export_log IS 'Q3: Audit log of telemetry export batches — tracks everything that leaves the network';

-- RLS: Tenants can only see their own export logs
ALTER TABLE telemetry_export_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY telemetry_export_log_tenant_isolation ON telemetry_export_log
    USING (tenant_id = current_setting('app.tenant_id')::UUID);

GRANT SELECT, INSERT ON telemetry_export_log TO phantex_app;
GRANT USAGE, SELECT ON SEQUENCE telemetry_export_log_id_seq TO phantex_app;

-- ══════════════════════════════════════════════════════════════════════
-- Q4: Cloud-side ClickHouse schema (for reference — not executed in PG)
-- ══════════════════════════════════════════════════════════════════════
--
-- This ClickHouse DDL is stored here for documentation. Deploy it on
-- the Phantex Cloud ClickHouse instance when Q4 goes live.
--
-- CREATE TABLE IF NOT EXISTS telemetry_vectors (
--     tenant_hash      FixedString(64),
--     feature_vector   Array(Float64),
--     attack_class     LowCardinality(String),
--     confidence       Float32,
--     event_timestamp  DateTime64(3),
--     ingested_at      DateTime64(3) DEFAULT now64(3),
--
--     -- Partition by month for efficient retention
--     INDEX idx_attack_class attack_class TYPE set(100) GRANULARITY 4,
--     INDEX idx_confidence confidence TYPE minmax GRANULARITY 4
-- ) ENGINE = MergeTree()
-- PARTITION BY toYYYYMM(event_timestamp)
-- ORDER BY (tenant_hash, event_timestamp)
-- TTL toDateTime(event_timestamp) + INTERVAL 90 DAY DELETE
-- SETTINGS index_granularity = 8192;
--
-- -- Materialized view for per-tenant daily aggregates
-- CREATE MATERIALIZED VIEW IF NOT EXISTS telemetry_daily_agg
-- ENGINE = SummingMergeTree()
-- PARTITION BY toYYYYMM(day)
-- ORDER BY (tenant_hash, attack_class, day)
-- AS SELECT
--     tenant_hash,
--     attack_class,
--     toDate(event_timestamp) AS day,
--     count() AS record_count,
--     avg(confidence) AS avg_confidence
-- FROM telemetry_vectors
-- GROUP BY tenant_hash, attack_class, day;
