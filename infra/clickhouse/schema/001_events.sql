-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex ClickHouse — Events Table
--
-- Primary storage for high-volume event analytics.
-- Optimised for time-range + tenant + agent queries.
-- ============================================================================

CREATE DATABASE IF NOT EXISTS phantex;

CREATE TABLE IF NOT EXISTS phantex.events
(
    event_id      UUID,
    tenant_id     UUID,
    agent_id      String        DEFAULT '',   -- PAID slug, not UUID
    sensor_id     String        DEFAULT '',
    event_type    LowCardinality(String),
    attack_class  LowCardinality(Nullable(String)),
    severity      LowCardinality(String)     DEFAULT 'info',
    payload       String        DEFAULT '{}',   -- JSON blob
    source_ip     Nullable(IPv4),
    dest_ip       Nullable(IPv4),
    dest_port     Nullable(UInt16),
    bytes_sent    Nullable(UInt64),
    bytes_recv    Nullable(UInt64),
    file_path     Nullable(String),
    tool_name     Nullable(String),
    duration_ms   Nullable(UInt32),
    framework     LowCardinality(String)     DEFAULT '',
    timestamp     DateTime64(3, 'UTC'),
    ingested_at   DateTime64(3, 'UTC')       DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, agent_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Secondary indexes for common filter patterns
ALTER TABLE phantex.events ADD INDEX IF NOT EXISTS idx_event_type event_type TYPE set(100) GRANULARITY 4;
ALTER TABLE phantex.events ADD INDEX IF NOT EXISTS idx_severity severity TYPE set(10) GRANULARITY 4;
ALTER TABLE phantex.events ADD INDEX IF NOT EXISTS idx_attack_class attack_class TYPE set(100) GRANULARITY 4;
