-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex ClickHouse — Pre-Aggregated Tables
--
-- Materialized views that maintain hourly and daily rollups.
-- Dashboard queries hit these instead of scanning the full events table.
-- ============================================================================

-- ── Hourly event counts by type ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS phantex.events_hourly
(
    tenant_id    UUID,
    agent_id     String,
    event_type   LowCardinality(String),
    severity     LowCardinality(String),
    hour         DateTime,
    event_count  UInt64,
    bytes_sent   UInt64,
    bytes_recv   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, agent_id, event_type, severity, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.events_hourly_mv
TO phantex.events_hourly
AS SELECT
    tenant_id,
    agent_id,
    event_type,
    severity,
    toStartOfHour(timestamp) AS hour,
    count()                  AS event_count,
    sum(ifNull(bytes_sent, 0)) AS bytes_sent,
    sum(ifNull(bytes_recv, 0)) AS bytes_recv
FROM phantex.events
GROUP BY tenant_id, agent_id, event_type, severity, hour;

-- ── Daily event counts ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS phantex.events_daily
(
    tenant_id    UUID,
    event_type   LowCardinality(String),
    severity     LowCardinality(String),
    day          Date,
    event_count  UInt64,
    unique_agents UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, event_type, severity, day)
TTL day + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.events_daily_mv
TO phantex.events_daily
AS SELECT
    tenant_id,
    event_type,
    severity,
    toDate(timestamp)                AS day,
    count()                          AS event_count,
    uniqExact(agent_id)              AS unique_agents
FROM phantex.events
GROUP BY tenant_id, event_type, severity, day;

-- ── Hourly attack breakdown ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS phantex.attack_hourly
(
    tenant_id    UUID,
    attack_class LowCardinality(String),
    severity     LowCardinality(String),
    hour         DateTime,
    alert_count  UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, attack_class, severity, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.attack_hourly_mv
TO phantex.attack_hourly
AS SELECT
    tenant_id,
    attack_class,
    severity,
    toStartOfHour(timestamp) AS hour,
    count()                  AS alert_count
FROM phantex.events
WHERE attack_class IS NOT NULL
GROUP BY tenant_id, attack_class, severity, hour;
