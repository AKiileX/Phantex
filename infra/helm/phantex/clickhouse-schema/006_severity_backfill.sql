-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex ClickHouse — Severity Normalization Backfill
--
-- Fixes:
--   1. Normalize all existing severity values to lowercase
--      (ch_writer now inserts .lower() but existing data has uppercase)
--   2. Repopulate MVs that depend on lowercase severity by re-inserting
--      affected rows after the UPDATE.
--
-- This is safe to run multiple times (idempotent).
-- ============================================================================

-- ── 1. Normalize severity to lowercase ──────────────────────────────────────

ALTER TABLE phantex.events
UPDATE severity = lower(severity)
WHERE severity != lower(severity);

-- Wait for mutations to complete before proceeding
-- (In ClickHouse, ALTER TABLE UPDATE is asynchronous)
-- The MVs will pick up new inserts with correct lowercase severity.
-- For existing aggregated data: drop and repopulate the MVs that
-- depend on severity case sensitivity.

-- ── 2. Recreate agent_risk_daily MV (uses countIf severity = 'critical' etc) ──

DROP TABLE IF EXISTS phantex.agent_risk_daily_mv;
DROP TABLE IF EXISTS phantex.agent_risk_daily;

CREATE TABLE IF NOT EXISTS phantex.agent_risk_daily
(
    tenant_id     UUID,
    agent_id      String,
    day           Date,
    total_events  UInt64,
    critical_count UInt64,
    high_count    UInt64,
    medium_count  UInt64,
    low_count     UInt64,
    attack_count  UInt64,
    unique_attack_classes UInt64,
    bytes_sent    UInt64,
    bytes_recv    UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, agent_id, day)
TTL day + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.agent_risk_daily_mv
TO phantex.agent_risk_daily
AS SELECT
    tenant_id,
    agent_id,
    toDate(timestamp)                   AS day,
    count()                             AS total_events,
    countIf(severity = 'critical')      AS critical_count,
    countIf(severity = 'high')          AS high_count,
    countIf(severity = 'medium')        AS medium_count,
    countIf(severity = 'low')           AS low_count,
    countIf(attack_class IS NOT NULL)   AS attack_count,
    uniqExactIf(attack_class, attack_class IS NOT NULL) AS unique_attack_classes,
    sum(ifNull(bytes_sent, 0))          AS bytes_sent,
    sum(ifNull(bytes_recv, 0))          AS bytes_recv
FROM phantex.events
GROUP BY tenant_id, agent_id, day;

-- Backfill from existing data
INSERT INTO phantex.agent_risk_daily
SELECT
    tenant_id,
    agent_id,
    toDate(timestamp)                   AS day,
    count()                             AS total_events,
    countIf(severity = 'critical')      AS critical_count,
    countIf(severity = 'high')          AS high_count,
    countIf(severity = 'medium')        AS medium_count,
    countIf(severity = 'low')           AS low_count,
    countIf(attack_class IS NOT NULL)   AS attack_count,
    uniqExactIf(attack_class, attack_class IS NOT NULL) AS unique_attack_classes,
    sum(ifNull(bytes_sent, 0))          AS bytes_sent,
    sum(ifNull(bytes_recv, 0))          AS bytes_recv
FROM phantex.events
GROUP BY tenant_id, agent_id, day;

-- ── 3. Recreate severity_daily MV ──────────────────────────────────────────

DROP TABLE IF EXISTS phantex.severity_daily_mv;
DROP TABLE IF EXISTS phantex.severity_daily;

CREATE TABLE IF NOT EXISTS phantex.severity_daily
(
    tenant_id    UUID,
    severity     LowCardinality(String),
    day          Date,
    event_count  UInt64,
    unique_agents UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, severity, day)
TTL day + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.severity_daily_mv
TO phantex.severity_daily
AS SELECT
    tenant_id,
    severity,
    toDate(timestamp)       AS day,
    count()                 AS event_count,
    uniqExact(agent_id)     AS unique_agents
FROM phantex.events
GROUP BY tenant_id, severity, day;

-- Backfill
INSERT INTO phantex.severity_daily
SELECT
    tenant_id,
    severity,
    toDate(timestamp)       AS day,
    count()                 AS event_count,
    uniqExact(agent_id)     AS unique_agents
FROM phantex.events
GROUP BY tenant_id, severity, day;
