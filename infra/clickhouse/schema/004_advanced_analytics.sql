-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex ClickHouse — Advanced Analytics Materialized Views
--
-- 10 new MVs for the AC dashboard pages:
--   1. attack_class_daily    — daily attack-class trend
--   2. tool_usage_hourly     — per-tool call heatmap
--   3. agent_risk_daily      — per-agent risk timeline
--   4. geo_daily             — geographic destination distribution
--   5. rule_hits_daily       — rule hit rates
--   6. alert_resolution      — alert resolution time distribution
--   7. framework_daily       — framework usage breakdown
--   8. severity_daily        — severity distribution over time
--   9. agent_comms_hourly    — inter-agent communication patterns
--  10. data_volume_hourly    — bytes in/out volume tracking
-- ============================================================================

-- ─── 1. Daily attack-class trend ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.attack_class_daily
(
    tenant_id    UUID,
    attack_class LowCardinality(String),
    severity     LowCardinality(String),
    day          Date,
    event_count  UInt64,
    unique_agents UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, attack_class, severity, day)
TTL day + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.attack_class_daily_mv
TO phantex.attack_class_daily
AS SELECT
    tenant_id,
    attack_class,
    severity,
    toDate(timestamp)       AS day,
    count()                 AS event_count,
    uniqExact(agent_id)     AS unique_agents
FROM phantex.events
WHERE attack_class IS NOT NULL
GROUP BY tenant_id, attack_class, severity, day;

-- ─── 2. Per-tool hourly heatmap ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.tool_usage_hourly
(
    tenant_id       UUID,
    tool_name       String,
    hour            DateTime,
    call_count      UInt64,
    total_duration  UInt64,
    unique_agents   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, tool_name, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.tool_usage_hourly_mv
TO phantex.tool_usage_hourly
AS SELECT
    tenant_id,
    tool_name,
    toStartOfHour(timestamp) AS hour,
    count()                  AS call_count,
    sum(ifNull(duration_ms, 0)) AS total_duration,
    uniqExact(agent_id)      AS unique_agents
FROM phantex.events
WHERE event_type = 'TOOL_CALL' AND tool_name IS NOT NULL AND tool_name != ''
GROUP BY tenant_id, tool_name, hour;

-- ─── 3. Per-agent daily risk timeline ───────────────────────────────────────

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

-- ─── 4. Geographic destination daily ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.geo_daily
(
    tenant_id       UUID,
    dest_ip         IPv4,
    day             Date,
    connection_count UInt64,
    bytes_sent      UInt64,
    bytes_recv      UInt64,
    unique_agents   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, dest_ip, day)
TTL day + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.geo_daily_mv
TO phantex.geo_daily
AS SELECT
    tenant_id,
    dest_ip,
    toDate(timestamp)          AS day,
    count()                    AS connection_count,
    sum(ifNull(bytes_sent, 0)) AS bytes_sent,
    sum(ifNull(bytes_recv, 0)) AS bytes_recv,
    uniqExact(agent_id)        AS unique_agents
FROM phantex.events
WHERE dest_ip IS NOT NULL AND event_type = 'NETWORK_CONNECT'
GROUP BY tenant_id, dest_ip, day;

-- ─── 5. Rule hit rates daily ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.rule_hits_daily
(
    tenant_id       UUID,
    attack_class    LowCardinality(String),
    severity        LowCardinality(String),
    day             Date,
    hit_count       UInt64,
    unique_agents   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, attack_class, severity, day)
TTL day + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.rule_hits_daily_mv
TO phantex.rule_hits_daily
AS SELECT
    tenant_id,
    attack_class,
    severity,
    toDate(timestamp)       AS day,
    count()                 AS hit_count,
    uniqExact(agent_id)     AS unique_agents
FROM phantex.events
WHERE attack_class IS NOT NULL
GROUP BY tenant_id, attack_class, severity, day;

-- ─── 6. Alert resolution time (per-severity hourly) ────────────────────────

CREATE TABLE IF NOT EXISTS phantex.severity_hourly
(
    tenant_id    UUID,
    severity     LowCardinality(String),
    hour         DateTime,
    event_count  UInt64,
    avg_duration Float64,
    max_duration UInt32
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, severity, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.severity_hourly_mv
TO phantex.severity_hourly
AS SELECT
    tenant_id,
    severity,
    toStartOfHour(timestamp)            AS hour,
    count()                             AS event_count,
    ifNull(avg(duration_ms), 0)         AS avg_duration,
    ifNull(max(duration_ms), 0)         AS max_duration
FROM phantex.events
GROUP BY tenant_id, severity, hour;

-- ─── 7. Framework usage daily ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.framework_daily
(
    tenant_id    UUID,
    framework    LowCardinality(String),
    day          Date,
    event_count  UInt64,
    unique_agents UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, framework, day)
TTL day + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.framework_daily_mv
TO phantex.framework_daily
AS SELECT
    tenant_id,
    framework,
    toDate(timestamp)       AS day,
    count()                 AS event_count,
    uniqExact(agent_id)     AS unique_agents
FROM phantex.events
WHERE framework != ''
GROUP BY tenant_id, framework, day;

-- ─── 8. Severity distribution daily ─────────────────────────────────────────

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

-- ─── 9. Inter-agent communication patterns hourly ───────────────────────────

CREATE TABLE IF NOT EXISTS phantex.agent_comms_hourly
(
    tenant_id    UUID,
    agent_id     String,
    dest_ip      IPv4,
    hour         DateTime,
    conn_count   UInt64,
    bytes_sent   UInt64,
    bytes_recv   UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, agent_id, dest_ip, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.agent_comms_hourly_mv
TO phantex.agent_comms_hourly
AS SELECT
    tenant_id,
    agent_id,
    dest_ip,
    toStartOfHour(timestamp) AS hour,
    count()                  AS conn_count,
    sum(ifNull(bytes_sent, 0)) AS bytes_sent,
    sum(ifNull(bytes_recv, 0)) AS bytes_recv
FROM phantex.events
WHERE event_type = 'NETWORK_CONNECT' AND dest_ip IS NOT NULL
GROUP BY tenant_id, agent_id, dest_ip, hour;

-- ─── 10. Data volume hourly ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.data_volume_hourly
(
    tenant_id    UUID,
    hour         DateTime,
    event_count  UInt64,
    bytes_sent   UInt64,
    bytes_recv   UInt64,
    unique_agents UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.data_volume_hourly_mv
TO phantex.data_volume_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    count()                  AS event_count,
    sum(ifNull(bytes_sent, 0)) AS bytes_sent,
    sum(ifNull(bytes_recv, 0)) AS bytes_recv,
    uniqExact(agent_id)      AS unique_agents
FROM phantex.events
GROUP BY tenant_id, hour;
