-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex ClickHouse — FinOps Cost & Token Tracking
--
-- Tables + MVs for cost monitoring:
--   1. token_usage          — per-request token counts (raw)
--   2. cost_hourly          — aggregated cost per agent/model/hour
--   3. budget_alerts        — budget threshold crossing log
--   4. cost_anomalies       — detected cost anomalies
-- ============================================================================

-- ─── 1. Raw token usage (event-level) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.token_usage
(
    tenant_id          UUID,
    agent_id           String,
    request_id         String,
    provider           LowCardinality(String),
    model              LowCardinality(String),
    prompt_tokens      UInt32,
    completion_tokens  UInt32,
    total_tokens       UInt32,
    estimated_cost_usd Float64,
    latency_ms         Float64,
    source             LowCardinality(String)  DEFAULT 'backend',
    timestamp          DateTime64(3)           DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, agent_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- ─── 2. Hourly cost aggregation ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.cost_hourly
(
    tenant_id          UUID,
    agent_id           String,
    provider           LowCardinality(String),
    model              LowCardinality(String),
    hour               DateTime,
    request_count      UInt64,
    prompt_tokens      UInt64,
    completion_tokens  UInt64,
    total_tokens       UInt64,
    total_cost_usd     Float64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, agent_id, provider, model, hour)
TTL hour + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.cost_hourly_mv
TO phantex.cost_hourly
AS SELECT
    tenant_id,
    agent_id,
    provider,
    model,
    toStartOfHour(timestamp) AS hour,
    count()                  AS request_count,
    sum(prompt_tokens)       AS prompt_tokens,
    sum(completion_tokens)   AS completion_tokens,
    sum(total_tokens)        AS total_tokens,
    sum(estimated_cost_usd)  AS total_cost_usd
FROM phantex.token_usage
GROUP BY tenant_id, agent_id, provider, model, hour;

-- ─── 3. Budget alert log ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.budget_alerts
(
    tenant_id       UUID,
    scope           LowCardinality(String),   -- 'agent', 'team', 'tenant'
    scope_id        String,                    -- agent_id, team_id, or tenant_id
    threshold_pct   UInt8,                     -- 80, 90, 100
    budget_usd      Float64,
    spent_usd       Float64,
    alert_action    LowCardinality(String),   -- 'warn', 'hard_cap'
    timestamp       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, scope, scope_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 365 DAY;

-- ─── 4. Cost anomaly log ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS phantex.cost_anomalies
(
    tenant_id       UUID,
    agent_id        String,
    anomaly_type    LowCardinality(String),   -- 'spike', 'sustained_high', 'unusual_model'
    severity        LowCardinality(String),   -- 'low', 'medium', 'high', 'critical'
    description     String,
    cost_usd        Float64,
    baseline_usd    Float64,
    deviation_factor Float64,
    correlated_alert_id Nullable(UUID),
    timestamp       DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, agent_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 365 DAY;
