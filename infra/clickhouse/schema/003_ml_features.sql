-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- Phantex ClickHouse — ML Feature Extraction Views
--
-- Materialized views that pre-compute features used by the ML pipeline (J1).
-- These feed into Redis (hot) and are queryable for training data (cold).
-- ============================================================================

-- ── Hourly feature vector per agent ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS phantex.ml_features_hourly
(
    tenant_id               UUID,
    agent_id                String,
    hour                    DateTime,
    -- Volume features
    event_count             UInt64,
    tool_call_count         UInt64,
    file_read_count         UInt64,
    network_connect_count   UInt64,
    -- Network features
    bytes_sent_total        UInt64,
    bytes_recv_total        UInt64,
    unique_dest_ips         UInt64,
    unique_dest_ports       UInt64,
    -- Diversity features
    unique_event_types      UInt64,
    unique_tools            UInt64,
    unique_files            UInt64,
    -- Behavioral features
    avg_duration_ms         Float64,
    max_duration_ms         UInt32
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, agent_id, hour)
TTL hour + INTERVAL 90 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS phantex.ml_features_hourly_mv
TO phantex.ml_features_hourly
AS SELECT
    tenant_id,
    agent_id,
    toStartOfHour(timestamp)                                  AS hour,
    -- Volume
    count()                                                    AS event_count,
    countIf(event_type = 'TOOL_CALL')                         AS tool_call_count,
    countIf(event_type = 'FILE_READ')                         AS file_read_count,
    countIf(event_type = 'NETWORK_CONNECT')                   AS network_connect_count,
    -- Network
    sum(ifNull(bytes_sent, 0))                                  AS bytes_sent_total,
    sum(ifNull(bytes_recv, 0))                                  AS bytes_recv_total,
    uniqExactIf(dest_ip, dest_ip IS NOT NULL)                 AS unique_dest_ips,
    uniqExactIf(dest_port, dest_port IS NOT NULL)             AS unique_dest_ports,
    -- Diversity
    uniqExact(event_type)                                      AS unique_event_types,
    uniqExactIf(tool_name, tool_name IS NOT NULL AND tool_name != '') AS unique_tools,
    uniqExactIf(file_path, file_path IS NOT NULL AND file_path != '') AS unique_files,
    -- Behavioral
    coalesce(avgOrDefault(duration_ms), 0)                    AS avg_duration_ms,
    coalesce(maxOrDefault(duration_ms), 0)                    AS max_duration_ms
FROM phantex.events
GROUP BY tenant_id, agent_id, hour;
