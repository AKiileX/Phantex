# ClickHouse Infrastructure

## Overview

ClickHouse is the analytics engine for high-volume event queries, dashboards,
and ML feature extraction. PostgreSQL remains the source of truth for
transactional data; ClickHouse handles analytical workloads.

## Architecture

```
Kafka phantex.events.{tenant}
    ├──▶ PostgreSQL (transactional queries, API reads)
    └──▶ ClickHouse (analytics, ML features, dashboards)
         via storage-writer consumer (I4)
```

## Schema Files

| File | Contents |
|------|----------|
| `schema/001_events.sql` | Main events table — MergeTree, partitioned by month, 90-day TTL |
| `schema/002_aggregations.sql` | Hourly + daily rollups via materialized views |
| `schema/003_ml_features.sql` | ML feature extraction materialized views (feeds J1) |
| `schema/004_advanced_analytics.sql` | Attack-class, tool-usage, agent-risk, geo, rule-hits, severity, framework, comms, data-volume MVs |
| `schema/005_finops_cost_tracking.sql` | FinOps cost tracking tables — compute, token, storage, anomaly tables + MVs |
| `schema/006_severity_backfill.sql` | Normalize severity to lowercase, recreate + backfill agent_risk_daily & severity_daily MVs |

## Dev Usage

ClickHouse is started as part of `docker-compose.dev.yml`.

Standalone (for testing):
```bash
docker compose -f infra/clickhouse/docker-compose.clickhouse.yml up -d
```

Connect:
```bash
docker exec -it phantex-clickhouse clickhouse-client --database phantex
```

## Users

| User | Role | Purpose |
|------|------|---------|
| `phantex` (default) | Admin | Schema migrations, admin queries |
| `phantex_app` | Read-only | API analytics queries (profile: readonly) |

## Key Design Decisions

- **MergeTree** engine: optimal for time-series append workloads
- **PARTITION BY toYYYYMM**: monthly partitions, 90-day TTL auto-drops old partitions
- **ORDER BY (tenant_id, agent_id, timestamp)**: optimised for tenant-scoped, agent-filtered, time-range queries
- **LowCardinality** on event_type, severity, attack_class: 10-50x compression + faster GROUP BY
- **SummingMergeTree** for aggregations: automatic merge of partial aggregates
- **No ReplacingMergeTree** for events table: events are immutable, we use idempotent writes (ON DUPLICATE IGNORE pattern via event_id dedup)
