# Configuration Reference

## Environment Variables

All backend settings use the `PHANTEX_` prefix.

### Core

| Variable | Default | Description |
|----------|---------|------------|
| `PHANTEX_ENVIRONMENT` | `development` | `development` / `staging` / `production` |
| `PHANTEX_DEBUG` | `false` | Debug mode (must be `false` in production) |
| `PHANTEX_DB_HOST` | `localhost` | PostgreSQL host |
| `PHANTEX_DB_PORT` | `5432` | PostgreSQL port |
| `PHANTEX_DB_NAME` | `phantex` | Database name |
| `PHANTEX_DB_USER` | `phantex_app` | DB app role (RLS-restricted, no DELETE) |
| `PHANTEX_DB_PASSWORD` | `phantex-app-dev-password` | DB password (change in production!) |
| `PHANTEX_DB_SSL_MODE` | `prefer` | `disable`/`prefer`/`require`/`verify-full` |
| `PHANTEX_REDIS_URL` | `redis://:phantex-dev-redis-pw@localhost:6379/0` | Redis connection |
| `PHANTEX_KAFKA_BOOTSTRAP` | `localhost:9092` | Kafka broker(s) |

### Auth & Secrets

| Variable | Default | Description |
|----------|---------|------------|
| `PHANTEX_JWT_SECRET` | (dev default) | JWT signing secret — **must change in production** |
| `PHANTEX_JWT_ALGORITHM` | `HS256` | JWT algorithm — prod requires `RS256` or `ES256` |
| `PHANTEX_JWT_PRIVATE_KEY_FILE` | `""` | PEM private key path (required for RS/ES) |
| `PHANTEX_JWT_PUBLIC_KEY_FILE` | `""` | PEM public key path (required for RS/ES) |
| `PHANTEX_JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token TTL |
| `PHANTEX_JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL |
| `PHANTEX_VAULT_ENABLED` | `false` | Enable Vault for secret management |
| `PHANTEX_VAULT_ADDR` | `http://127.0.0.1:8200` | Vault address |
| `PHANTEX_VAULT_ROLE_ID` | `""` | Vault AppRole role ID |
| `PHANTEX_VAULT_SECRET_ID` | `""` | Vault AppRole secret ID |
| `PHANTEX_INTERNAL_TOKEN` | (dev default) | Gateway ↔ backend internal token |

### Optional Services

| Variable | Default | Description |
|----------|---------|------------|
| `PHANTEX_CLICKHOUSE_HOST` | `""` (disabled) | ClickHouse host — empty = analytics disabled |
| `PHANTEX_CLICKHOUSE_PORT` | `8123` | ClickHouse HTTP port |
| `PHANTEX_NEO4J_URI` | `""` (disabled) | Neo4j Bolt URI — empty = graph queries disabled |
| `PHANTEX_CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed CORS origins (JSON list) |
| `PHANTEX_RATE_LIMIT_PER_SECOND` | `100` | API rate limit |
| `PHANTEX_GRAPHQL_INTROSPECTION_ENABLED` | `false` | GraphQL introspection (must be off in prod) |

### Copilot (AI Investigation Assistant)

| Variable | Default | Description |
|----------|---------|------------|
| `COPILOT_PROVIDER` | `local` | LLM provider: `local` / `openai` / `anthropic` |
| `COPILOT_LOCAL_URL` | `http://host.docker.internal:1234/v1` | Local LLM endpoint |
| `COPILOT_LOCAL_MODEL` | `mistral` | Local model name |

---

## Gateway Configuration

The gateway (`gateway/gateway.yaml`) controls event ingestion and routing:

```yaml
log_level: info
log_format: console

grpc:
  listen_addr: "0.0.0.0:50051"
  tls_enabled: false
  # tls_cert_file: "/etc/phantex/tls/gateway.crt"
  # tls_key_file: "/etc/phantex/tls/gateway.key"
  # tls_ca_file: "/etc/phantex/tls/ca.crt"

auth:
  tokens:
    # Map: auth_token → tenant_id
    "your-sensor-token-here": "a0000000-0000-0000-0000-000000000001"

kafka:
  enabled: true
  brokers:
    - "kafka:9092"
  topic_prefix: "phantex.events"    # events go to phantex.events.{tenant_id}
  batch_size: 100
  batch_timeout: 1s

backend:
  url: "http://phantex-backend:8000"
  internal_token: "your-internal-token"
```

To add a new sensor, add its token to `auth.tokens` and restart the gateway.

---

## Services Ports

| Service | URL / Port | Purpose |
|---------|-----------|---------|
| Dashboard | http://localhost:3000 | Operator console (React 19 PWA) |
| Backend API | http://localhost:8000 | REST + GraphQL + WebSocket |
| Gateway (gRPC) | localhost:50051 | Sensor/SDK event ingestion |
| PostgreSQL | localhost:5432 | Primary data store (RLS) |
| Kafka | localhost:9092 | Event transport (KRaft) |
| Redis | localhost:6379 | Cache + rate limiting |
| ClickHouse | localhost:8123 | Analytics (full mode only) |
| Neo4j | localhost:7474 | Investigation graphs (full mode only) |
| Trust Engine | localhost:50052 | Rust trust scoring |
| Kafka UI | http://localhost:8080 | Topic browser (dev mode only) |

---

## Migrations

The quickstart script runs migrations automatically. Manual management:

```bash
cd backend/migrations

bash migrate.sh status           # Show which migrations have been applied
bash migrate.sh up               # Apply all pending migrations
bash migrate.sh up 003           # Apply a specific migration
bash migrate.sh verify           # Verify schema, RLS, grants, partitions
bash migrate.sh connect          # Open psql shell as admin
bash migrate.sh connect-app      # Open psql shell as restricted app role
```

All migrations use `IF NOT EXISTS` / `CREATE OR REPLACE` and are safe to re-run.
