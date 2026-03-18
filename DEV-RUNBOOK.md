# Phantex — Dev Operations Runbook

## Quick Start

```bash
# From the repo root (WSL or native Linux):
./quickstart.sh              # dev mode — generates secrets, starts all services
./quickstart.sh --prod       # production mode — strong secrets, no debug tools
```

## Architecture

```
Simulator → Kafka:9092 → Consumer → Postgres:5432 + ClickHouse:8123
                ↓
         Rule Engine (18 rules) → Alerts → Kafka → WebSocket clients
                ↓
         ML Pipeline (features → inference → baseline → content)

Gateway:50051 (Go, gRPC + Kafka)
uvicorn:8000 ← FastAPI API (REST + WS)
    ↕ gRPC
Trust Engine:50052 (Rust, in-memory graph)

Dashboard:3000 (Docker) / :5173 (Vite dev)
```

## Services & Ports

| Service | Port | Runtime | Log File |
|---------|------|---------|----------|
| PostgreSQL | 5432 | Docker | docker logs phantex-postgres |
| Kafka | 9092 | Docker | docker logs phantex-kafka |
| Redis | 6379 | Docker | docker logs phantex-redis |
| ClickHouse | 8123 | Docker | docker logs phantex-clickhouse |
| Neo4j | 7687 | Docker | docker logs phantex-neo4j |
| Trust Engine | 50052 | Rust binary | /tmp/trust-engine.log |
| API (uvicorn) | 8000 | Python | /tmp/phantex-uvicorn.log |
| Kafka Consumer | — | Python | /tmp/phantex-consumer.log |
| Rule Engine | — | Python | /tmp/phantex-rule-engine.log |
| ML Features | — | Python | /tmp/phantex-main_features.log |
| ML Inference | — | Python | /tmp/phantex-main_inference.log |
| ML Baseline | — | Python | /tmp/phantex-main_baseline.log |
| ML Content | — | Python | docker logs phantex-ml-content |
| Gateway | 50051 | Go | docker logs phantex-gateway |
| Storage Writer | — | Go | docker logs phantex-storage-writer |
| Dashboard | 3000 | Docker (nginx) | docker logs phantex-dashboard |
| Kafka UI | 8080 | Docker | docker logs phantex-kafka-ui |
| Simulator | — | Python | /tmp/phantex-simulator.log |

## Startup Order

`quickstart.sh` handles this automatically. Manual order:

1. **Docker containers** — `docker compose -f docker-compose.dev.yml up -d`
2. **Trust Engine** — needs port 50052 free
3. **Kafka Consumer** — writes events from Kafka to Postgres + ClickHouse
4. **Rule Engine** — reads events from Kafka, evaluates 18 PRL rules, fires alerts
5. **ML Pipelines** — feature extraction, inference, baseline, content analysis (4 processes)
6. **uvicorn** — API server, must set `TRUST_ENGINE_ADDR=localhost:50052`
7. **Simulator** — produces synthetic agent telemetry (2 events/sec, 8% attack)

## Key Environment

uvicorn reads `backend/.env` via pydantic-settings (`env_prefix=PHANTEX_`):

```env
PHANTEX_CLICKHOUSE_HOST=localhost
PHANTEX_NEO4J_URI=bolt://localhost:7687
PHANTEX_CORS_ORIGINS=["http://localhost:5173","http://localhost:3000"]
```

Other env vars set in `docker-compose.dev.yml`:
- `DATABASE_URL` / `ADMIN_DATABASE_URL` — Postgres connection
- `KAFKA_BOOTSTRAP_SERVERS` — Kafka broker
- `REDIS_URL` — Redis
- `TRUST_ENGINE_ADDR` — gRPC address for trust client
- `PHANTEX_INTERNAL_TOKEN` — Shared secret for gateway ↔ backend internal API (response action command relay). Set in `docker-compose.dev.yml`, defaults to `phantex-dev-internal-token` in dev. Must be a strong random value in production.

## Response Action Pipeline

SOC analyst triggers a response action on an alert → backend queues command in `agent_commands` table → gateway polls `GET /internal/commands/pending/{sensor_id}` → relays to sensor → sensor executes (isolate, block_ip, kill_process, quarantine, collect_forensics) → reports back via `PATCH /internal/commands/{id}/status`.

```
AlertDetailPage → POST /alerts/{id}/actions → agent_commands (DB)
                                                    ↓ (gateway polls)
                     GET /internal/commands/pending/{sensor_id}
                                                    ↓
                     Gateway → Sensor (heartbeat response)
                                                    ↓
                     Sensor executor (allow-list, no shell)
                                                    ↓
                     PATCH /internal/commands/{id}/status
```

Internal API auth: `PHANTEX_INTERNAL_TOKEN` header with `hmac.compare_digest()` timing-safe comparison. ABAC permission: `alerts.execute_action` (separate from `alerts.acknowledge`).

## Auth

```
Email:    admin@phantex.dev      # Set via PHANTEX_ADMIN_EMAIL env var
Password: changeme               # Set via PHANTEX_ADMIN_PASSWORD env var
```

> ⚠️ **Change default credentials immediately.** The seed migration uses `changeme` — override via env vars in any non-local environment.

```bash
# Get a token:
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"${PHANTEX_ADMIN_EMAIL:-admin@phantex.dev}"'","password":"'"${PHANTEX_ADMIN_PASSWORD:-changeme}"'"}'
```

---

## Sensor Fleet Management

The platform tracks deployed sensors (eBPF probes) via a dedicated `sensors` table and API.

### Database

Migration `030_sensors.sql` creates the `sensors` table with RLS, grants, indexes, and CHECK constraints. Applied via:

```bash
# Preferred: use the migration runner
bash backend/migrations/migrate.sh up

# Or manually for a single migration:
docker cp backend/migrations/030_sensors.sql phantex-postgres:/tmp/030_sensors.sql
docker exec phantex-postgres psql -U phantex_admin -d phantex -f /tmp/030_sensors.sql
```

### API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/api/v1/sensors` | JWT (user) | List sensors (cursor pagination, status/search filters) |
| `GET` | `/api/v1/sensors/{uuid}` | JWT (user) | Sensor detail |
| `POST` | `/api/internal/sensors/register` | Internal token | Gateway registers a sensor on connect |
| `POST` | `/api/internal/sensors/heartbeat` | Internal token | Gateway relays sensor heartbeat metrics |

Internal endpoints use timing-safe `PHANTEX_INTERNAL_TOKEN` auth via `hmac.compare_digest`.

### Dashboard Pages

- **Sensors** (`/sensors`) — Fleet overview with health badges, probe counts, event throughput, CPU/memory, live refresh.
- **Sensor Detail** (`/sensors/:id`) — Identity, health metrics, resources, diagnostics cards.

### Key Files

| File | Purpose |
|------|---------|
| `backend/migrations/030_sensors.sql` | DDL, RLS, grants, indexes |
| `backend/app/models/sensor.py` | SQLAlchemy model |
| `backend/app/schemas/sensor.py` | Pydantic response/filter schemas |
| `backend/app/services/sensor_service.py` | CRUD + heartbeat + status refresh |
| `backend/app/routers/sensors.py` | Public REST API |
| `backend/app/routers/internal_sensors.py` | Internal gateway API |
| `dashboard/src/pages/SensorsPage.tsx` | Fleet list page |
| `dashboard/src/pages/SensorDetailPage.tsx` | Detail page |
| `dashboard/src/api/sensors.ts` | TanStack Query hooks |

---

## Known Issues & Fixes

### 1. ClickHouse 503 — `ssl_context=None` passed to client

**File:** `backend/app/clickhouse.py`

**Symptom:** `/api/v1/analytics/*` returned HTTP 503. ClickHouse client threw `HttpClient.__init__() got an unexpected keyword argument 'ssl_context'`.

**Root cause:** `get_clickhouse()` always passed `ssl_context=None` to `clickhouse_connect.get_async_client()` even when TLS was disabled. The library rejects `None` as a value.

**Fix:** Only pass `ssl_context` kwarg when the value is not `None`.

### 2. Trust Engine NOT_SERVING — gRPC not wired

**Files:** `backend/app/services/trust_client.py`

**Symptom:** `/api/v1/trust/health` returned `{"status":"NOT_SERVING","uptime_secs":0.0}` — the fallback response.

**Root causes (3 bugs):**

| Bug | Detail | Fix |
|-----|--------|-----|
| grpcio not installed | `_grpc_available = False` at import time → fallback mode | Installed `grpcio==1.78.0` + `grpcio-tools` in backend venv |
| Proto stubs not on sys.path | Generated `trust_pb2_grpc.py` does `from phantex.v1 import trust_pb2` — needs `proto/gen` on sys.path | Added path setup at top of `trust_client.py` (resolves project root + `proto/gen`) |
| `health_check()` never connected | Checked `self._stub is None` and returned fallback without calling `_ensure_connected()` first | Added `await self._ensure_connected()` before the stub check |

### 3. gRPC "Channel is closed" after connect

**File:** `backend/app/services/trust_client.py`

**Symptom:** Trust graph endpoint logged `trust_client.retry attempt=1 error=Channel is closed` 3 times, then `trust_client.call_failed`.

**Root cause:** `grpc.aio.insecure_channel()` returns a lazy channel that isn't ready yet. The stub call fired immediately before the TCP handshake completed.

**Fix:** Added `await channel_ready()` with timeout after channel creation. Waits for the channel to reach READY state before creating the stub.

### 4. WebSocket `rate_limit()` TypeError

**File:** `backend/app/routers/ws.py`

**Symptom:** Dashboard WebSocket connection threw `TypeError: rate_limit() missing 1 required positional argument: 'request'`.

**Root cause:** `router = APIRouter(dependencies=[Depends(rate_limit)])` applies to **all** routes including WebSocket. `rate_limit(request: Request)` can't resolve a `Request` from a WebSocket scope — FastAPI injects `WebSocket`, not `Request`.

**Fix:** Removed router-level `dependencies=[Depends(rate_limit)]`. Applied `dependencies=[Depends(rate_limit)]` only to the two REST endpoints (`POST /ws/ticket`, `GET /ws/status`).

### 5. Kafka bridge connection error (transient)

**Symptom:** `KafkaConnectionError: Unable to bootstrap from [('localhost', 9092)]` on startup.

**Root cause:** Kafka container takes a few seconds to be ready. aiokafka's built-in retry (5s delay) reconnects automatically.

**Not a bug** — graceful degradation working as designed. No code change needed.
