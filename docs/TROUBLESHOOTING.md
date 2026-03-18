# Troubleshooting

## `column users.failed_login_attempts does not exist`

Database migrations haven't been applied. The quickstart script now runs them automatically, but if you started services manually:

```bash
cd backend/migrations
bash migrate.sh up       # apply all pending migrations
```

Then restart the backend: `docker restart phantex-backend`

---

## Docker build fails with `GPG error: At least one invalid signature`

Stale apt cache in Docker's BuildKit layer cache. Fix:

```bash
docker builder prune     # clear build cache
./quickstart.sh --lite   # rebuild from scratch
```

---

## Backend keeps crashing in production mode

The backend enforces startup validators — it will refuse to start if any secret is still a dev default. Check the logs:

```bash
docker logs phantex-backend 2>&1 | head -30
```

The error message will tell you exactly which `PHANTEX_*` variable needs to change. See [Production Hardening Checklist](PRODUCTION.md#production-hardening-checklist).

---

## Services start but dashboard shows empty data

1. Check that Kafka topics were created: visit `http://localhost:8080` (Kafka UI, dev mode only)
2. Check backend logs: `docker logs phantex-backend -f`
3. Verify migrations: `cd backend/migrations && bash migrate.sh status`
4. If needed, seed test data: `bash migrate.sh seed`

---

## Sensor can't connect to gateway

1. Verify the gateway is running: `docker ps | grep gateway`
2. Check sensor auth token matches `gateway.yaml` → `auth.tokens`
3. Test gRPC connectivity: `grpcurl -plaintext localhost:50051 list`
4. If using TLS: ensure CA cert is mounted and `tls_enabled: true` in sensor config
