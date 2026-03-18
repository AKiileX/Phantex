# Production Deployment

## Quick Production Start

```bash
./quickstart.sh --prod
```

This auto-generates all secrets, writes them to `.env.production`, starts in production mode, and prints a one-time admin password. **Save the admin password — it won't be shown again.**

---

## Manual Production Setup

**1. Create environment file:**

```bash
cp .env.production.example .env.production
```

**2. Generate secrets:**

```bash
# JWT secret (64 characters)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# Database / Redis / ClickHouse / Neo4j passwords
openssl rand -base64 32

# Gateway sensor token
openssl rand -base64 48

# JWT RS256 key pair (required in production — HS256 is rejected)
openssl genrsa -out jwt-private.pem 2048
openssl rsa -in jwt-private.pem -pubout -o jwt-public.pem
```

**3. Edit `.env.production`:**

```bash
PHANTEX_ENVIRONMENT=production
PHANTEX_DEBUG=false
PHANTEX_JWT_SECRET=<generated-jwt-secret>
PHANTEX_JWT_ALGORITHM=RS256
PHANTEX_JWT_PRIVATE_KEY_FILE=/etc/phantex/jwt-private.pem
PHANTEX_JWT_PUBLIC_KEY_FILE=/etc/phantex/jwt-public.pem
PHANTEX_DB_PASSWORD=<generated-db-password>
PHANTEX_DB_ADMIN_PASSWORD=<generated-admin-password>
PHANTEX_DB_SSL_MODE=require
PHANTEX_REDIS_URL=redis://:<generated-redis-password>@redis:6379/0
PHANTEX_INTERNAL_TOKEN=<generated-internal-token>
PHANTEX_CORS_ORIGINS=["https://your-domain.com"]
PHANTEX_WS_LEGACY_TOKEN_ENABLED=false
PHANTEX_GRAPHQL_INTROSPECTION_ENABLED=false
```

**4. Start:**

```bash
docker compose -f docker-compose.dev.yml -f docker-compose.prod.yml \
  --env-file .env.production up -d
```

---

## Rotating Tokens and Secrets

### Rotate sensor auth tokens

1. Generate a new token: `openssl rand -base64 48`
2. Add it to `gateway/gateway.yaml` under `auth.tokens` (map token → tenant ID)
3. Update the sensor's `PHANTEX_AUTH_TOKEN` environment variable or config file
4. Restart the gateway: `docker restart phantex-gateway`
5. Restart the sensor (or it will reconnect with new token on next retry)

### Rotate JWT signing keys

1. Generate a new RSA key pair (see above)
2. Mount the new keys into the backend container
3. Update `PHANTEX_JWT_PRIVATE_KEY_FILE` and `PHANTEX_JWT_PUBLIC_KEY_FILE`
4. Restart the backend — existing sessions using old tokens will be invalidated

### Rotate database passwords

1. Connect to Postgres and change the password: `ALTER ROLE phantex_app WITH PASSWORD 'new-password';`
2. Update `PHANTEX_DB_PASSWORD` in `.env.production`
3. Restart the backend and all workers

### Rotate the internal gateway token

1. Generate a new token: `openssl rand -base64 48`
2. Update `PHANTEX_INTERNAL_TOKEN` in `.env.production`
3. Update `backend.internal_token` in `gateway/gateway.yaml`
4. Restart both gateway and backend

---

## Production Hardening Checklist

The backend **refuses to start** in production if dev defaults remain. It validates:

| Check | Env Variable | Requirement |
|-------|-------------|-------------|
| JWT secret | `PHANTEX_JWT_SECRET` | Cannot be dev default |
| JWT algorithm | `PHANTEX_JWT_ALGORITHM` | Must be RS256 or ES256 (HS256 rejected) |
| JWT key files | `PHANTEX_JWT_PRIVATE_KEY_FILE` | Required for asymmetric signing |
| DB passwords | `PHANTEX_DB_PASSWORD`, `PHANTEX_DB_ADMIN_PASSWORD` | Cannot be dev defaults |
| Debug mode | `PHANTEX_DEBUG` | Must be `false` |
| CORS origins | `PHANTEX_CORS_ORIGINS` | Cannot contain localhost |
| DB TLS | `PHANTEX_DB_SSL_MODE` | Cannot be `disable` |
| GraphQL introspection | `PHANTEX_GRAPHQL_INTROSPECTION_ENABLED` | Must be `false` |
| Redis URL | `PHANTEX_REDIS_URL` | Cannot use dev password |
| Internal token | `PHANTEX_INTERNAL_TOKEN` | Cannot be dev default |
| gRPC TLS | `grpc.tls_enabled` in `gateway.yaml` | Must be `true` |

---

## Kubernetes / Helm

```bash
# Install with default values
helm install phantex infra/helm/ -n phantex --create-namespace

# Production with custom values
helm install phantex infra/helm/ \
  -f infra/helm/values-prod.yaml \
  -n phantex --create-namespace

# Staging / on-prem variants
helm install phantex infra/helm/ -f infra/helm/values-staging.yaml
helm install phantex infra/helm/ -f infra/helm/values-onprem.yaml
```

---

## Air-Gapped Deployment

```bash
# On a connected machine — bundle all images + charts
./packaging/airgap/bundle.sh

# On the air-gapped machine
./packaging/airgap/install.sh
```

---

## Upgrade System

```bash
./upgrade.sh                # 6-step automated upgrade
./upgrade.sh rollback       # full state restoration
```

The upgrade flow: pre-flight checks → extract bundle → backup (7 components) → load images → migrate DB → deploy → health gate → auto-rollback on failure.
