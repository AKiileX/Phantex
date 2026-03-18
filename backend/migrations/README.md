# Phantex — Database Migrations

## Quick Start

```bash
# 1. Start PostgreSQL
cd ../../infra/postgres
docker compose -f docker-compose.postgres.yml up -d

# 2. Run migrations
cd ../../backend/migrations
bash migrate.sh up

# 3. Seed test data (development only)
bash migrate.sh seed

# 4. Verify everything
bash migrate.sh verify
```

## Commands

| Command | Description |
|---------|-------------|
| `bash migrate.sh up` | Apply all pending migrations |
| `bash migrate.sh up 001` | Apply a specific migration |
| `bash migrate.sh seed` | Insert development test data |
| `bash migrate.sh status` | Show applied migrations |
| `bash migrate.sh verify` | Check schema, RLS, grants, partitions |
| `bash migrate.sh reset` | Drop + recreate database (destroys data) |
| `bash migrate.sh connect` | Open psql as admin |
| `bash migrate.sh connect-app` | Open psql as phantex_app (restricted) |

## Migration Files

| File | Description |
|------|-------------|
| `001_initial_schema.sql` | Tables, indexes, RLS policies, app role, triggers |
| `002_bootstrap.sql` | Bootstrap data — default tenant + admin user (all environments) |
| `002z_dev_seed.sh` | Development test data — 3 agents, 1000 events, 5 alerts (dev only) |

## Database Roles

| Role | Purpose | Permissions |
|------|---------|-------------|
| `phantex_admin` | Schema management, migrations | Superuser (owner) |
| `phantex_app` | Application connections | SELECT, INSERT, UPDATE only. No DELETE/DROP/ALTER. |

The application (FastAPI) always connects as `phantex_app`.
The admin role is only used for running migrations.

## Row-Level Security (RLS)

Every tenant-scoped table has RLS enabled. The application sets the tenant context on each request:

```sql
SET app.current_tenant = '<tenant_uuid>';
```

This means even if there's a bug in the application layer, PostgreSQL will refuse to return rows from other tenants.

## Event Partitioning

The `events` table is range-partitioned by `timestamp` (monthly). The initial migration creates partitions for the current month + 3 months ahead. In production, use `pg_partman` or a cron job for automatic partition creation.

## Connection Defaults (Development)

| Setting | Value |
|---------|-------|
| Host | `localhost` |
| Port | `5432` |
| Database | `phantex` |
| Admin user | `phantex_admin` / `phantex-dev-password` |
| App user | `phantex_app` / `phantex-app-dev-password` |

Override with environment variables: `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`.
