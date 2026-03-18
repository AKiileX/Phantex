#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ============================================================================
# Phantex — Database Migration Runner
#
# Usage:
#   bash migrate.sh status             # Show applied migrations
#   bash migrate.sh up                 # Apply all pending migrations
#   bash migrate.sh up 001             # Apply specific migration
#   bash migrate.sh seed               # Insert development test data
#   bash migrate.sh reset              # Drop + recreate database (DESTROYS DATA)
#   bash migrate.sh verify             # Verify schema + RLS + grants
#   bash migrate.sh connect            # Open psql shell (admin)
#   bash migrate.sh connect-app        # Open psql shell (app role)
#
# Environment variables (all have dev defaults):
#   PGHOST      (default: localhost)
#   PGPORT      (default: 5432)
#   PGDATABASE  (default: phantex)
#   PGUSER      (default: phantex_admin)
#   PGPASSWORD  (default: phantex-dev-password)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MIGRATIONS_DIR="${SCRIPT_DIR}"

# Dev defaults
export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGDATABASE="${PGDATABASE:-phantex}"
export PGUSER="${PGUSER:-phantex_admin}"
export PGPASSWORD="${PGPASSWORD:-phantex-dev-password}"
CONTAINER="${PG_CONTAINER:-phantex-postgres}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[migrate]${NC} $*"; }
warn()  { echo -e "${YELLOW}[migrate]${NC} $*"; }
error() { echo -e "${RED}[migrate]${NC} $*" >&2; }

psql_exec() {
    docker exec -e PGUSER="$PGUSER" -e PGPASSWORD="$PGPASSWORD" "$CONTAINER" \
        psql -U "$PGUSER" -d "$PGDATABASE" -v ON_ERROR_STOP=1 -q "$@"
}

psql_print() {
    docker exec -e PGUSER="$PGUSER" -e PGPASSWORD="$PGPASSWORD" "$CONTAINER" \
        psql -U "$PGUSER" -d "$PGDATABASE" -v ON_ERROR_STOP=1 "$@"
}

psql_pipe() {
    docker exec -i -e PGUSER="$PGUSER" -e PGPASSWORD="$PGPASSWORD" "$CONTAINER" \
        psql -U "$PGUSER" -d "$PGDATABASE" -v ON_ERROR_STOP=1
}

wait_for_pg() {
    log "Waiting for PostgreSQL container ${CONTAINER}..."
    for i in $(seq 1 30); do
        if docker exec "$CONTAINER" pg_isready -U "$PGUSER" -d "$PGDATABASE" > /dev/null 2>&1; then
            log "PostgreSQL ready."
            return 0
        fi
        sleep 1
    done
    error "PostgreSQL not available after 30s."
    exit 1
}

cmd_status() {
    log "Migration status:"
    psql_print -c "SELECT version, applied_at, description FROM schema_migrations ORDER BY version;" 2>/dev/null || {
        warn "schema_migrations table does not exist — no migrations have been run."
    }
}

cmd_up() {
    local target="${1:-}"
    wait_for_pg

    # Get list of SQL migration files
    local files=()
    for f in "${MIGRATIONS_DIR}"/[0-9][0-9][0-9]_*.sql; do
        [ -f "$f" ] || continue
        files+=("$f")
    done

    if [ ${#files[@]} -eq 0 ]; then
        error "No migration files found in ${MIGRATIONS_DIR}"
        exit 1
    fi

    # Check which have been applied
    local applied=""
    applied=$(psql_print -t -c "SELECT version FROM schema_migrations ORDER BY version;" 2>/dev/null || echo "")

    local count=0
    for f in "${files[@]}"; do
        local basename
        basename="$(basename "$f")"
        local version="${basename%%_*}"  # Extract "001" from "001_initial_schema.sql"

        # Skip if targeting a specific version and this isn't it
        if [ -n "$target" ] && [ "$version" != "$target" ]; then
            continue
        fi

        # Skip if already applied
        if echo "$applied" | grep -q "^ *${version}$"; then
            log "  ${version} — already applied, skipping."
            continue
        fi

        log "  Applying ${basename}..."
        psql_pipe < "$f"

        # Ensure migration is tracked (idempotent — some files self-register)
        local desc="${basename%.sql}"
        desc="${desc#[0-9][0-9][0-9]_}"  # strip version prefix
        psql_pipe <<EOF
INSERT INTO schema_migrations (version, description)
VALUES ('${version}', '${desc}')
ON CONFLICT (version) DO NOTHING;
EOF

        log "  ${version} ✅ applied."
        count=$((count + 1))
    done

    if [ $count -eq 0 ]; then
        log "All migrations are up to date."
    else
        log "${count} migration(s) applied."
    fi
}

cmd_seed() {
    wait_for_pg

    # Bootstrap (tenant + admin) — always needed
    local bootstrap_file="${MIGRATIONS_DIR}/002_bootstrap.sql"
    if [ -f "$bootstrap_file" ]; then
        log "Applying bootstrap data (tenant + admin user)..."
        psql_pipe < "$bootstrap_file"
    fi

    # Dev seed (fake agents, events, alerts) — explicit opt-in
    log "Loading development test data (3 agents, 1000 events, 5 alerts)..."
    docker exec -e POSTGRES_USER="$PGUSER" -e POSTGRES_DB="$PGDATABASE" \
        -e PGPASSWORD="$PGPASSWORD" -e PHANTEX_LOAD_SEED_DATA=true \
        "$CONTAINER" bash /docker-entrypoint-initdb.d/002z_dev_seed.sh

    log "Seed data inserted. ✅"
}

cmd_reset() {
    warn "⚠️  This will DROP and RECREATE the phantex database. ALL DATA WILL BE LOST."
    read -r -p "Type 'yes' to confirm: " confirm
    if [ "$confirm" != "yes" ]; then
        log "Aborted."
        exit 0
    fi

    wait_for_pg

    log "Terminating active connections..."
    docker exec "$CONTAINER" psql -U "$PGUSER" -d postgres -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'phantex' AND pid <> pg_backend_pid();" 2>/dev/null || true

    log "Dropping database..."
    docker exec "$CONTAINER" psql -U "$PGUSER" -d postgres -c "DROP DATABASE IF EXISTS phantex;"

    log "Creating database..."
    docker exec "$CONTAINER" psql -U "$PGUSER" -d postgres -c "CREATE DATABASE phantex OWNER phantex_admin;"

    log "Database reset. Run 'bash migrate.sh up' to apply migrations."
}

cmd_verify() {
    wait_for_pg
    log "Verifying schema..."

    echo ""
    log "Tables:"
    psql_print -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"

    echo ""
    log "Row-Level Security policies:"
    psql_print -c "SELECT tablename, policyname, permissive, roles, cmd FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename;"

    echo ""
    log "RLS status:"
    psql_print -c "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('agents','events','alerts','rules','users','audit_log','refresh_tokens') ORDER BY relname;"

    echo ""
    log "phantex_app grants:"
    psql_print -c "SELECT table_name, string_agg(privilege_type, ', ' ORDER BY privilege_type) AS privileges FROM information_schema.table_privileges WHERE grantee = 'phantex_app' AND table_schema = 'public' GROUP BY table_name ORDER BY table_name;"

    echo ""
    log "Event partitions:"
    psql_print -c "SELECT inhrelid::regclass AS partition, pg_get_expr(c.relpartbound, c.oid) AS bound FROM pg_inherits JOIN pg_class c ON c.oid = inhrelid WHERE inhparent = 'events'::regclass ORDER BY inhrelid::regclass;"

    echo ""
    log "Indexes:"
    psql_print -c "SELECT indexname, tablename FROM pg_indexes WHERE schemaname = 'public' AND indexname LIKE 'idx_%' ORDER BY tablename, indexname;"

    echo ""
    log "Schema verification complete. ✅"
}

cmd_connect() {
    log "Connecting as ${PGUSER}..."
    docker exec -it "$CONTAINER" psql -U "$PGUSER" -d "$PGDATABASE"
}

cmd_connect_app() {
    log "Connecting as phantex_app..."
    docker exec -it "$CONTAINER" psql -U phantex_app -d "$PGDATABASE"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

case "${1:-help}" in
    status)       cmd_status ;;
    up)           cmd_up "${2:-}" ;;
    seed)         cmd_seed ;;
    reset)        cmd_reset ;;
    verify)       cmd_verify ;;
    connect)      cmd_connect ;;
    connect-app)  cmd_connect_app ;;
    help|*)
        echo "Usage: bash migrate.sh {status|up [VERSION]|seed|reset|verify|connect|connect-app}"
        echo ""
        echo "Commands:"
        echo "  status       Show applied migrations"
        echo "  up           Apply all pending migrations"
        echo "  up 001       Apply a specific migration"
        echo "  seed         Insert development test data"
        echo "  reset        Drop + recreate database (DESTROYS DATA)"
        echo "  verify       Verify schema, RLS, grants, partitions"
        echo "  connect      Open psql as admin"
        echo "  connect-app  Open psql as phantex_app (restricted)"
        ;;
esac
