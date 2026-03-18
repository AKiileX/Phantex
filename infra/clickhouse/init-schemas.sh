#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ClickHouse schema initializer
# The clickhouse-server:*-alpine image does NOT auto-execute
# /docker-entrypoint-initdb.d/*.sql like Postgres does.
# This entrypoint wrapper starts the server, waits for it to be ready,
# then applies all schema files in order.

set -e

# Start clickhouse-server in the background
/entrypoint.sh &
SERVER_PID=$!

# Wait for ClickHouse to become responsive (up to 60s)
echo "[init-schemas] Waiting for ClickHouse to start..."
TRIES=0
MAX_TRIES=60
while [ $TRIES -lt $MAX_TRIES ]; do
    if clickhouse-client --query "SELECT 1" > /dev/null 2>&1; then
        echo "[init-schemas] ClickHouse is ready."
        break
    fi
    TRIES=$((TRIES + 1))
    sleep 1
done

if [ $TRIES -eq $MAX_TRIES ]; then
    echo "[init-schemas] ERROR: ClickHouse did not start within ${MAX_TRIES}s"
    exit 1
fi

# Create the database if it doesn't exist
DB="${CLICKHOUSE_DB:-phantex}"
echo "[init-schemas] Ensuring database '${DB}' exists..."
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS ${DB}"

# Apply schema files in sorted order (idempotent — all use IF NOT EXISTS)
INITDB_DIR="/docker-entrypoint-initdb.d"
if [ -d "$INITDB_DIR" ]; then
    for f in $(find "$INITDB_DIR" -name '*.sql' | sort); do
        echo "[init-schemas] Applying $(basename "$f")..."
        clickhouse-client --database="$DB" --multiquery < "$f"
    done
    echo "[init-schemas] All schemas applied."
else
    echo "[init-schemas] No initdb directory found, skipping."
fi

# Bring the server back to the foreground
wait $SERVER_PID
