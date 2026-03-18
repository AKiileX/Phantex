#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Create phantex_app role if not exists
APP_ROLE_PW="${PHANTEX_APP_ROLE_PASSWORD:-phantex-app-dev-password}"
echo "=== Creating phantex_app role ==="
docker exec phantex-postgres psql -U phantex_admin -d phantex -c "
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'phantex_app') THEN
        CREATE ROLE phantex_app WITH LOGIN PASSWORD '${APP_ROLE_PW}';
        RAISE NOTICE 'Created phantex_app role';
    ELSE
        ALTER ROLE phantex_app WITH PASSWORD '${APP_ROLE_PW}';
        RAISE NOTICE 'phantex_app role already exists, password reset';
    END IF;
END
\$\$;
"

echo ""
echo "=== Granting permissions ==="
docker exec phantex-postgres psql -U phantex_admin -d phantex -c "
GRANT CONNECT ON DATABASE phantex TO phantex_app;
GRANT USAGE ON SCHEMA public TO phantex_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO phantex_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO phantex_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO phantex_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO phantex_app;
"

echo ""
echo "=== Test connection ==="
docker exec phantex-postgres psql -U phantex_app -d phantex -c "SELECT current_user, count(*) FROM policies;"
