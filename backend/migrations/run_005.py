# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Run migration 005: make audit_log.tenant_id nullable."""

import asyncio
import os

import asyncpg

async def migrate():
    conn = await asyncpg.connect(
        os.environ["PHANTEX_DATABASE_URL"],
    )
    try:
        await conn.execute("ALTER TABLE audit_log ALTER COLUMN tenant_id DROP NOT NULL")
        await conn.execute("DROP POLICY IF EXISTS tenant_isolation_audit ON audit_log")
        await conn.execute(
            "CREATE POLICY tenant_isolation_audit ON audit_log "
            "FOR ALL TO phantex_app "
            "USING (tenant_id::text = current_setting('app.current_tenant', true))"
        )
        await conn.execute(
            "INSERT INTO schema_migrations (version, description) "
            "VALUES ('005', 'Make audit_log.tenant_id nullable for pre-auth audit entries')"
        )
        print("Migration 005 applied successfully")
    finally:
        await conn.close()

asyncio.run(migrate())
