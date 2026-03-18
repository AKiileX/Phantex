# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Apply all ClickHouse schema files via HTTP API.

Reads *.sql files from infra/clickhouse/schema/ in sorted order,
splits on semicolons, and executes each statement.
"""
import os
import pathlib
import urllib.request
import urllib.parse
import sys

_ch_user = os.environ.get("CLICKHOUSE_USER", "phantex")
_ch_pass = os.environ.get("CLICKHOUSE_PASSWORD", "phantex-dev-password")
_ch_host = os.environ.get("CLICKHOUSE_HOST", "localhost")
_ch_port = os.environ.get("CLICKHOUSE_PORT", "8123")
CH_URL = f"http://{_ch_host}:{_ch_port}/?user={urllib.parse.quote(_ch_user)}&password={urllib.parse.quote(_ch_pass)}"

# Locate schema directory relative to this script
_script_dir = pathlib.Path(__file__).resolve().parent
_schema_dir = _script_dir.parent / "infra" / "clickhouse" / "schema"

if not _schema_dir.is_dir():
    print(f"ERROR: schema directory not found: {_schema_dir}", file=sys.stderr)
    sys.exit(1)

sql_files = sorted(_schema_dir.glob("*.sql"))
if not sql_files:
    print(f"ERROR: no .sql files found in {_schema_dir}", file=sys.stderr)
    sys.exit(1)

print(f"Found {len(sql_files)} schema files in {_schema_dir}\n")

ok = 0
fail = 0
total = 0
for sql_file in sql_files:
    print(f"--- {sql_file.name} ---")
    content = sql_file.read_text(encoding="utf-8")
    # Split on semicolons, filter empty statements
    stmts = [s.strip() for s in content.split(";") if s.strip()]
    for j, sql in enumerate(stmts, 1):
        total += 1
        try:
            data = sql.encode("utf-8")
            req = urllib.request.Request(CH_URL, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
            print(f"  [{j}/{len(stmts)}] OK")
            ok += 1
        except Exception as e:
            print(f"  [{j}/{len(stmts)}] FAIL: {e}")
            fail += 1

print(f"\nDone: {ok} ok, {fail} failed (of {total} statements)")
