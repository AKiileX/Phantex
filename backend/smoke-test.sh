#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Quick smoke test for the backend API
set -e

BASE=http://localhost:8000

# Login
TOKEN=$(curl -sf -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"'"${PHANTEX_ADMIN_EMAIL:-admin@localhost}"'","password":"'"${PHANTEX_ADMIN_PASSWORD:-changeme}"'"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Login OK — token: ${TOKEN:0:20}..."

# Test exports endpoint
echo ""
echo "=== GET /api/v1/exports/ ==="
RESP=$(curl -s -w "\n%{http_code}" "$BASE/api/v1/exports/" -H "Authorization: Bearer $TOKEN")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
echo "HTTP $HTTP_CODE"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"

echo ""
echo "=== GET /api/v1/alerts?status=open ==="
RESP=$(curl -s -w "\n%{http_code}" "$BASE/api/v1/alerts?status=open" -H "Authorization: Bearer $TOKEN")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
echo "HTTP $HTTP_CODE"
echo "$BODY" | python3 -m json.tool 2>/dev/null | head -20 || echo "$BODY"

echo ""
echo "=== GET /api/v1/dashboard/summary ==="
RESP=$(curl -s -w "\n%{http_code}" "$BASE/api/v1/dashboard/summary" -H "Authorization: Bearer $TOKEN")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
echo "HTTP $HTTP_CODE"
echo "$BODY" | python3 -m json.tool 2>/dev/null | head -30 || echo "$BODY"

echo ""
echo "Done!"
