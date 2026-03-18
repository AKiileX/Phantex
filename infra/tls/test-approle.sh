# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

﻿#!/bin/sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=phantex-dev-root-token
ROLE_ID=$(vault read -field=role_id auth/approle/role/phantex-backend/role-id)
echo "ROLE_ID=$ROLE_ID"
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/phantex-backend/secret-id)
echo "SECRET_ID obtained"
APP_TOKEN=$(vault write -field=token auth/approle/login role_id=$ROLE_ID secret_id=$SECRET_ID)
echo "AppRole login successful"
echo ""
echo "=== Reading secrets with scoped AppRole token ==="
VAULT_TOKEN=$APP_TOKEN vault kv get secret/phantex/database
echo ""
echo "=== Testing transit sign (JWT) ==="
VAULT_TOKEN=$APP_TOKEN vault write transit/sign/jwt-signing input=$(echo -n "test-payload" | base64)
