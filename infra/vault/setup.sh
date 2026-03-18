#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex — Vault Initial Setup (dev mode)
#
# Seeds Vault with:
#   1. JWT RS256 signing key pair (transit engine)
#   2. Service secrets (DB passwords, Kafka creds, API keys)
#   3. ACL policies (backend, gateway, sensor)
#   4. AppRole auth for each service
#
# Prerequisites:
#   - Vault running (docker compose up -d)
#   - vault CLI available
#
# Usage:
#   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=phantex-dev-root-token bash infra/vault/setup.sh

set -euo pipefail

: "${VAULT_ADDR:=http://127.0.0.1:8200}"
: "${VAULT_TOKEN:=phantex-dev-root-token}"

export VAULT_ADDR VAULT_TOKEN

echo "=== Phantex Vault Setup ==="
echo "VAULT_ADDR: $VAULT_ADDR"

# Wait for Vault to be ready
for i in $(seq 1 30); do
    if vault status &>/dev/null; then
        break
    fi
    echo "Waiting for Vault... ($i/30)"
    sleep 1
done

vault status || { echo "ERROR: Vault not reachable"; exit 1; }

# ── 1. Enable Transit Engine (JWT signing) ────────────────────────────────
echo ""
echo "--- Enabling transit secrets engine ---"
vault secrets enable -path=transit transit 2>/dev/null || echo "transit engine already enabled"

# Create RS256 signing key for JWT tokens
echo "Creating JWT RS256 signing key..."
vault write -f transit/keys/jwt-signing \
    type=rsa-2048 \
    exportable=false \
    allow_plaintext_backup=false \
    deletion_allowed=false

echo "JWT signing key created: transit/keys/jwt-signing"

# ── 2. Enable KV v2 Engine (service secrets) ─────────────────────────────
echo ""
echo "--- Enabling KV v2 secrets engine ---"
vault secrets enable -path=secret -version=2 kv 2>/dev/null || echo "KV engine already enabled"

# ── 2b. Enable PKI Engine (short-lived mTLS certificates) ────────────────
# Root CA + intermediate CA with 24h leaf TTL for all services.
echo ""
echo "--- Enabling PKI secrets engines ---"

# Root CA (10-year TTL, issues intermediate only)
vault secrets enable -path=pki pki 2>/dev/null || echo "PKI root engine already enabled"
vault secrets tune -max-lease-ttl=87600h pki

# Generate root CA (self-signed)
vault write -field=certificate pki/root/generate/internal \
    common_name="Phantex Root CA" \
    issuer_name="phantex-root" \
    ttl=87600h > /dev/null 2>&1 || echo "Root CA already configured"

vault write pki/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"

# Intermediate CA (5-year TTL, issues leaf certs)
vault secrets enable -path=pki_int pki 2>/dev/null || echo "PKI intermediate engine already enabled"
vault secrets tune -max-lease-ttl=43800h pki_int

# Generate intermediate CSR and sign with root
vault write -format=json pki_int/intermediate/generate/internal \
    common_name="Phantex Intermediate CA" \
    issuer_name="phantex-intermediate" | \
    jq -r '.data.csr' > /tmp/phantex_pki_intermediate.csr 2>/dev/null || echo "Intermediate CA already configured"

if [ -f /tmp/phantex_pki_intermediate.csr ] && [ -s /tmp/phantex_pki_intermediate.csr ]; then
    vault write -format=json pki/root/sign-intermediate \
        csr=@/tmp/phantex_pki_intermediate.csr \
        format=pem_bundle \
        ttl=43800h | \
        jq -r '.data.certificate' > /tmp/phantex_intermediate_signed.pem

    vault write pki_int/intermediate/set-signed \
        certificate=@/tmp/phantex_intermediate_signed.pem

    rm -f /tmp/phantex_pki_intermediate.csr /tmp/phantex_intermediate_signed.pem
fi

vault write pki_int/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki_int/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki_int/crl"

# Per-service roles with 24-hour leaf TTL and role-specific EKU
echo "Creating PKI roles (24h leaf TTL)..."

# Gateway — serverAuth only (accepts sensor connections)
vault write pki_int/roles/phantex-gateway \
    allowed_domains="gateway,phantex-gateway,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    max_ttl=24h \
    ttl=24h \
    key_type=ec \
    key_bits=256 \
    server_flag=true \
    client_flag=false \
    no_store=true

# Sensor — clientAuth only (connects to gateway)
vault write pki_int/roles/phantex-sensor \
    allowed_domains="sensor,phantex-sensor,localhost" \
    allow_subdomains=true \
    allow_bare_domains=true \
    allow_localhost=true \
    max_ttl=24h \
    ttl=24h \
    key_type=ec \
    key_bits=256 \
    server_flag=false \
    client_flag=true \
    no_store=true

# Backend — server+client (serves API, connects to DBs)
vault write pki_int/roles/phantex-backend \
    allowed_domains="backend,phantex-backend,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    max_ttl=24h \
    ttl=24h \
    key_type=ec \
    key_bits=256 \
    server_flag=true \
    client_flag=true \
    no_store=true

# Kafka — server+client (broker-to-broker + client connections)
vault write pki_int/roles/phantex-kafka \
    allowed_domains="kafka,phantex-kafka,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    max_ttl=24h \
    ttl=24h \
    key_type=ec \
    key_bits=256 \
    server_flag=true \
    client_flag=true \
    no_store=true

# PostgreSQL — serverAuth only
vault write pki_int/roles/phantex-postgres \
    allowed_domains="postgres,phantex-postgres,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    max_ttl=24h \
    ttl=24h \
    key_type=ec \
    key_bits=256 \
    server_flag=true \
    client_flag=false \
    no_store=true

# Redis — serverAuth only
vault write pki_int/roles/phantex-redis \
    allowed_domains="redis,phantex-redis,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_localhost=true \
    max_ttl=24h \
    ttl=24h \
    key_type=ec \
    key_bits=256 \
    server_flag=true \
    client_flag=false \
    no_store=true

echo "PKI roles created: gateway, sensor, backend, kafka, postgres, redis (all 24h TTL, ECDSA P-256)"

# Seed development secrets (override via environment variables for non-dev environments)
echo "Seeding development secrets..."

: "${PHANTEX_DB_APP_PASSWORD:=phantex-app-dev-password}"
: "${PHANTEX_DB_ADMIN_PASSWORD:=phantex-dev-password}"
: "${PHANTEX_REDIS_PASSWORD:=}"
: "${PHANTEX_GATEWAY_AUTH_TOKEN:=phantex-dev-token-do-not-use-in-production}"

vault kv put secret/phantex/database \
    app_user=phantex_app \
    app_password="$PHANTEX_DB_APP_PASSWORD" \
    admin_user=phantex_admin \
    admin_password="$PHANTEX_DB_ADMIN_PASSWORD" \
    host=postgres \
    port=5432 \
    name=phantex \
    ssl_mode=prefer

vault kv put secret/phantex/kafka \
    bootstrap_servers=kafka:9092 \
    tls_enabled=false

vault kv put secret/phantex/gateway \
    auth_tokens="{\"$PHANTEX_GATEWAY_AUTH_TOKEN\":\"default-tenant\"}" \
    listen_addr=":50051"

vault kv put secret/phantex/redis \
    url=redis://redis:6379/0 \
    tls_enabled=false

echo "Development secrets seeded."

# ── 3. ACL Policies ──────────────────────────────────────────────────────
echo ""
echo "--- Creating ACL policies ---"

# Backend policy: read secrets + sign/verify JWTs
vault policy write phantex-backend - <<'EOF'
# Read database and kafka secrets
path "secret/data/phantex/database" {
  capabilities = ["read"]
}
path "secret/data/phantex/kafka" {
  capabilities = ["read"]
}
path "secret/data/phantex/redis" {
  capabilities = ["read"]
}

# JWT signing (transit)
path "transit/sign/jwt-signing" {
  capabilities = ["update"]
}
path "transit/verify/jwt-signing" {
  capabilities = ["update"]
}

# Read public key for JWT verification
path "transit/keys/jwt-signing" {
  capabilities = ["read"]
}

# PKI — issue backend certificates (24h TTL)
path "pki_int/issue/phantex-backend" {
  capabilities = ["create", "update"]
}
EOF

# Gateway policy: read gateway secrets + verify JWTs
vault policy write phantex-gateway - <<'EOF'
path "secret/data/phantex/gateway" {
  capabilities = ["read"]
}
path "secret/data/phantex/kafka" {
  capabilities = ["read"]
}

# JWT verification only (no signing)
path "transit/verify/jwt-signing" {
  capabilities = ["update"]
}
path "transit/keys/jwt-signing" {
  capabilities = ["read"]
}

# PKI — issue gateway certificates (24h TTL)
path "pki_int/issue/phantex-gateway" {
  capabilities = ["create", "update"]
}
EOF

# Sensor policy: minimal — read own config only
vault policy write phantex-sensor - <<'EOF'
path "secret/data/phantex/sensor" {
  capabilities = ["read"]
}

# PKI — issue sensor certificates (24h TTL)
path "pki_int/issue/phantex-sensor" {
  capabilities = ["create", "update"]
}
EOF

echo "Policies created: phantex-backend, phantex-gateway, phantex-sensor"

# ── 4. AppRole Auth ──────────────────────────────────────────────────────
echo ""
echo "--- Enabling AppRole auth ---"
vault auth enable approle 2>/dev/null || echo "AppRole already enabled"

# Backend role
vault write auth/approle/role/phantex-backend \
    token_policies=phantex-backend \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Gateway role
vault write auth/approle/role/phantex-gateway \
    token_policies=phantex-gateway \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

# Sensor role
vault write auth/approle/role/phantex-sensor \
    token_policies=phantex-sensor \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0 \
    secret_id_num_uses=0

echo "AppRole roles created."

# ── 5. Print Role IDs + Secret IDs (dev only) ────────────────────────────
echo ""
echo "=== DEV CREDENTIALS (NOT FOR PRODUCTION) ==="
echo ""

for role in phantex-backend phantex-gateway phantex-sensor; do
    ROLE_ID=$(vault read -field=role_id auth/approle/role/$role/role-id)
    SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/$role/secret-id)
    echo "$role:"
    echo "  ROLE_ID=$ROLE_ID"
    echo "  SECRET_ID=<redacted — written to ${OUT_DIR:-/tmp}/approle-${role}.env>"
    # Write secret to file (not stdout) so it doesn't leak into CI logs
    mkdir -p "${OUT_DIR:-/tmp}"
    printf 'VAULT_ROLE_ID=%s\nVAULT_SECRET_ID=%s\n' "$ROLE_ID" "$SECRET_ID" > "${OUT_DIR:-/tmp}/approle-${role}.env"
    chmod 600 "${OUT_DIR:-/tmp}/approle-${role}.env"
    echo ""
done

echo "=== Vault setup complete ==="
