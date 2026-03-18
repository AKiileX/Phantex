#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ──────────────────────────────────────────────────────────────────────────────
# Phantex — Development TLS Certificate Generator
#
# Generates a full CA chain + leaf certificates for local mTLS development.
# In production, certificates come from Vault PKI (H2).
#
# Usage:  ./generate-dev-certs.sh [output_dir]
#         Default output: ./certs/
#
# Generated files:
#   ca.pem / ca-key.pem           — Root CA (self-signed, 10y)
#   gateway.pem / gateway-key.pem — Gateway server cert (365d)
#   sensor.pem / sensor-key.pem   — Sensor client cert  (365d)
#   backend.pem / backend-key.pem — Backend service cert (365d)
#   kafka.pem / kafka-key.pem     — Kafka broker cert   (365d)
#   postgres.pem / postgres-key.pem — PostgreSQL cert   (365d)
#   redis.pem / redis-key.pem     — Redis cert          (365d)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

OUT_DIR="${1:-./certs}"
DAYS_CA=3650
DAYS_LEAF=365
KEY_ALG="ec"
KEY_CURVE="prime256v1"   # ECDSA P-256 (NIST standard, TLS 1.3 compatible)

echo "=== Phantex Dev TLS Certificate Generator ==="
echo "Output directory: ${OUT_DIR}"

mkdir -p "${OUT_DIR}"

# ── Helper: generate a leaf cert signed by the CA ─────────────────────────────
generate_leaf() {
    local name="$1"
    local cn="$2"
    local san="$3"
    local eku="${4:-serverAuth,clientAuth}"  # Role-specific EKU

    echo "  Generating ${name} certificate (CN=${cn}, SAN=${san}, EKU=${eku})..."

    # Private key
    openssl ecparam -genkey -name "${KEY_CURVE}" -noout \
        -out "${OUT_DIR}/${name}-key.pem" 2>/dev/null

    # CSR
    openssl req -new \
        -key "${OUT_DIR}/${name}-key.pem" \
        -out "${OUT_DIR}/${name}.csr" \
        -subj "/C=US/ST=CA/O=Phantex Dev/OU=${name}/CN=${cn}" \
        2>/dev/null

    # Sign with CA
    openssl x509 -req \
        -in "${OUT_DIR}/${name}.csr" \
        -CA "${OUT_DIR}/ca.pem" \
        -CAkey "${OUT_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "${OUT_DIR}/${name}.pem" \
        -days "${DAYS_LEAF}" \
        -sha256 \
        -extfile <(printf "subjectAltName=${san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=${eku}") \
        2>/dev/null

    # Cleanup CSR
    rm -f "${OUT_DIR}/${name}.csr"
}

# ── Step 1: Root CA ──────────────────────────────────────────────────────────
echo "[1/8] Generating Root CA..."
openssl ecparam -genkey -name "${KEY_CURVE}" -noout \
    -out "${OUT_DIR}/ca-key.pem" 2>/dev/null
openssl req -new -x509 \
    -key "${OUT_DIR}/ca-key.pem" \
    -out "${OUT_DIR}/ca.pem" \
    -days "${DAYS_CA}" \
    -sha256 \
    -subj "/C=US/ST=CA/O=Phantex Dev/OU=Security/CN=Phantex Dev Root CA" \
    2>/dev/null

echo "  CA certificate generated (valid ${DAYS_CA} days)"

# ── Step 2: Leaf certificates ────────────────────────────────────────────────
echo "[2/8] Generating Gateway certificate..."
generate_leaf "gateway" "phantex-gateway" "DNS:phantex-gateway,DNS:gateway,DNS:localhost,IP:127.0.0.1" "serverAuth"

echo "[3/8] Generating Sensor certificate..."
generate_leaf "sensor" "phantex-sensor" "DNS:phantex-sensor,DNS:sensor,DNS:localhost,IP:127.0.0.1" "clientAuth"

echo "[4/8] Generating Backend certificate..."
generate_leaf "backend" "phantex-backend" "DNS:phantex-backend,DNS:backend,DNS:localhost,IP:127.0.0.1" "serverAuth,clientAuth"

echo "[5/8] Generating Kafka certificate..."
generate_leaf "kafka" "phantex-kafka" "DNS:phantex-kafka,DNS:kafka,DNS:localhost,IP:127.0.0.1" "serverAuth"

echo "[6/8] Generating PostgreSQL certificate..."
generate_leaf "postgres" "phantex-postgres" "DNS:phantex-postgres,DNS:postgres,DNS:localhost,IP:127.0.0.1" "serverAuth"

echo "[7/8] Generating Redis certificate..."
generate_leaf "redis" "phantex-redis" "DNS:phantex-redis,DNS:redis,DNS:localhost,IP:127.0.0.1" "serverAuth"

# ── Step 3: Set permissions ──────────────────────────────────────────────────
echo "[8/8] Setting file permissions..."
chmod 644 "${OUT_DIR}"/*.pem
chmod 600 "${OUT_DIR}"/*-key.pem

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Certificates generated successfully ==="
echo ""
echo "Files:"
ls -la "${OUT_DIR}"/*.pem
echo ""
echo "CA fingerprint (SHA-256):"
openssl x509 -in "${OUT_DIR}/ca.pem" -noout -fingerprint -sha256
echo ""
echo "To verify a cert:  openssl verify -CAfile ${OUT_DIR}/ca.pem ${OUT_DIR}/gateway.pem"
echo "To inspect a cert: openssl x509 -in ${OUT_DIR}/gateway.pem -text -noout"
echo ""
echo "WARNING: These certificates are for DEVELOPMENT ONLY."
echo "         Production uses Vault PKI"
