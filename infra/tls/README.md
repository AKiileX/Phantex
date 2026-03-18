# Phantex — TLS Certificate Infrastructure

## Overview

All inter-service communication in Phantex uses mTLS (mutual TLS 1.3). In development, self-signed certificates are auto-generated. In production, certificates are issued by HashiCorp Vault PKI (Block H2).

## Development Setup

Generate dev certificates:

```bash
cd infra/tls
chmod +x generate-dev-certs.sh
./generate-dev-certs.sh          # Output: ./certs/
./generate-dev-certs.sh /tmp/c   # Output: /tmp/c/
```

Docker Compose auto-generates certs on first `up` if `./infra/tls/certs/` doesn't exist.

## Certificate Chain

```
Phantex Dev Root CA (10 years, ECDSA P-256)
├── gateway.pem   — gRPC server (sensor ↔ gateway mTLS)
├── sensor.pem    — gRPC client cert (sensor identity)
├── backend.pem   — Backend API service
├── kafka.pem     — Kafka broker
├── postgres.pem  — PostgreSQL server
└── redis.pem     — Redis server
```

## Crypto Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Key algorithm | ECDSA P-256 | TLS 1.3 native, faster than RSA, NIST approved |
| Signature | SHA-256 | Standard for ECDSA P-256 |
| Min TLS version | 1.3 | No fallback to 1.2 — enforced in all services |
| Leaf cert TTL | 365 days (dev) / 24 hours (prod via Vault) | Dev: convenience. Prod: minimal blast radius |
| CA cert TTL | 10 years (dev) / 5 years (prod Vault root) | CA rotation is rare; leaf rotation is frequent |

## Security Notes

- **Development certs** are committed to `.gitignore` (never checked into git)
- **Production** uses Vault PKI with auto-rotation (24h leaf TTL)
- All services enforce `MinVersion: TLS 1.3` — no TLS 1.2 fallback
- ECDSA P-256 keys only — no RSA < 2048
- Each service gets its own identity cert (no wildcards)
- CA fingerprint pinning on sensor → gateway connection
