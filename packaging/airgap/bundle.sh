#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# PHANTEX — Air-Gap Bundle Builder
#
# Exports all container images, Helm charts, configs, and scripts into a
# single self-contained archive for disconnected deployment.
#
# Usage:
#   ./bundle.sh                        # build full bundle
#   ./bundle.sh --registry ghcr.io/org # custom source registry
#   ./bundle.sh --version 0.2.0        # specific version
#
# Output: packaging/airgap/dist/phantex-airgap-{version}.tar.gz
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${VERSION:-0.2.0}"
REGISTRY="${REGISTRY:-ghcr.io/phantex}"
DIST="$SCRIPT_DIR/dist"
STAGING="$SCRIPT_DIR/.staging"

# ── Colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[bundle]${NC} $*"; }
pass() { echo -e "${GREEN}[  OK  ]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── Parse Args ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry) REGISTRY="$2"; shift 2 ;;
        --version)  VERSION="$2";  shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--registry REGISTRY] [--version VERSION]"
            exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

# ── Application images to export ─────────────────────────────────────────
APP_IMAGES=(
    "${REGISTRY}/phantex-backend:${VERSION}"
    "${REGISTRY}/phantex-gateway:${VERSION}"
    "${REGISTRY}/phantex-dashboard:${VERSION}"
    "${REGISTRY}/phantex-trust-engine:${VERSION}"
    "${REGISTRY}/phantex-sensor:${VERSION}"
)

# ── Infrastructure images ────────────────────────────────────────────────
INFRA_IMAGES=(
    "postgres:16-alpine"
    "apache/kafka:3.7.0"
    "redis:7-alpine"
    "clickhouse/clickhouse-server:24.1-alpine"
    "neo4j:5.17-community"
)

ALL_IMAGES=("${APP_IMAGES[@]}" "${INFRA_IMAGES[@]}")

# ── Clean & Prepare ─────────────────────────────────────────────────────
log "╔══════════════════════════════════════════════════╗"
log "║  PHANTEX — Air-Gap Bundle Builder v${VERSION}       ║"
log "╚══════════════════════════════════════════════════╝"
log ""

rm -rf "$STAGING"
mkdir -p "$STAGING"/{images,helm,config,scripts,models,migrations}

# Cleanup staging on error or interrupt
cleanup() { rm -rf "$STAGING" 2>/dev/null || true; }
trap cleanup ERR INT TERM

# ── Step 1: Export container images ──────────────────────────────────────
log "Step 1/6: Exporting container images..."

for img in "${ALL_IMAGES[@]}"; do
    sanitized=$(echo "$img" | sed 's|[/:]|_|g')
    tarfile="$STAGING/images/${sanitized}.tar"
    log "  Saving $img ..."

    if docker image inspect "$img" &>/dev/null; then
        docker save "$img" -o "$tarfile"
        size=$(du -sh "$tarfile" | cut -f1)
        pass "  $img → ${sanitized}.tar ($size)"
    else
        log "  Pulling $img ..."
        docker pull "$img"
        docker save "$img" -o "$tarfile"
        size=$(du -sh "$tarfile" | cut -f1)
        pass "  $img → ${sanitized}.tar ($size)"
    fi
done

# ── Step 2: Package Helm chart ───────────────────────────────────────────
log "Step 2/6: Packaging Helm chart..."

if command -v helm &>/dev/null; then
    helm package "$ROOT/infra/helm/phantex" \
        --version "$VERSION" \
        --app-version "$VERSION" \
        --destination "$STAGING/helm/"
    pass "  Helm chart packaged"
else
    # Fallback: copy chart directory
    cp -r "$ROOT/infra/helm/phantex" "$STAGING/helm/"
    pass "  Helm chart copied (helm CLI not available)"
fi

# Copy all values files
cp "$ROOT/infra/helm/phantex/values.yaml" "$STAGING/helm/values-default.yaml"
cp "$ROOT/infra/helm/phantex/values-prod.yaml" "$STAGING/helm/" 2>/dev/null || true
cp "$ROOT/infra/helm/phantex/values-staging.yaml" "$STAGING/helm/" 2>/dev/null || true
if [[ -f "$ROOT/infra/helm/phantex/values-onprem.yaml" ]]; then
    cp "$ROOT/infra/helm/phantex/values-onprem.yaml" "$STAGING/helm/"
fi

# ── Step 3: Config templates ─────────────────────────────────────────────
log "Step 3/6: Copying configuration templates..."

# Docker compose for non-K8s deployments
cp "$ROOT/docker-compose.dev.yml" "$STAGING/config/docker-compose.yml"

# Infra configs
cp -r "$ROOT/infra/clickhouse" "$STAGING/config/" 2>/dev/null || true
cp -r "$ROOT/infra/kafka"      "$STAGING/config/" 2>/dev/null || true
cp -r "$ROOT/infra/neo4j"      "$STAGING/config/" 2>/dev/null || true
cp -r "$ROOT/infra/postgres"   "$STAGING/config/" 2>/dev/null || true
cp -r "$ROOT/infra/tls"        "$STAGING/config/" 2>/dev/null || true

# Backend config template
cp "$ROOT/packaging/backend/phantex.yaml.example" "$STAGING/config/phantex.yaml.example" 2>/dev/null || true

pass "  Config templates copied"

# ── Step 4: ML models ───────────────────────────────────────────────────
log "Step 4/6: Packaging ML model artifacts..."

if [[ -d "$ROOT/backend/models" ]]; then
    cp -r "$ROOT/backend/models" "$STAGING/models/"
    model_size=$(du -sh "$STAGING/models" | cut -f1)
    pass "  Models packaged ($model_size)"
else
    log "  WARNING: No models directory found — skipping"
fi

# ── Step 5: Database migrations ──────────────────────────────────────────
log "Step 5/6: Copying database migrations..."

cp -r "$ROOT/backend/migrations" "$STAGING/migrations/"
cp "$ROOT/migrations"/*.sql "$STAGING/migrations/" 2>/dev/null || true

pass "  Migrations copied"

# ── Step 6: Install script + docs ────────────────────────────────────────
log "Step 6/6: Adding install script and documentation..."

cp "$SCRIPT_DIR/install.sh" "$STAGING/install.sh"
chmod +x "$STAGING/install.sh"

# Add README
cat > "$STAGING/README.md" << 'HEREDOC'
# PHANTEX Air-Gap Installation Bundle

This archive contains everything needed to deploy PHANTEX in a disconnected
(air-gapped) environment. No internet access is required.

## Contents

| Directory | Contents |
|-----------|----------|
| `images/` | Docker container images as tar archives |
| `helm/` | Helm chart + values files |
| `config/` | Infrastructure configuration templates |
| `models/` | Pre-trained ML model artifacts |
| `migrations/` | Database migration SQL files |
| `install.sh` | Automated installer script |

## Quick Start

```bash
tar xzf phantex-airgap-*.tar.gz
cd phantex-airgap/
sudo ./install.sh
```

## Detailed Installation

See `install.sh --help` for options:

```bash
./install.sh \
    --registry registry.internal:5000 \
    --namespace phantex \
    --values helm/values-onprem.yaml \
    --skip-infra          # if using external PostgreSQL, Kafka, etc.
```

## Requirements

- Kubernetes 1.27+ (K3s, RKE2, or OpenShift 4.12+)
- `kubectl` and `helm` CLI
- Docker or containerd for image loading
- 16 GB RAM, 4 CPU cores minimum
- 100 GB storage
HEREDOC

pass "  Install script and docs added"

# ── Build final archive ─────────────────────────────────────────────────
log ""
log "Building final archive..."
mkdir -p "$DIST"

BUNDLE="$DIST/phantex-airgap-${VERSION}.tar.gz"
tar czf "$BUNDLE" -C "$STAGING" .

# Compute checksum
sha256sum "$BUNDLE" > "${BUNDLE}.sha256"

# Summary
bundle_size=$(du -sh "$BUNDLE" | cut -f1)
image_count=${#ALL_IMAGES[@]}

log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
pass "Air-gap bundle created!"
log "  Archive: $BUNDLE ($bundle_size)"
log "  SHA-256: $(cat "${BUNDLE}.sha256" | cut -d' ' -f1)"
log "  Images:  $image_count"
log "  Version: $VERSION"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Cleanup staging
rm -rf "$STAGING"
