#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# PHANTEX — Air-Gap Installer
#
# Deploys PHANTEX from the air-gap bundle on a disconnected Kubernetes cluster.
# No internet access required.
#
# Usage:
#   ./install.sh                                  # default install
#   ./install.sh --registry registry.local:5000   # custom registry
#   ./install.sh --namespace phantex-prod          # custom namespace
#   ./install.sh --values helm/values-onprem.yaml  # custom Helm values
#   ./install.sh --skip-infra                      # use external infra
#   ./install.sh --docker-compose                  # non-K8s deployment
#
# Prerequisites:
#   - Kubernetes 1.27+ (or Docker 24+ for --docker-compose mode)
#   - kubectl, helm, docker/ctr CLI
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────
REGISTRY=""
NAMESPACE="phantex"
VALUES_FILE=""
SKIP_INFRA=false
DOCKER_COMPOSE=false
RUNTIME="docker"   # docker or ctr (containerd)

# ── Colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[install]${NC} $*"; }
pass() { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── Parse Args ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)        REGISTRY="$2"; shift 2 ;;
        --namespace)       NAMESPACE="$2"; shift 2 ;;
        --values)          VALUES_FILE="$2"; shift 2 ;;
        --skip-infra)      SKIP_INFRA=true; shift ;;
        --docker-compose)  DOCKER_COMPOSE=true; shift ;;
        --runtime)         RUNTIME="$2"; shift 2 ;;
        --help|-h)
            cat <<EOF
PHANTEX Air-Gap Installer

Usage: $0 [OPTIONS]

Options:
  --registry REGISTRY    Push images to this registry (e.g., registry.local:5000)
  --namespace NS         Kubernetes namespace (default: phantex)
  --values FILE          Helm values file (default: auto-detect)
  --skip-infra           Skip infrastructure (use external PG, Kafka, etc.)
  --docker-compose       Deploy with Docker Compose instead of Kubernetes
  --runtime docker|ctr   Container runtime for image loading (default: docker)
  -h, --help             Show this help
EOF
            exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

# ── Pre-flight ───────────────────────────────────────────────────────────

log "╔══════════════════════════════════════════════════════╗"
log "║  PHANTEX — Air-Gap Installer                        ║"
log "╚══════════════════════════════════════════════════════╝"
log ""

preflight_checks() {
    local errors=0

    if $DOCKER_COMPOSE; then
        command -v docker &>/dev/null || { fail "docker not found"; }
        # Check for compose v2 plugin or standalone v1
        if ! docker compose version &>/dev/null && ! command -v docker-compose &>/dev/null; then
            fail "docker compose not found (neither 'docker compose' plugin nor 'docker-compose' standalone)"
        fi
    else
        command -v kubectl &>/dev/null || { warn "kubectl not found"; ((errors++)); }
        command -v helm &>/dev/null    || { warn "helm not found"; ((errors++)); }

        if [[ "$RUNTIME" == "docker" ]]; then
            command -v docker &>/dev/null || { warn "docker not found"; ((errors++)); }
        elif [[ "$RUNTIME" == "ctr" ]]; then
            command -v ctr &>/dev/null || { warn "ctr (containerd) not found"; ((errors++)); }
        fi

        # Check K8s connectivity
        if command -v kubectl &>/dev/null; then
            kubectl cluster-info &>/dev/null || { warn "Cannot reach Kubernetes cluster"; ((errors++)); }
        fi
    fi

    if [[ $errors -gt 0 ]]; then
        fail "Pre-flight checks failed ($errors errors). Fix the above and retry."
    fi
    pass "Pre-flight checks passed"
}

preflight_checks

# ── Step 1: Load container images ────────────────────────────────────────

load_images() {
    log "Step 1/5: Loading container images..."

    local loaded=0
    local total=0

    for tarfile in "$SCRIPT_DIR"/images/*.tar; do
        [[ -f "$tarfile" ]] || continue
        ((total++))
        local name=$(basename "$tarfile" .tar)

        if [[ "$RUNTIME" == "ctr" ]]; then
            ctr -n k8s.io images import "$tarfile" 2>/dev/null && ((loaded++)) && pass "  $name"
        else
            docker load -i "$tarfile" 2>/dev/null && ((loaded++)) && pass "  $name"
        fi
    done

    pass "  Loaded $loaded/$total images"
}

# ── Step 2: Push to internal registry (if specified) ─────────────────────

push_to_registry() {
    if [[ -z "$REGISTRY" ]]; then
        log "Step 2/5: No registry specified — using local images"
        return 0
    fi

    log "Step 2/5: Pushing images to $REGISTRY ..."

    for tarfile in "$SCRIPT_DIR"/images/*.tar; do
        [[ -f "$tarfile" ]] || continue

        # Get original image name from the already-loaded image
        # (images were loaded in step 1, so just inspect the tar metadata)
        local original
        original=$(tar -xf "$tarfile" -O manifest.json 2>/dev/null | \
            python3 -c "import sys,json; tags=json.load(sys.stdin)[0].get('RepoTags',[]); print(tags[0] if tags else '')" 2>/dev/null || \
            docker load -i "$tarfile" 2>/dev/null | grep "Loaded image" | sed 's/Loaded image: //')

        if [[ -n "$original" ]]; then
            # Re-tag for internal registry, preserving multi-segment names
            # e.g. apache/kafka:3.7.0 → registry.local:5000/apache/kafka:3.7.0
            #      ghcr.io/phantex/phantex-backend:0.2.0 → registry.local:5000/phantex-backend:0.2.0
            local base
            # Strip known source registries but keep org/image paths
            base=$(echo "$original" | sed -E 's|^(ghcr\.io|docker\.io|registry\.hub\.docker\.com)/||')
            local new_tag="${REGISTRY}/${base}"

            docker tag "$original" "$new_tag"
            docker push "$new_tag"
            pass "  $new_tag"
        fi
    done
}

# ── Step 3: Apply database migrations ────────────────────────────────────

apply_migrations() {
    log "Step 3/5: Database migrations..."

    if $SKIP_INFRA; then
        warn "  --skip-infra: ensure PostgreSQL migrations are applied manually"
        warn "  Migration files: $SCRIPT_DIR/migrations/"
        return 0
    fi

    # For K8s: wait for PostgreSQL pod, then run migrations
    if ! $DOCKER_COMPOSE; then
        log "  Waiting for PostgreSQL pod..."
        kubectl -n "$NAMESPACE" wait --for=condition=ready pod -l app=postgres --timeout=120s 2>/dev/null || {
            warn "  PostgreSQL pod not found — apply migrations manually"
            return 0
        }

        local pg_pod
        pg_pod=$(kubectl -n "$NAMESPACE" get pod -l app=postgres -o jsonpath='{.items[0].metadata.name}')

        for sql in "$SCRIPT_DIR"/migrations/*.sql; do
            [[ -f "$sql" ]] || continue
            local name=$(basename "$sql")
            kubectl -n "$NAMESPACE" exec -i "$pg_pod" -- \
                psql -U phantex_admin -d phantex < "$sql" 2>/dev/null && \
                pass "  Applied: $name" || \
                warn "  Skipped (already applied?): $name"
        done
    fi
}

# ── Step 4: Deploy with Helm or Docker Compose ──────────────────────────

deploy_kubernetes() {
    log "Step 4/5: Deploying to Kubernetes..."

    kubectl create namespace "$NAMESPACE" 2>/dev/null || true

    # Build helm args array to avoid word-splitting issues
    local -a helm_args=(upgrade --install phantex)

    # Find chart
    local chart
    chart=$(find "$SCRIPT_DIR/helm" -name "phantex-*.tgz" 2>/dev/null | head -1)
    if [[ -z "$chart" ]]; then
        chart="$SCRIPT_DIR/helm/phantex"
    fi
    helm_args+=("$chart")

    helm_args+=(--namespace "$NAMESPACE" --create-namespace --atomic --timeout 10m)

    # Determine values file
    if [[ -n "$VALUES_FILE" ]]; then
        helm_args+=(-f "$VALUES_FILE")
    elif [[ -f "$SCRIPT_DIR/helm/values-onprem.yaml" ]]; then
        helm_args+=(-f "$SCRIPT_DIR/helm/values-onprem.yaml")
    fi

    # Set registry override if specified
    if [[ -n "$REGISTRY" ]]; then
        helm_args+=(--set "global.imageRegistry=$REGISTRY")
    fi

    helm_args+=(--wait)

    # Install or upgrade
    helm "${helm_args[@]}"

    pass "  Helm release deployed"
}

deploy_docker_compose() {
    log "Step 4/5: Deploying with Docker Compose..."

    local compose_file="$SCRIPT_DIR/config/docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
        fail "docker-compose.yml not found in config/"
    fi

    # Deploy in a subshell to avoid changing the parent cwd
    (
        cd "$SCRIPT_DIR/config"
        # Use docker compose (v2 plugin) or docker-compose (v1 standalone)
        if docker compose version &>/dev/null; then
            docker compose -f docker-compose.yml up -d
        elif command -v docker-compose &>/dev/null; then
            docker-compose -f docker-compose.yml up -d
        else
            fail "No Docker Compose implementation found"
        fi
    )

    pass "  Docker Compose stack started"
}

deploy() {
    if $DOCKER_COMPOSE; then
        deploy_docker_compose
    else
        deploy_kubernetes
    fi
}

# ── Step 5: Health Check ─────────────────────────────────────────────────

health_check() {
    log "Step 5/5: Running health checks..."

    local retries=30
    local delay=10
    local ok=false

    if $DOCKER_COMPOSE; then
        for i in $(seq 1 $retries); do
            if curl -sf http://localhost:8000/healthz &>/dev/null; then
                ok=true
                break
            fi
            log "  Waiting for backend... ($i/$retries)"
            sleep $delay
        done
    else
        # K8s: check pod readiness using jsonpath for accurate container counts
        for i in $(seq 1 $retries); do
            local not_ready
            not_ready=$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null | \
                       grep -cvE '([0-9]+)/\1\s+Running|Completed' || true)
            local total
            total=$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null | \
                   grep -cv 'Completed' || true)

            if [[ "$total" -gt 0 && "$not_ready" -eq 0 ]]; then
                ok=true
                break
            fi
            log "  Waiting for pods... ($((total - not_ready))/$total ready, attempt $i/$retries)"
            sleep $delay
        done
    fi

    if $ok; then
        pass "  All health checks passed"
    else
        fail "  Health checks failed after $((retries * delay))s"
    fi
}

# ── Execute ──────────────────────────────────────────────────────────────

load_images
push_to_registry
apply_migrations
deploy
health_check

log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
pass "PHANTEX installation complete!"
log ""
if $DOCKER_COMPOSE; then
    log "  Dashboard:  http://localhost:3000"
    log "  API:        http://localhost:8000"
    log "  Gateway:    localhost:50051 (gRPC)"
else
    log "  Namespace:    $NAMESPACE"
    log "  Dashboard:    kubectl -n $NAMESPACE port-forward svc/phantex-dashboard 3000:80"
    log "  API:          kubectl -n $NAMESPACE port-forward svc/phantex-backend 8000:8000"
fi
log ""
log "  Default admin: admin@localhost (change immediately via PHANTEX_ADMIN_EMAIL / PHANTEX_ADMIN_PASSWORD)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
