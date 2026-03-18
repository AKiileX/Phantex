#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# PHANTEX — On-Premises Upgrade Script
#
# Safe upgrade path with automatic rollback on failure.
# Supports: Helm-based K8s and Docker Compose deployments.
#
# Usage:
#   ./upgrade.sh --version 0.3.0 --bundle phantex-airgap-0.3.0.tar.gz
#   ./upgrade.sh --version 0.3.0 --bundle ... --docker-compose
#   ./upgrade.sh rollback                # rollback to previous version
#   ./upgrade.sh status                  # check current version + history
#
# Flow:
#   1. Pre-flight validation
#   2. Backup current state (DB + config + Helm release)
#   3. Load new container images
#   4. Apply database migrations
#   5. Helm upgrade --atomic (or docker compose up)
#   6. Health check gates
#   7. On failure → automatic rollback
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────
VERSION=""
BUNDLE=""
NAMESPACE="phantex"
VALUES_FILE=""
DOCKER_COMPOSE=false
BACKUP_DIR="/var/lib/phantex/backups"
HEALTH_TIMEOUT=300          # 5 minutes
HEALTH_INTERVAL=10          # check every 10s

# ── Colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[upgrade]${NC} $*"; }
pass() { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

# ── Parse Args ───────────────────────────────────────────────────────────
COMMAND="upgrade"

if [[ "${1:-}" == "rollback" ]]; then
    COMMAND="rollback"
    shift
elif [[ "${1:-}" == "status" ]]; then
    COMMAND="status"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)         VERSION="$2"; shift 2 ;;
        --bundle)          BUNDLE="$2"; shift 2 ;;
        --namespace)       NAMESPACE="$2"; shift 2 ;;
        --values)          VALUES_FILE="$2"; shift 2 ;;
        --docker-compose)  DOCKER_COMPOSE=true; shift ;;
        --backup-dir)      BACKUP_DIR="$2"; shift 2 ;;
        --health-timeout)  HEALTH_TIMEOUT="$2"; shift 2 ;;
        --help|-h)
            cat <<EOF
PHANTEX On-Premises Upgrade Tool

Usage:
  $0 --version VERSION --bundle BUNDLE [OPTIONS]
  $0 rollback [OPTIONS]
  $0 status [OPTIONS]

Commands:
  upgrade (default)  Upgrade to a new version
  rollback           Rollback to the previous version
  status             Show current version and upgrade history

Options:
  --version VERSION    Target version (required for upgrade)
  --bundle BUNDLE      Path to air-gap bundle .tar.gz (required for upgrade)
  --namespace NS       Kubernetes namespace (default: phantex)
  --values FILE        Helm values override file
  --docker-compose     Use Docker Compose instead of Kubernetes
  --backup-dir DIR     Backup directory (default: /var/lib/phantex/backups)
  --health-timeout SEC Health check timeout in seconds (default: 300)
EOF
            exit 0 ;;
        *) fail "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Utility Functions ────────────────────────────────────────────────────

timestamp() { date +%Y%m%d-%H%M%S; }

get_current_version() {
    if $DOCKER_COMPOSE; then
        docker inspect phantex-backend 2>/dev/null | \
            sed -n 's/.*"PHANTEX_VERSION=\([^"]*\)".*/\1/p' | head -1 || echo "unknown"
    else
        helm list -n "$NAMESPACE" -o json 2>/dev/null | \
            sed -n 's/.*"app_version":"\([^"]*\)".*/\1/p' | head -1 || echo "unknown"
    fi
}

write_history() {
    local action="$1" from_ver="$2" to_ver="$3" status="$4"
    mkdir -p "$BACKUP_DIR"
    echo "{\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"action\": \"$action\", \"from\": \"$from_ver\", \"to\": \"$to_ver\", \"status\": \"$status\"}" \
        >> "$BACKUP_DIR/upgrade-history.jsonl"
}

# ── Status Command ───────────────────────────────────────────────────────

cmd_status() {
    log "PHANTEX Deployment Status"
    log ""

    local current
    current=$(get_current_version)
    log "  Current version: $current"
    log "  Namespace:       $NAMESPACE"
    log ""

    if [[ -f "$BACKUP_DIR/upgrade-history.jsonl" ]]; then
        log "  Upgrade History (last 10):"
        tail -10 "$BACKUP_DIR/upgrade-history.jsonl" | while IFS= read -r line; do
            local ts action from to status
            ts=$(echo "$line" | sed -n 's/.*"timestamp":"\([^"]*\)".*/\1/p')
            action=$(echo "$line" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p')
            from=$(echo "$line" | sed -n 's/.*"from":"\([^"]*\)".*/\1/p')
            to=$(echo "$line" | sed -n 's/.*"to":"\([^"]*\)".*/\1/p')
            status=$(echo "$line" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')
            printf "    %s  %-10s  %s → %s  [%s]\n" "$ts" "$action" "$from" "$to" "$status"
        done
    else
        log "  No upgrade history found."
    fi

    if ! $DOCKER_COMPOSE; then
        log ""
        log "  Helm Releases:"
        helm list -n "$NAMESPACE" 2>/dev/null || warn "  Could not list Helm releases"
        log ""
        log "  Pod Status:"
        kubectl -n "$NAMESPACE" get pods 2>/dev/null || warn "  Could not list pods"
    fi
}

# ── Backup ───────────────────────────────────────────────────────────────

backup_current() {
    local ts
    ts=$(timestamp)
    local current_ver
    current_ver=$(get_current_version)
    local backup_path="$BACKUP_DIR/$ts-v$current_ver"

    mkdir -p "$backup_path"

    log "  Creating backup → $backup_path"

    # Backup Helm release
    if ! $DOCKER_COMPOSE; then
        helm get values phantex -n "$NAMESPACE" > "$backup_path/helm-values.yaml" 2>/dev/null || true
        helm get manifest phantex -n "$NAMESPACE" > "$backup_path/helm-manifest.yaml" 2>/dev/null || true
    fi

    # Backup database (schema + small tables like policies, config)
    if ! $DOCKER_COMPOSE; then
        local pg_pod
        pg_pod=$(kubectl -n "$NAMESPACE" get pod -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
        if [[ -n "$pg_pod" ]]; then
            kubectl -n "$NAMESPACE" exec "$pg_pod" -- \
                pg_dump -U phantex_admin -d phantex --schema-only \
                > "$backup_path/schema.sql" 2>/dev/null || warn "  Could not backup schema"

            # Backup config tables (small, critical)
            for table in response_config response_policies drift_policy detection_policies; do
                kubectl -n "$NAMESPACE" exec "$pg_pod" -- \
                    pg_dump -U phantex_admin -d phantex --data-only -t "$table" \
                    > "$backup_path/${table}.sql" 2>/dev/null || true
            done
            pass "  Database backup complete"
        else
            warn "  PostgreSQL pod not found — skipping DB backup"
        fi
    else
        # Docker Compose: direct pg_dump
        docker exec phantex-postgres pg_dump -U phantex_admin -d phantex --schema-only \
            > "$backup_path/schema.sql" 2>/dev/null || warn "  Could not backup schema"
    fi

    # Record backup metadata
    echo "{\"version\": \"$current_ver\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"path\": \"$backup_path\"}" \
        > "$backup_path/metadata.json"

    echo "$backup_path"
}

# ── Health Check ─────────────────────────────────────────────────────────

health_check_loop() {
    local elapsed=0

    while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
        local healthy=true

        if $DOCKER_COMPOSE; then
            # Check backend health endpoint
            if ! curl -sf http://localhost:8000/healthz &>/dev/null; then
                healthy=false
            fi
        else
            # Check all pods are ready (handles multi-container pods like 2/2, 3/3)
            local not_ready
            not_ready=$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null | \
                       grep -cvE '([0-9]+)/\1\s+Running|Completed' || true)
            if [[ "$not_ready" -gt 0 ]]; then
                healthy=false
            fi

            # Check backend health endpoint via port-forward (if available)
            local backend_pod
            backend_pod=$(kubectl -n "$NAMESPACE" get pod -l app=phantex-backend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
            if [[ -n "$backend_pod" ]]; then
                kubectl -n "$NAMESPACE" exec "$backend_pod" -- \
                    python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" \
                    &>/dev/null || healthy=false
            fi
        fi

        if $healthy; then
            return 0
        fi

        log "  Health check pending... ($elapsed/${HEALTH_TIMEOUT}s)"
        sleep "$HEALTH_INTERVAL"
        ((elapsed += HEALTH_INTERVAL))
    done

    return 1
}

# ── Upgrade Command ──────────────────────────────────────────────────────

cmd_upgrade() {
    if [[ -z "$VERSION" ]]; then
        fail "ERROR: --version is required"
        exit 1
    fi
    if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
        fail "ERROR: --bundle must point to a valid air-gap bundle"
        exit 1
    fi

    local current_ver
    current_ver=$(get_current_version)

    log "╔══════════════════════════════════════════════════════╗"
    log "║  PHANTEX — On-Premises Upgrade                      ║"
    log "╚══════════════════════════════════════════════════════╝"
    log ""
    log "  Current version: $current_ver"
    log "  Target version:  $VERSION"
    log "  Bundle:          $BUNDLE"
    log ""

    # Step 1: Pre-flight
    log "Step 1/6: Pre-flight validation..."
    if $DOCKER_COMPOSE; then
        command -v docker &>/dev/null || { fail "docker not found"; exit 1; }
    else
        command -v kubectl &>/dev/null || { fail "kubectl not found"; exit 1; }
        command -v helm &>/dev/null    || { fail "helm not found"; exit 1; }
    fi
    pass "  Pre-flight passed"

    # Step 2: Extract bundle
    log "Step 2/6: Extracting bundle..."
    local extract_dir
    extract_dir=$(mktemp -d)
    # Cleanup extract dir on error or interrupt
    trap "rm -rf '$extract_dir' 2>/dev/null || true" ERR INT TERM
    tar xzf "$BUNDLE" -C "$extract_dir"
    pass "  Bundle extracted → $extract_dir"

    # Step 3: Backup
    log "Step 3/6: Backing up current deployment..."
    local backup_path
    backup_path=$(backup_current)
    pass "  Backup → $backup_path"

    # Step 4: Load new images
    log "Step 4/6: Loading new container images..."
    for tarfile in "$extract_dir"/images/*.tar; do
        [[ -f "$tarfile" ]] || continue
        docker load -i "$tarfile" 2>/dev/null || true
    done
    pass "  Images loaded"

    # Step 5: Database migrations
    log "Step 5/6: Applying database migrations..."
    if [[ -d "$extract_dir/migrations" ]]; then
        if ! $DOCKER_COMPOSE; then
            local pg_pod
            pg_pod=$(kubectl -n "$NAMESPACE" get pod -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
            if [[ -n "$pg_pod" ]]; then
                for sql in "$extract_dir"/migrations/*.sql; do
                    [[ -f "$sql" ]] || continue
                    local sql_name
                    sql_name=$(basename "$sql")
                    if kubectl -n "$NAMESPACE" exec -i "$pg_pod" -- \
                        psql -U phantex_admin -d phantex < "$sql" 2>/dev/null; then
                        pass "  Applied: $sql_name"
                    else
                        warn "  Migration warning: $sql_name (may already be applied)"
                    fi
                done
            fi
        else
            for sql in "$extract_dir"/migrations/*.sql; do
                [[ -f "$sql" ]] || continue
                local sql_name
                sql_name=$(basename "$sql")
                if docker exec -i phantex-postgres \
                    psql -U phantex_admin -d phantex < "$sql" 2>/dev/null; then
                    pass "  Applied: $sql_name"
                else
                    warn "  Migration warning: $sql_name (may already be applied)"
                fi
            done
        fi
    fi
    pass "  Migrations applied"

    # Step 6: Deploy
    log "Step 6/6: Deploying v${VERSION}..."

    if $DOCKER_COMPOSE; then
        if [[ -f "$extract_dir/config/docker-compose.yml" ]]; then
            (
                cd "$extract_dir/config"
                docker compose -f docker-compose.yml up -d --force-recreate
            )
        fi
    else
        # Helm upgrade with --atomic for automatic rollback on failure
        local -a helm_args=(upgrade phantex)

        local chart
        chart=$(find "$extract_dir/helm" -name "phantex-*.tgz" 2>/dev/null | head -1)
        if [[ -z "$chart" ]]; then
            chart="$extract_dir/helm/phantex"
        fi
        helm_args+=("$chart")

        helm_args+=(--namespace "$NAMESPACE" --atomic --timeout 10m)
        helm_args+=(--set "global.appVersion=$VERSION")

        if [[ -n "$VALUES_FILE" ]]; then
            helm_args+=(-f "$VALUES_FILE")
        elif [[ -f "$extract_dir/helm/values-onprem.yaml" ]]; then
            helm_args+=(-f "$extract_dir/helm/values-onprem.yaml")
        fi

        helm_args+=(--wait)
        helm "${helm_args[@]}"
    fi

    # Health check gate
    log ""
    log "Running health checks..."
    if health_check_loop; then
        pass "Health checks passed"
        write_history "upgrade" "$current_ver" "$VERSION" "success"
        log ""
        log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        pass "Upgrade to v${VERSION} complete!"
        log "  Previous: $current_ver → Backup: $backup_path"
        log "  Rollback: $0 rollback"
        log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    else
        fail "Health checks failed — initiating rollback..."
        write_history "upgrade" "$current_ver" "$VERSION" "failed"

        # Automatic rollback
        do_rollback "$backup_path" "$current_ver"
    fi

    # Cleanup
    rm -rf "$extract_dir"
}

# ── Rollback ─────────────────────────────────────────────────────────────

do_rollback() {
    local backup_path="${1:-}"
    local target_ver="${2:-}"

    # Find latest backup if not specified
    if [[ -z "$backup_path" ]]; then
        backup_path=$(ls -d "$BACKUP_DIR"/*/ 2>/dev/null | sort -r | head -1)
        if [[ -z "$backup_path" ]]; then
            fail "No backups found in $BACKUP_DIR"
            exit 1
        fi
    fi

    if [[ -z "$target_ver" && -f "$backup_path/metadata.json" ]]; then
        target_ver=$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' "$backup_path/metadata.json" || echo "unknown")
    fi

    local current_ver
    current_ver=$(get_current_version)

    log "Rolling back: $current_ver → $target_ver"
    log "  Backup: $backup_path"

    if $DOCKER_COMPOSE; then
        # Docker Compose: restore DB + restart
        if [[ -f "$backup_path/schema.sql" ]]; then
            docker exec -i phantex-postgres \
                psql -U phantex_admin -d phantex < "$backup_path/schema.sql" 2>/dev/null || true
        fi
        docker compose restart 2>/dev/null || true
    else
        # Helm: rollback to previous revision
        helm rollback phantex -n "$NAMESPACE" --wait --timeout 5m 2>/dev/null || {
            # If Helm rollback fails, restore from backup values
            if [[ -f "$backup_path/helm-values.yaml" ]]; then
                local chart
                chart=$(helm list -n "$NAMESPACE" -o json | \
                    sed -n 's/.*"chart":"\([^"]*\)".*/\1/p' | head -1)
                helm upgrade phantex "$chart" \
                    --namespace "$NAMESPACE" \
                    -f "$backup_path/helm-values.yaml" \
                    --atomic --timeout 5m --wait
            fi
        }
    fi

    # Verify health after rollback
    log "Verifying rollback..."
    if health_check_loop; then
        pass "Rollback successful: now running v$target_ver"
        write_history "rollback" "$current_ver" "$target_ver" "success"
    else
        fail "CRITICAL: Rollback health check failed!"
        fail "Manual intervention required."
        write_history "rollback" "$current_ver" "$target_ver" "failed"
        exit 2
    fi
}

cmd_rollback() {
    log "╔══════════════════════════════════════════════════════╗"
    log "║  PHANTEX — Rollback to Previous Version             ║"
    log "╚══════════════════════════════════════════════════════╝"
    log ""
    do_rollback "" ""
}

# ── Main Dispatch ────────────────────────────────────────────────────────

case "$COMMAND" in
    upgrade)  cmd_upgrade  ;;
    rollback) cmd_rollback ;;
    status)   cmd_status   ;;
    *)        fail "Unknown command: $COMMAND" ;;
esac
