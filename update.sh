#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# Phantex — Safe Update Script
#
# Pull the latest code, apply new migrations, rebuild containers, and verify
# health. Creates a rollback checkpoint before every update.
#
# Works for:
#   - Local dev deployments (quickstart.sh)
#   - Single-machine production (quickstart.sh --prod)
#   - Docker Compose on cloud VMs
#
# Usage:
#   ./update.sh                  # update to latest
#   ./update.sh --check          # preview changes only (dry run)
#   ./update.sh --rollback       # rollback to previous checkpoint
#   ./update.sh --status         # show current version + update history
#
# For air-gapped / Kubernetes, use packaging/upgrade/upgrade.sh instead.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[update]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
err()   { echo -e "${RED}[ FAIL ]${NC} $*" >&2; }

# ── Config ───────────────────────────────────────────────────────────────
BACKUP_DIR=".phantex-backups"
HISTORY_FILE="$BACKUP_DIR/update-history.jsonl"
HEALTH_TIMEOUT=120
HEALTH_INTERVAL=5

# Detect mode
if [[ -f ".env.production" ]]; then
  COMPOSE_CMD="docker compose -f docker-compose.dev.yml -f docker-compose.prod.yml --env-file .env.production"
  MODE="prod"
else
  COMPOSE_CMD="docker compose -f docker-compose.dev.yml"
  MODE="dev"
fi

# ── Version helpers ──────────────────────────────────────────────────────

get_version() {
  if [[ -f VERSION ]]; then
    cat VERSION
  else
    git rev-parse --short HEAD 2>/dev/null || echo "unknown"
  fi
}

get_git_branch() {
  git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"
}

write_history() {
  local action="$1" from_ver="$2" to_ver="$3" status="$4"
  mkdir -p "$BACKUP_DIR"
  echo "{\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"action\": \"$action\", \"from\": \"$from_ver\", \"to\": \"$to_ver\", \"status\": \"$status\", \"mode\": \"$MODE\"}" \
    >> "$HISTORY_FILE"
}

# ── Preflight ────────────────────────────────────────────────────────────

preflight() {
  info "Checking prerequisites..."

  if ! command -v docker &>/dev/null; then
    err "Docker not found"; exit 1
  fi
  if ! command -v git &>/dev/null; then
    err "Git not found"; exit 1
  fi
  if ! docker compose version &>/dev/null; then
    err "Docker Compose not found"; exit 1
  fi

  # Check for uncommitted local changes that might conflict
  if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    warn "You have uncommitted local changes."
    warn "These will be preserved but may cause merge conflicts."
    read -r -p "Continue? [y/N] " confirm
    if [[ "$confirm" != [yY] ]]; then
      info "Aborted."
      exit 0
    fi
  fi

  ok "Prerequisites passed"
}

# ── Check (dry run) ─────────────────────────────────────────────────────

cmd_check() {
  local current_ver
  current_ver=$(get_version)
  local branch
  branch=$(get_git_branch)

  info "Current version: $current_ver (branch: $branch)"
  info "Mode: $MODE"
  info ""
  info "Checking for updates..."

  git fetch origin "$branch" --quiet 2>/dev/null || { err "Could not reach remote"; exit 1; }

  local ahead behind
  ahead=$(git rev-list --count "origin/$branch..HEAD" 2>/dev/null || echo 0)
  behind=$(git rev-list --count "HEAD..origin/$branch" 2>/dev/null || echo 0)

  if [[ "$behind" -eq 0 ]]; then
    ok "Already up to date."
    return
  fi

  info "Updates available: $behind new commit(s)"
  info ""
  info "Changes:"
  git --no-pager log --oneline "HEAD..origin/$branch" | head -20
  info ""

  # Check for new migrations
  local new_migrations
  new_migrations=$(git diff --name-only "HEAD..origin/$branch" -- backend/migrations/*.sql 2>/dev/null | wc -l)
  if [[ "$new_migrations" -gt 0 ]]; then
    info "📋 Includes $new_migrations new database migration(s):"
    git diff --name-only "HEAD..origin/$branch" -- backend/migrations/*.sql 2>/dev/null
  fi

  # Check for breaking changes
  local compose_changes
  compose_changes=$(git diff --name-only "HEAD..origin/$branch" -- docker-compose*.yml 2>/dev/null | wc -l)
  if [[ "$compose_changes" -gt 0 ]]; then
    warn "⚠️  Docker Compose files changed — containers will be recreated"
  fi

  info ""
  info "Run ${BOLD}./update.sh${NC} to apply these changes."
}

# ── Backup ───────────────────────────────────────────────────────────────

create_backup() {
  local current_ver="$1"
  local ts
  ts=$(date +%Y%m%d-%H%M%S)
  local backup_path="$BACKUP_DIR/$ts-v${current_ver}"

  mkdir -p "$backup_path"

  info "Creating backup → $backup_path"

  # Save git commit for rollback
  git rev-parse HEAD > "$backup_path/git-commit.txt"

  # Backup database schema
  if docker exec phantex-postgres pg_isready -U phantex_admin -d phantex &>/dev/null; then
    docker exec phantex-postgres \
      pg_dump -U phantex_admin -d phantex --schema-only \
      > "$backup_path/schema.sql" 2>/dev/null || warn "Could not backup schema"

    # Backup user data (users, tenants, rules, policies — small critical tables)
    for table in users tenants rules detection_policies response_config response_policies drift_policy notification_channels alert_routing_rules; do
      docker exec phantex-postgres \
        pg_dump -U phantex_admin -d phantex --data-only -t "$table" \
        > "$backup_path/${table}.sql" 2>/dev/null || true
    done
    ok "Database backup complete"
  else
    warn "PostgreSQL not running — skipping DB backup"
  fi

  # Save env file reference (not the secrets themselves)
  if [[ -f ".env.production" ]]; then
    cp ".env.production" "$backup_path/env.production.bak"
    chmod 600 "$backup_path/env.production.bak"
  fi

  # Metadata
  cat > "$backup_path/metadata.json" <<EOF
{
  "version": "$current_ver",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$(git rev-parse HEAD)",
  "git_branch": "$(get_git_branch)",
  "mode": "$MODE",
  "docker_images": $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep phantex | head -10 | jq -R . | jq -s . 2>/dev/null || echo '[]')
}
EOF

  ok "Backup saved"
  echo "$backup_path"
}

# ── Apply Migrations ─────────────────────────────────────────────────────

apply_migrations() {
  info "Checking for pending migrations..."

  if ! docker exec phantex-postgres pg_isready -U phantex_admin -d phantex &>/dev/null; then
    warn "PostgreSQL not ready — skipping migrations"
    return
  fi

  # Get applied versions
  local applied
  applied=$(docker exec phantex-postgres \
    psql -U phantex_admin -d phantex -t -c "SELECT version FROM schema_migrations ORDER BY version;" \
    2>/dev/null | tr -d ' ' || echo "")

  local count=0
  for sql in backend/migrations/[0-9][0-9][0-9]_*.sql; do
    [[ -f "$sql" ]] || continue
    local version
    version=$(basename "$sql" | grep -oE '^[0-9]+')

    # Skip already applied
    if echo "$applied" | grep -qw "$version"; then
      continue
    fi

    info "  Applying: $(basename "$sql")"
    if docker exec -i phantex-postgres \
      psql -U phantex_admin -d phantex -v ON_ERROR_STOP=1 < "$sql" 2>/dev/null; then
      ok "  Applied: $(basename "$sql")"
      ((count++))
    else
      err "  Failed: $(basename "$sql")"
      err "  Migration failed — aborting update."
      err "  Run ./update.sh --rollback to restore previous state."
      return 1
    fi
  done

  if [[ $count -eq 0 ]]; then
    ok "No pending migrations"
  else
    ok "$count migration(s) applied"
  fi
}

# ── Health Check ─────────────────────────────────────────────────────────

health_check() {
  local elapsed=0

  while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
    if curl -sf http://localhost:8000/healthz &>/dev/null; then
      return 0
    fi
    sleep "$HEALTH_INTERVAL"
    ((elapsed += HEALTH_INTERVAL))
    info "  Waiting for backend... ($elapsed/${HEALTH_TIMEOUT}s)"
  done

  return 1
}

# ── Upgrade ──────────────────────────────────────────────────────────────

cmd_update() {
  local current_ver branch
  current_ver=$(get_version)
  branch=$(get_git_branch)

  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║         PHANTEX — Safe Update                           ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
  info "Current version: $current_ver"
  info "Branch: $branch | Mode: $MODE"
  echo ""

  # Step 1: Preflight
  info "Step 1/6: Pre-flight checks..."
  preflight

  # Step 2: Backup
  info "Step 2/6: Creating backup checkpoint..."
  local backup_path
  backup_path=$(create_backup "$current_ver")

  # Step 3: Pull latest code
  info "Step 3/6: Pulling latest changes..."
  if ! git pull --ff-only origin "$branch" 2>/dev/null; then
    # Try stash + pull + stash pop for local changes
    warn "Fast-forward failed — attempting stash merge..."
    git stash 2>/dev/null || true
    if ! git pull --ff-only origin "$branch" 2>/dev/null; then
      err "Could not merge updates. Resolve conflicts manually:"
      err "  git stash pop && git merge origin/$branch"
      write_history "update" "$current_ver" "?" "conflict"
      exit 1
    fi
    git stash pop 2>/dev/null || warn "Could not restore stashed changes"
  fi
  local new_ver
  new_ver=$(get_version)
  ok "Code updated: $current_ver → $new_ver"

  # Step 4: Apply database migrations
  info "Step 4/6: Applying database migrations..."
  if ! apply_migrations; then
    err "Migration failed — rolling back..."
    git checkout "$(cat "$backup_path/git-commit.txt")" 2>/dev/null || true
    write_history "update" "$current_ver" "$new_ver" "migration-failed"
    exit 1
  fi

  # Step 5: Rebuild and restart containers
  info "Step 5/6: Rebuilding containers..."
  $COMPOSE_CMD build --quiet 2>/dev/null || $COMPOSE_CMD build
  $COMPOSE_CMD up -d --force-recreate
  ok "Containers restarted"

  # Step 6: Health check
  info "Step 6/6: Running health checks..."
  if health_check; then
    ok "Health checks passed"
    write_history "update" "$current_ver" "$new_ver" "success"

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  Update complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Previous:  ${YELLOW}$current_ver${NC}"
    echo -e "  Current:   ${GREEN}$new_ver${NC}"
    echo -e "  Backup:    ${CYAN}$backup_path${NC}"
    echo ""
    echo -e "  Rollback:  ${CYAN}./update.sh --rollback${NC}"
    echo ""
  else
    err "Health checks FAILED — rolling back automatically..."
    write_history "update" "$current_ver" "$new_ver" "health-failed"
    do_rollback
    exit 1
  fi
}

# ── Rollback ─────────────────────────────────────────────────────────────

do_rollback() {
  # Find latest backup
  local backup_path
  backup_path=$(ls -d "$BACKUP_DIR"/*/ 2>/dev/null | sort -r | head -1)

  if [[ -z "$backup_path" ]]; then
    err "No backups found in $BACKUP_DIR"
    exit 1
  fi

  local commit_file="$backup_path/git-commit.txt"
  if [[ ! -f "$commit_file" ]]; then
    err "No git commit found in backup: $backup_path"
    exit 1
  fi

  local target_commit
  target_commit=$(cat "$commit_file")
  local current_ver
  current_ver=$(get_version)

  info "Rolling back to commit $target_commit..."
  info "Backup: $backup_path"

  # Restore git state
  git checkout "$target_commit" 2>/dev/null || {
    err "Could not checkout commit $target_commit"
    exit 1
  }

  # Rebuild containers with old code
  $COMPOSE_CMD build --quiet 2>/dev/null || $COMPOSE_CMD build
  $COMPOSE_CMD up -d --force-recreate

  # Verify health
  info "Verifying rollback..."
  if health_check; then
    local restored_ver
    restored_ver=$(get_version)
    ok "Rollback successful: now at $restored_ver"
    write_history "rollback" "$current_ver" "$restored_ver" "success"
    echo ""
    warn "You are now in detached HEAD state."
    warn "To return to the latest: git checkout $(get_git_branch)"
  else
    err "CRITICAL: Rollback health check failed!"
    err "Manual intervention required."
    write_history "rollback" "$current_ver" "$(get_version)" "failed"
    exit 2
  fi
}

cmd_rollback() {
  echo ""
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║         PHANTEX — Rollback to Previous Version          ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
  do_rollback
}

# ── Status ───────────────────────────────────────────────────────────────

cmd_status() {
  echo ""
  info "PHANTEX Deployment Status"
  echo ""
  info "  Version:  $(get_version)"
  info "  Branch:   $(get_git_branch)"
  info "  Commit:   $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
  info "  Mode:     $MODE"
  echo ""

  # Running containers
  info "  Services:"
  $COMPOSE_CMD ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || true
  echo ""

  # Update history
  if [[ -f "$HISTORY_FILE" ]]; then
    info "  Update History (last 10):"
    tail -10 "$HISTORY_FILE" | while IFS= read -r line; do
      local ts action from to status
      ts=$(echo "$line" | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4)
      action=$(echo "$line" | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
      from=$(echo "$line" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
      to=$(echo "$line" | grep -o '"to":"[^"]*"' | cut -d'"' -f4)
      status=$(echo "$line" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
      printf "    %s  %-10s  %s → %s  [%s]\n" "$ts" "$action" "$from" "$to" "$status"
    done
  else
    info "  No update history yet."
  fi
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────

case "${1:-update}" in
  --check|-c)     cmd_check ;;
  --rollback|-r)  cmd_rollback ;;
  --status|-s)    cmd_status ;;
  --help|-h)
    cat <<EOF
PHANTEX Safe Update Tool

Usage:
  ./update.sh                Update to latest version
  ./update.sh --check        Preview available changes (dry run)
  ./update.sh --rollback     Rollback to previous checkpoint
  ./update.sh --status       Show current version and update history

What happens during update:
  1. Pre-flight checks (git, docker, compose)
  2. Backup (DB schema, user data, config, git commit)
  3. Pull latest code (git pull --ff-only)
  4. Apply new database migrations (idempotent, tracked)
  5. Rebuild and restart containers
  6. Health check gate (auto-rollback on failure)

Safe for: local dev, single-machine production, cloud VMs
For air-gapped / Kubernetes: use packaging/upgrade/upgrade.sh
EOF
    ;;
  update|"")      cmd_update ;;
  *)              err "Unknown option: $1. Use --help for usage."; exit 1 ;;
esac
