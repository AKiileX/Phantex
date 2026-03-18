#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ============================================================================
# Phantex — Dependency Audit Script
# Runs vulnerability scanners across all stacks.
#
# Usage:
#   ./audit-deps.sh           # Run all scanners
#   ./audit-deps.sh --go      # Go only
#   ./audit-deps.sh --python  # Python only
#   ./audit-deps.sh --node    # Node.js only
#   ./audit-deps.sh --docker  # Docker images only
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

header() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════════"
}

success() { echo -e "  ${GREEN}✓${NC} $1"; }
warning() { echo -e "  ${YELLOW}⚠${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
error()   { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS + 1)); }

# ── Parse arguments ──────────────────────────────────────────────
RUN_GO=true
RUN_PYTHON=true
RUN_NODE=true
RUN_DOCKER=true

if [[ $# -gt 0 ]]; then
    RUN_GO=false; RUN_PYTHON=false; RUN_NODE=false; RUN_DOCKER=false
    for arg in "$@"; do
        case "$arg" in
            --go)     RUN_GO=true ;;
            --python) RUN_PYTHON=true ;;
            --node)   RUN_NODE=true ;;
            --docker) RUN_DOCKER=true ;;
            --help)
                echo "Usage: $0 [--go] [--python] [--node] [--docker]"
                exit 0
                ;;
            *) echo "Unknown option: $arg"; exit 1 ;;
        esac
    done
fi

echo "Phantex Dependency Audit"
echo "========================"
echo "Project root: $PROJECT_ROOT"
echo ""

# ── Go Vulnerability Check ───────────────────────────────────────
if $RUN_GO; then
    header "Go — govulncheck"

    if ! command -v govulncheck &>/dev/null; then
        warning "govulncheck not found. Install: go install golang.org/x/vuln/cmd/govulncheck@latest"
    else
        for module in sensor gateway; do
            echo "  Scanning $module..."
            if (cd "$PROJECT_ROOT/$module" && govulncheck ./... 2>&1); then
                success "$module: no known vulnerabilities"
            else
                error "$module: vulnerabilities found (see output above)"
            fi
        done
    fi

    # Verify go.sum integrity
    for module in sensor gateway; do
        echo "  Verifying $module go.sum..."
        if (cd "$PROJECT_ROOT/$module" && go mod verify 2>&1); then
            success "$module: go.sum verified"
        else
            error "$module: go.sum verification failed"
        fi
    done
fi

# ── Python Vulnerability Check ───────────────────────────────────
if $RUN_PYTHON; then
    header "Python — pip-audit"

    if ! command -v pip-audit &>/dev/null; then
        warning "pip-audit not found. Install: pip install pip-audit"
    else
        for pkg_dir in backend engine sdk; do
            REQ_FILE="$PROJECT_ROOT/$pkg_dir/requirements.txt"
            if [[ -f "$REQ_FILE" ]]; then
                echo "  Scanning $pkg_dir..."
                if pip-audit -r "$REQ_FILE" 2>&1; then
                    success "$pkg_dir: no known vulnerabilities"
                else
                    error "$pkg_dir: vulnerabilities found"
                fi
            else
                echo "  SKIP: $pkg_dir (no requirements.txt)"
            fi
        done
    fi

    # Check for unpinned dependencies
    header "Python — Pin Check"
    for pkg_dir in backend engine sdk; do
        REQ_FILE="$PROJECT_ROOT/$pkg_dir/requirements.txt"
        if [[ -f "$REQ_FILE" ]]; then
            UNPINNED=$(grep -E '^[a-zA-Z]' "$REQ_FILE" | grep -v '==' | grep -v '^#' || true)
            if [[ -n "$UNPINNED" ]]; then
                warning "$pkg_dir has unpinned dependencies:"
                echo "$UNPINNED" | sed 's/^/    /'
            else
                success "$pkg_dir: all dependencies pinned with =="
            fi
        fi
    done
fi

# ── Node.js Vulnerability Check ─────────────────────────────────
if $RUN_NODE; then
    header "Node.js — npm audit"

    if [[ -f "$PROJECT_ROOT/dashboard/package-lock.json" ]]; then
        echo "  Scanning dashboard..."
        if (cd "$PROJECT_ROOT/dashboard" && npm audit --audit-level=high 2>&1); then
            success "dashboard: no high/critical vulnerabilities"
        else
            error "dashboard: vulnerabilities found"
        fi
    else
        warning "dashboard/package-lock.json not found — run 'npm install' first"
    fi

    # Type check as bonus validation
    if [[ -f "$PROJECT_ROOT/dashboard/package.json" ]]; then
        echo "  Type checking dashboard..."
        if (cd "$PROJECT_ROOT/dashboard" && npx tsc -b --noEmit 2>&1); then
            success "dashboard: TypeScript compiles clean"
        else
            warning "dashboard: TypeScript errors detected"
        fi
    fi
fi

# ── Docker Image Scan ────────────────────────────────────────────
if $RUN_DOCKER; then
    header "Docker — Trivy"

    if ! command -v trivy &>/dev/null; then
        warning "trivy not found. Install: https://aquasecurity.github.io/trivy/"
    else
        for component in backend dashboard gateway sensor; do
            IMAGE="phantex-${component}:latest"
            if docker image inspect "$IMAGE" &>/dev/null 2>&1; then
                echo "  Scanning $IMAGE..."
                if trivy image --severity HIGH,CRITICAL --exit-code 1 "$IMAGE" 2>&1; then
                    success "$IMAGE: no high/critical vulnerabilities"
                else
                    error "$IMAGE: vulnerabilities found"
                fi
            else
                echo "  SKIP: $IMAGE (not built locally)"
            fi
        done
    fi

    # Check for :latest tags in Dockerfiles
    header "Docker — Tag Pin Check"
    for dockerfile in backend/Dockerfile dashboard/Dockerfile sensor/Dockerfile gateway/Dockerfile; do
        FULL_PATH="$PROJECT_ROOT/$dockerfile"
        if [[ -f "$FULL_PATH" ]]; then
            LATEST_TAGS=$(grep -n ':latest' "$FULL_PATH" | grep -i 'FROM' || true)
            if [[ -n "$LATEST_TAGS" ]]; then
                warning "$dockerfile uses :latest tag:"
                echo "$LATEST_TAGS" | sed 's/^/    /'
            else
                success "$dockerfile: no :latest tags"
            fi
        fi
    done
fi

# ── Summary ──────────────────────────────────────────────────────
header "Summary"
echo ""
if [[ $ERRORS -gt 0 ]]; then
    echo -e "  ${RED}$ERRORS error(s)${NC}, ${YELLOW}$WARNINGS warning(s)${NC}"
    echo ""
    echo "  Fix critical issues before merging."
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${GREEN}0 errors${NC}, ${YELLOW}$WARNINGS warning(s)${NC}"
    echo ""
    echo "  Review warnings — non-blocking but should be addressed."
    exit 0
else
    echo -e "  ${GREEN}All checks passed — no vulnerabilities found${NC}"
    exit 0
fi
