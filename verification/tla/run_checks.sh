#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ──────────────────────────────────────────────────────────────────────────
# PHANTEX — TLC Model Checker Runner
#
# Runs the TLA+ model checker (TLC) against all formal specs.
# Requires: Java 11+ (for TLC), tla2tools.jar
#
# Usage:
#   ./run_checks.sh              # check all specs
#   ./run_checks.sh rule         # check only rule_evaluation
#   ./run_checks.sh policy       # check only policy_engine
#
# Environment variables:
#   TLC_JAR    — path to tla2tools.jar (default: downloads to /tmp)
#   TLC_WORKERS — number of worker threads (default: auto)
#   TLC_DEPTH  — max depth of state space search (default: 100)
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLC_VERSION="1.8.0"
TLC_JAR="${TLC_JAR:-/tmp/tla2tools-${TLC_VERSION}.jar}"
TLC_WORKERS="${TLC_WORKERS:-auto}"
TLC_DEPTH="${TLC_DEPTH:-100}"
RESULTS_DIR="${SCRIPT_DIR}/results"

# ── Colours ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Functions ────────────────────────────────────────────────────────────

log()  { echo -e "${CYAN}[tlc]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

download_tlc() {
    if [[ -f "$TLC_JAR" ]]; then
        log "Using cached TLC jar: $TLC_JAR"
        return 0
    fi
    local url="https://github.com/tlaplus/tlaplus/releases/download/v${TLC_VERSION}/tla2tools.jar"
    log "Downloading TLC ${TLC_VERSION} ..."
    curl -fsSL -o "$TLC_JAR" "$url" || {
        fail "Failed to download TLC from $url"
        exit 1
    }
    log "Downloaded → $TLC_JAR"
}

check_java() {
    if ! command -v java &>/dev/null; then
        fail "Java not found. TLC requires Java 11+."
        exit 1
    fi
    local ver
    ver=$(java -version 2>&1 | head -1 | awk -F '"' '{print $2}' | cut -d. -f1)
    if [[ "$ver" -lt 11 ]]; then
        fail "Java $ver detected — TLC requires Java 11+"
        exit 1
    fi
    log "Java OK (version $ver)"
}

# ── Run TLC on a single spec ────────────────────────────────────────────
# $1 = spec name (without .tla), e.g. "rule_evaluation"
run_tlc_spec() {
    local spec_name="$1"
    local tla_file="${SCRIPT_DIR}/${spec_name}.tla"
    local cfg_file="${SCRIPT_DIR}/${spec_name}.cfg"
    local log_file="${RESULTS_DIR}/${spec_name}.log"

    if [[ ! -f "$tla_file" ]]; then
        fail "Spec not found: $tla_file"
        return 1
    fi
    if [[ ! -f "$cfg_file" ]]; then
        fail "Config not found: $cfg_file"
        return 1
    fi

    log "Checking ${spec_name} ..."
    mkdir -p "$RESULTS_DIR"

    local start_time
    start_time=$(date +%s)

    # Run TLC — capture output
    set +e
    java -XX:+UseParallelGC \
         -Xmx4g \
         -Dtlc2.tool.impl.Tool.cdot=true \
         -cp "$TLC_JAR" tlc2.TLC \
         -workers "$TLC_WORKERS" \
         -depth "$TLC_DEPTH" \
         -cleanup \
         -deadlock \
         -config "$cfg_file" \
         "$tla_file" \
         2>&1 | tee "$log_file"
    local exit_code=$?
    set -e

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    # Extract stats from TLC output
    local states_found states_distinct
    states_found=$(grep -oP '\d+ states generated' "$log_file" | grep -oP '^\d+' || echo "?")
    states_distinct=$(grep -oP '\d+ distinct states found' "$log_file" | grep -oP '^\d+' || echo "?")

    if [[ $exit_code -eq 0 ]] && grep -q "Model checking completed. No error has been found." "$log_file"; then
        pass "${spec_name}: 0 violations (${states_found} states, ${states_distinct} distinct, ${elapsed}s)"
        # Append summary JSON
        echo "{\"spec\": \"${spec_name}\", \"result\": \"pass\", \"states_generated\": ${states_found:-0}, \"states_distinct\": ${states_distinct:-0}, \"elapsed_sec\": ${elapsed}}" \
            >> "${RESULTS_DIR}/summary.jsonl"
        return 0
    else
        fail "${spec_name}: VIOLATIONS FOUND (exit code ${exit_code})"
        echo "{\"spec\": \"${spec_name}\", \"result\": \"fail\", \"exit_code\": ${exit_code}, \"elapsed_sec\": ${elapsed}}" \
            >> "${RESULTS_DIR}/summary.jsonl"
        return 1
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
    local filter="${1:-all}"

    log "╔══════════════════════════════════════════════╗"
    log "║  PHANTEX — TLA+ Formal Verification Suite   ║"
    log "╚══════════════════════════════════════════════╝"
    log ""

    check_java
    download_tlc

    mkdir -p "$RESULTS_DIR"
    rm -f "${RESULTS_DIR}/summary.jsonl"

    local specs=()
    case "$filter" in
        rule|rule_evaluation)  specs=("rule_evaluation") ;;
        policy|policy_engine)  specs=("policy_engine") ;;
        all|*)                 specs=("rule_evaluation" "policy_engine") ;;
    esac

    local total=${#specs[@]}
    local passed=0
    local failed=0

    for spec in "${specs[@]}"; do
        if run_tlc_spec "$spec"; then
            (( passed++ ))
        else
            (( failed++ ))
        fi
        echo ""
    done

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "Results: ${passed}/${total} passed, ${failed} failed"
    log "Logs:    ${RESULTS_DIR}/"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ $failed -gt 0 ]]; then
        fail "Formal verification failed!"
        exit 1
    fi

    pass "All formal verification checks passed."
    exit 0
}

main "$@"
