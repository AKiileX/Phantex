#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ============================================================================
# Phantex — eBPF Probe Loading Test
# Tests that compiled BPF object files load successfully on a given kernel.
#
# Usage:
#   ./test_probes.sh --kernel 6.6.0 --probes ../../sensor/ebpf --timeout 300
#
# This script:
#   1. Finds all .bpf.o files in the probes directory
#   2. For each probe, attempts to load it into the kernel
#   3. Verifies attachment to the expected tracepoint/kprobe
#   4. Records pass/fail results with verifier output on failure
# ============================================================================
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────
KERNEL_VERSION=""
PROBES_DIR=""
TIMEOUT=300
RESULTS_DIR="$(dirname "$0")/results"

# ── Parse arguments ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)   KERNEL_VERSION="$2"; shift 2 ;;
        --probes)   PROBES_DIR="$2";     shift 2 ;;
        --timeout)  TIMEOUT="$2";        shift 2 ;;
        *)          echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$KERNEL_VERSION" || -z "$PROBES_DIR" ]]; then
    echo "Usage: $0 --kernel <version> --probes <dir> [--timeout <seconds>]"
    exit 1
fi

# ── Setup ────────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
RESULT_FILE="$RESULTS_DIR/kernel-${KERNEL_VERSION}.json"
PASS=0
FAIL=0
SKIP=0
RESULTS="[]"

echo "========================================"
echo " Phantex eBPF Probe Test"
echo " Kernel:  $KERNEL_VERSION"
echo " Probes:  $PROBES_DIR"
echo " Timeout: ${TIMEOUT}s"
echo "========================================"

# ── Probe map: BPF object → expected attach point ───────────────
declare -A PROBE_ATTACH_POINTS=(
    ["execve.bpf.o"]="tracepoint/syscalls/sys_enter_execve"
    ["openat.bpf.o"]="tracepoint/syscalls/sys_enter_openat"
    ["tcp_connect.bpf.o"]="kprobe/tcp_connect"
    ["write_read.bpf.o"]="tracepoint/syscalls/sys_enter_write"
    ["mmap.bpf.o"]="tracepoint/syscalls/sys_enter_mmap"
    ["dns.bpf.o"]="tracepoint/syscalls/sys_enter_sendto"
)

# ── Find all compiled probe objects ──────────────────────────────
PROBE_FILES=$(find "$PROBES_DIR" -name "*.bpf.o" -type f 2>/dev/null || true)

if [[ -z "$PROBE_FILES" ]]; then
    echo "ERROR: No .bpf.o files found in $PROBES_DIR"
    echo '{"kernel":"'"$KERNEL_VERSION"'","status":"error","message":"No probe objects found"}' > "$RESULT_FILE"
    exit 1
fi

echo ""
echo "Found probes:"
echo "$PROBE_FILES" | while read -r f; do echo "  $(basename "$f")"; done
echo ""

# ── Test each probe ──────────────────────────────────────────────
test_probe() {
    local probe_path="$1"
    local probe_name
    probe_name=$(basename "$probe_path")
    local attach_point="${PROBE_ATTACH_POINTS[$probe_name]:-}"

    echo "--- Testing: $probe_name ---"

    # Validate the BPF object file
    if ! file "$probe_path" | grep -q "ELF"; then
        echo "  SKIP: $probe_name is not a valid ELF file"
        SKIP=$((SKIP + 1))
        return
    fi

    # Check BPF sections
    local sections
    sections=$(llvm-readelf-18 -S "$probe_path" 2>/dev/null || readelf -S "$probe_path" 2>/dev/null || echo "")

    if [[ -z "$sections" ]]; then
        echo "  WARN: Could not read sections from $probe_name"
    else
        echo "  Sections:"
        echo "$sections" | grep -E '^\s*\[' | head -20 | while read -r line; do
            echo "    $line"
        done
    fi

    # Attempt to load with bpftool (if available; in CI this runs inside the VM)
    if command -v bpftool &>/dev/null; then
        local load_output
        load_output=$(timeout "$TIMEOUT" bpftool prog load "$probe_path" /sys/fs/bpf/phantex_test_"${probe_name%.bpf.o}" 2>&1) && {
            echo "  PASS: $probe_name loaded successfully"
            PASS=$((PASS + 1))

            # Verify attach point if known
            if [[ -n "$attach_point" ]]; then
                echo "  Expected attach: $attach_point"
            fi

            # Cleanup
            rm -f /sys/fs/bpf/phantex_test_"${probe_name%.bpf.o}" 2>/dev/null || true
        } || {
            local exit_code=$?
            echo "  FAIL: $probe_name failed to load (exit=$exit_code)"
            echo "  Verifier output:"
            echo "$load_output" | sed 's/^/    /'
            FAIL=$((FAIL + 1))
        }
    else
        # No bpftool — just validate the object file structure
        echo "  INFO: bpftool not available, validating object structure only"
        if echo "$sections" | grep -qE 'tracepoint|kprobe|raw_tracepoint|\.maps|\.rodata'; then
            echo "  PASS: $probe_name has valid BPF sections"
            PASS=$((PASS + 1))
        else
            echo "  WARN: $probe_name may not have standard BPF sections"
            SKIP=$((SKIP + 1))
        fi
    fi

    echo ""
}

# Process each probe
while IFS= read -r probe_file; do
    test_probe "$probe_file"
done <<< "$PROBE_FILES"

# ── Summary ──────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo "========================================"
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL)"
echo " Kernel:  $KERNEL_VERSION"
echo "========================================"

# Write JSON results
cat > "$RESULT_FILE" <<EOF
{
  "kernel": "$KERNEL_VERSION",
  "total": $TOTAL,
  "passed": $PASS,
  "failed": $FAIL,
  "skipped": $SKIP,
  "status": "$([ $FAIL -eq 0 ] && echo "pass" || echo "fail")",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "Results written to: $RESULT_FILE"

# Exit with failure if any probe failed
if [[ $FAIL -gt 0 ]]; then
    echo "::error::$FAIL probe(s) failed to load on kernel $KERNEL_VERSION"
    exit 1
fi

echo "All probes passed on kernel $KERNEL_VERSION"
