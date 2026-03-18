#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# Phantex Sensor — Interactive Setup & Launch
#
# One-command sensor deployment: checks prerequisites, builds the binary,
# generates a config, and starts the sensor.
#
# Usage:
#   ./start-sensor.sh              # interactive setup
#   ./start-sensor.sh --defaults   # non-interactive (dev defaults, foreground)
#   ./start-sensor.sh --status     # show running sensor status
#   ./start-sensor.sh --stop       # stop running sensor
#
# Environment variables (override prompts):
#   PHANTEX_TENANT_ID    — tenant UUID
#   PHANTEX_AUTH_TOKEN   — gateway bearer token
#   PHANTEX_GATEWAY      — gateway address (default: localhost:50051)
#
# Requirements: Go 1.23+, Linux (eBPF probes need kernel 5.8+), root/sudo
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENSOR_DIR="${SCRIPT_DIR}/sensor"
CONFIG_FILE="${SENSOR_DIR}/sensor.yaml"
BINARY="${SENSOR_DIR}/phantex-sensor"
LOG_FILE="/tmp/phantex-sensor.log"
PID_FILE="/tmp/phantex-sensor.pid"

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[sensor]${NC} $*"; }
ok()    { echo -e "${GREEN}[sensor]${NC} $*"; }
warn()  { echo -e "${YELLOW}[sensor]${NC} $*"; }
err()   { echo -e "${RED}[sensor]${NC} $*" >&2; }

# ── Parse args ──────────────────────────────────────────────────────────────
MODE="interactive"
for arg in "$@"; do
  case "$arg" in
    --defaults) MODE="defaults" ;;
    --status)
      if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        PID=$(cat "$PID_FILE")
        ok "Sensor is running (PID $PID)"
        echo -e "  Log: ${CYAN}tail -f $LOG_FILE${NC}"
        ps -p "$PID" -o pid,user,%cpu,%mem,etime,args --no-headers 2>/dev/null || true
      else
        warn "Sensor is not running."
      fi
      exit 0
      ;;
    --stop)
      if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        PID=$(cat "$PID_FILE")
        kill "$PID"
        rm -f "$PID_FILE"
        ok "Sensor stopped (PID $PID)."
      else
        pkill -f phantex-sensor 2>/dev/null && ok "Sensor stopped." || warn "No sensor process found."
      fi
      exit 0
      ;;
    --help|-h)
      echo "Usage: ./start-sensor.sh [--defaults|--status|--stop]"
      echo ""
      echo "  (default)    Interactive setup — prompts for config options"
      echo "  --defaults   Non-interactive — dev defaults, foreground"
      echo "  --status     Show running sensor PID and resource usage"
      echo "  --stop       Stop running sensor"
      exit 0
      ;;
    *) err "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ── Preflight ───────────────────────────────────────────────────────────────
info "Checking prerequisites..."

if [[ "$(uname -s)" == "Linux" ]]; then
  KERN_MAJOR=$(uname -r | cut -d. -f1)
  KERN_MINOR=$(uname -r | cut -d. -f2)
  if [[ $KERN_MAJOR -lt 5 || ( $KERN_MAJOR -eq 5 && $KERN_MINOR -lt 8 ) ]]; then
    warn "Kernel $(uname -r) detected. eBPF probes need 5.8+. Some probes may not load."
  fi
elif [[ "$(uname -s)" == *"MINGW"* || "$(uname -s)" == *"CYGWIN"* || "$(uname -s)" == *"MSYS"* ]]; then
  info "Windows detected — eBPF probes will be disabled (ETW mode)."
else
  warn "Unsupported OS: $(uname -s). Sensor is designed for Linux."
fi

if [[ $EUID -ne 0 ]]; then
  echo ""
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${RED}  ⚠  ROOT REQUIRED FOR eBPF PROBES${NC}"
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  eBPF probes need root or CAP_BPF+CAP_PERFMON to load."
  echo -e "  Without them the sensor runs in ${YELLOW}SDK-only mode${NC} (probes 0/N)."
  echo -e "  Network/process telemetry will NOT be captured."
  echo ""
  echo -e "  Re-run with: ${CYAN}sudo $0 $*${NC}"
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
fi

# Check Go
if ! command -v go &>/dev/null; then
  err "Go not found. Install Go 1.23+: https://go.dev/dl/"
  exit 1
fi
GO_VERSION=$(go version | grep -oP '\d+\.\d+' | head -1)
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
if [[ $GO_MAJOR -lt 1 || ( $GO_MAJOR -eq 1 && $GO_MINOR -lt 23 ) ]]; then
  err "Go $GO_VERSION is too old. Need 1.23+."
  exit 1
fi
ok "Go $GO_VERSION"

# Check gateway reachability
GW_ADDR="${PHANTEX_GATEWAY:-localhost:50051}"
if command -v nc &>/dev/null; then
  GW_HOST="${GW_ADDR%%:*}"
  GW_PORT="${GW_ADDR##*:}"
  if nc -z -w2 "$GW_HOST" "$GW_PORT" 2>/dev/null; then
    ok "Gateway reachable at $GW_ADDR"
  else
    warn "Cannot reach gateway at $GW_ADDR — is PhanTeX running? (./quickstart.sh)"
  fi
fi

# ── eBPF Toolchain ──────────────────────────────────────────────────────────
MISSING_TOOLS=()
command -v clang   &>/dev/null || MISSING_TOOLS+=("clang")
command -v llvm-strip &>/dev/null || MISSING_TOOLS+=("llvm")
command -v bpftool &>/dev/null || MISSING_TOOLS+=("bpftool")

# Check kernel headers
KERN=$(uname -r)
if [[ ! -d "/lib/modules/$KERN/build" && ! -d "/usr/src/linux-headers-$KERN" ]]; then
  MISSING_TOOLS+=("linux-headers-$KERN")
fi

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  warn "Missing eBPF build tools: ${MISSING_TOOLS[*]}"
  INSTALL_CMD=""
  if command -v apt-get &>/dev/null; then
    PKGS=""
    for t in "${MISSING_TOOLS[@]}"; do
      case "$t" in
        clang)    PKGS+="clang " ;;
        llvm)     PKGS+="llvm " ;;
        bpftool)  PKGS+="linux-tools-$(uname -r) linux-tools-common " ;;
        linux-headers-*) PKGS+="linux-headers-$(uname -r) " ;;
      esac
    done
    INSTALL_CMD="apt-get install -y $PKGS"
  elif command -v dnf &>/dev/null; then
    PKGS=""
    for t in "${MISSING_TOOLS[@]}"; do
      case "$t" in
        clang)    PKGS+="clang " ;;
        llvm)     PKGS+="llvm " ;;
        bpftool)  PKGS+="bpftool " ;;
        linux-headers-*) PKGS+="kernel-devel " ;;
      esac
    done
    INSTALL_CMD="dnf install -y $PKGS"
  fi

  if [[ -n "$INSTALL_CMD" ]]; then
    if [[ "$MODE" == "defaults" ]]; then
      info "Installing: $INSTALL_CMD"
      $INSTALL_CMD
    else
      echo ""
      read -rp "$(echo -e "${CYAN}Install missing tools now?${NC} ($INSTALL_CMD) [Y/n]: ")" INSTALL_ANSWER
      if [[ "${INSTALL_ANSWER:-Y}" =~ ^[Yy]$ ]]; then
        $INSTALL_CMD
      else
        err "Cannot build eBPF probes without: ${MISSING_TOOLS[*]}"
        exit 1
      fi
    fi
    ok "Build tools installed."
  else
    err "Cannot auto-install on this distro. Install manually: ${MISSING_TOOLS[*]}"
    exit 1
  fi
fi

# ── Signing Key ─────────────────────────────────────────────────────────────
SIGN_SEED="$SENSOR_DIR/keys/ebpf-sign.seed"
SIGN_PUB="$SENSOR_DIR/keys/ebpf-sign.pub"

if [[ ! -f "$SIGN_SEED" ]]; then
  info "No Ed25519 signing key found — generating a new keypair..."
  cd "$SENSOR_DIR"
  make genkey
  cd "$SCRIPT_DIR"
  ok "Keypair generated. Your probes will be signed with a key unique to this deployment."
fi

# ── Build ───────────────────────────────────────────────────────────────────
EMBED_DIR="$SENSOR_DIR/internal/ebpf/bpf"
NEEDS_BUILD=false

if [[ ! -f "$BINARY" ]]; then
  NEEDS_BUILD=true
elif [[ "$SENSOR_DIR/cmd/phantex-sensor/main.go" -nt "$BINARY" ]]; then
  NEEDS_BUILD=true
elif [[ -z $(ls "$EMBED_DIR"/*.bpf.o.sig 2>/dev/null) ]]; then
  NEEDS_BUILD=true
fi

if [[ "$NEEDS_BUILD" == "true" ]]; then
  info "Building sensor (compile probes → sign → build binary)..."
  cd "$SENSOR_DIR"
  # Capture build output — show a clean summary, surface errors on failure
  BUILD_LOG=$(mktemp)
  if make all > "$BUILD_LOG" 2>&1; then
    PROBE_COUNT=$(grep -c '\[BPF\]' "$BUILD_LOG" || true)
    SIGNED_COUNT=$(grep -c 'signed:' "$BUILD_LOG" || true)
    ok "eBPF probes compiled: ${PROBE_COUNT}  signed: ${SIGNED_COUNT}"
    # Show the signing public key line so user can record it
    PUB_LINE=$(grep 'Public key hex\|Signed.*Public key' "$BUILD_LOG" | tail -1 || true)
    [[ -n "$PUB_LINE" ]] && echo -e "  ${CYAN}${PUB_LINE}${NC}"
    ok "Sensor built with locally-signed eBPF probes."
  else
    err "Build failed. Full output:"
    cat "$BUILD_LOG"
    rm -f "$BUILD_LOG"
    exit 1
  fi
  rm -f "$BUILD_LOG"
  cd "$SCRIPT_DIR"
else
  ok "Sensor binary and signed probes up to date."
fi

# ── Config ──────────────────────────────────────────────────────────────────

# Defaults
DEF_TENANT="a0000000-0000-0000-0000-000000000001"
DEF_TOKEN="phantex-docker-compose-dev-token-2025"
DEF_GATEWAY="localhost:50051"
DEF_MODE="filtered"
DEF_ENV="dev"
DEF_LOG="info"
DEF_RUN="foreground"

if [[ "$MODE" == "interactive" && ! -f "$CONFIG_FILE" ]]; then
  echo ""
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}  PhanTeX Sensor Setup${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""

  # Tenant ID
  read -rp "$(echo -e "${CYAN}Tenant ID${NC} [${DEF_TENANT}]: ")" TENANT_ID
  TENANT_ID="${TENANT_ID:-$DEF_TENANT}"

  # Auth token
  read -rp "$(echo -e "${CYAN}Auth token${NC} [${DEF_TOKEN}]: ")" AUTH_TOKEN
  AUTH_TOKEN="${AUTH_TOKEN:-$DEF_TOKEN}"

  # Gateway address
  read -rp "$(echo -e "${CYAN}Gateway address${NC} [${DEF_GATEWAY}]: ")" GATEWAY_ADDR
  GATEWAY_ADDR="${GATEWAY_ADDR:-$DEF_GATEWAY}"

  # Filter mode
  echo ""
  echo -e "  ${YELLOW}Filter modes:${NC}"
  echo -e "    filtered — only track AI agent processes (recommended)"
  echo -e "    all      — trace every process (noisy, for testing)"
  read -rp "$(echo -e "${CYAN}Filter mode${NC} [${DEF_MODE}]: ")" FILTER_MODE
  FILTER_MODE="${FILTER_MODE:-$DEF_MODE}"

  # Environment tag
  read -rp "$(echo -e "${CYAN}Environment tag${NC} [${DEF_ENV}]: ")" ENV_TAG
  ENV_TAG="${ENV_TAG:-$DEF_ENV}"

  # Log level
  read -rp "$(echo -e "${CYAN}Log level${NC} (debug/info/warn/error) [${DEF_LOG}]: ")" LOG_LEVEL
  LOG_LEVEL="${LOG_LEVEL:-$DEF_LOG}"

  # Run mode
  echo ""
  echo -e "  ${YELLOW}Run modes:${NC}"
  echo -e "    foreground — run in terminal (Ctrl+C to stop)"
  echo -e "    background — run as daemon (use --stop to stop)"
  read -rp "$(echo -e "${CYAN}Run mode${NC} [${DEF_RUN}]: ")" RUN_MODE
  RUN_MODE="${RUN_MODE:-$DEF_RUN}"

elif [[ "$MODE" == "defaults" ]]; then
  TENANT_ID="${PHANTEX_TENANT_ID:-$DEF_TENANT}"
  AUTH_TOKEN="${PHANTEX_AUTH_TOKEN:-$DEF_TOKEN}"
  GATEWAY_ADDR="${PHANTEX_GATEWAY:-$DEF_GATEWAY}"
  FILTER_MODE="$DEF_MODE"
  ENV_TAG="$DEF_ENV"
  LOG_LEVEL="$DEF_LOG"
  RUN_MODE="foreground"
elif [[ -f "$CONFIG_FILE" ]]; then
  info "Using existing config: $CONFIG_FILE"
  TENANT_ID="${PHANTEX_TENANT_ID:-$DEF_TENANT}"
  AUTH_TOKEN="${PHANTEX_AUTH_TOKEN:-$DEF_TOKEN}"
  RUN_MODE="$DEF_RUN"
  # Don't overwrite existing config
fi

# Generate config if it doesn't exist
if [[ ! -f "$CONFIG_FILE" ]]; then
  info "Writing sensor config to $CONFIG_FILE..."
  cat > "$CONFIG_FILE" <<SEOF
# PhanTeX Sensor Configuration
# Generated by start-sensor.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

tenant_id: "${TENANT_ID}"
log_level: "${LOG_LEVEL}"
log_format: console

ebpf:
  filter_mode: "${FILTER_MODE}"

transport:
  gateway_addr: "${GATEWAY_ADDR}"
  batch_size: 100
  batch_timeout: 1s
  buffer_size: 10000

discovery:
  scan_interval: 30s
  env_tag: "${ENV_TAG}"
  exclude_self: true
  deduplicate_workers: true

health:
  enabled: true
  addr: ":9090"

sdk_socket:
  enabled: true
  socket_path: /var/run/phantex/sdk.sock
SEOF
  ok "Config written."
fi

# ── Launch ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Starting PhanTeX Sensor${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Kill any existing sensor
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  warn "Stopping existing sensor (PID $(cat "$PID_FILE"))..."
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  sleep 1
fi
pkill -f phantex-sensor 2>/dev/null || true
sleep 1

export PHANTEX_AUTH_TOKEN="${AUTH_TOKEN:-${PHANTEX_AUTH_TOKEN:-$DEF_TOKEN}}"
export PHANTEX_TENANT_ID="${TENANT_ID:-${PHANTEX_TENANT_ID:-$DEF_TENANT}}"

cd "$SENSOR_DIR"

if [[ "${RUN_MODE:-foreground}" == "background" ]]; then
  nohup "$BINARY" -config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
  SENSOR_PID=$!
  echo "$SENSOR_PID" > "$PID_FILE"
  sleep 3

  if kill -0 "$SENSOR_PID" 2>/dev/null; then
    ok "Sensor running in background (PID $SENSOR_PID)"
    echo ""
    echo -e "  Logs:    ${CYAN}tail -f $LOG_FILE${NC}"
    echo -e "  Status:  ${CYAN}./start-sensor.sh --status${NC}"
    echo -e "  Stop:    ${CYAN}./start-sensor.sh --stop${NC}"
    echo ""
    echo -e "  ${YELLOW}Recent logs:${NC}"
    tail -20 "$LOG_FILE"
  else
    err "Sensor exited immediately. Check logs:"
    tail -30 "$LOG_FILE"
    exit 1
  fi
else
  info "Running in foreground (Ctrl+C to stop)..."
  echo ""
  exec "$BINARY" -config "$CONFIG_FILE"
fi
