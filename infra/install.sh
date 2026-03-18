#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex Sensor — One-line install script
#
# Usage (once GitHub releases are set up):
#   curl -sSL https://raw.githubusercontent.com/AKiileX/Phantex/main/infra/install.sh | bash
#
#   # Or with options:
#   curl -sSL https://raw.githubusercontent.com/AKiileX/Phantex/main/infra/install.sh | bash -s -- \
#     --token MY_SENSOR_TOKEN \
#     --gateway gateway.example.com:50051
#
# Supports: Ubuntu/Debian (.deb), RHEL/CentOS/Fedora (.rpm)
# Requires: root, kernel 5.15+ with BTF support

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
VERSION="${PHANTEX_VERSION:-latest}"
BASE_URL="${PHANTEX_DOWNLOAD_URL:-https://github.com/AKiileX/Phantex/releases/download}"
CONFIG_DIR="/etc/phantex"
SENSOR_TOKEN=""
GATEWAY_ADDR=""

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[phantex]${NC} $*"; }
warn()  { echo -e "${YELLOW}[phantex]${NC} $*"; }
error() { echo -e "${RED}[phantex]${NC} $*" >&2; }
fatal() { error "$@"; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token)   SENSOR_TOKEN="$2";  shift 2;;
    --gateway) GATEWAY_ADDR="$2";  shift 2;;
    --version) VERSION="$2";       shift 2;;
    *)         fatal "Unknown option: $1";;
  esac
done

# ── Pre-flight checks ────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || fatal "This script must be run as root. Use: sudo bash install.sh"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *)       fatal "Unsupported architecture: $ARCH" ;;
esac

# Check kernel version (need 5.15+)
KERNEL_VER="$(uname -r | cut -d. -f1-2)"
KERNEL_MAJOR="$(echo "$KERNEL_VER" | cut -d. -f1)"
KERNEL_MINOR="$(echo "$KERNEL_VER" | cut -d. -f2)"
if [[ "$KERNEL_MAJOR" -lt 5 ]] || { [[ "$KERNEL_MAJOR" -eq 5 ]] && [[ "$KERNEL_MINOR" -lt 15 ]]; }; then
  fatal "Kernel $KERNEL_VER is too old. Phantex requires 5.15+ with BTF support."
fi

# Check BTF support
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  warn "BTF vmlinux not found at /sys/kernel/btf/vmlinux"
  warn "eBPF probes may fail. Ensure CONFIG_DEBUG_INFO_BTF=y in your kernel config."
fi

info "System: $(uname -sr), arch=$ARCH, kernel=$KERNEL_VER"

# ── Detect package manager ───────────────────────────────────────────────────
if command -v dpkg &>/dev/null; then
  PKG_TYPE="deb"
  PKG_INSTALL="dpkg -i"
elif command -v rpm &>/dev/null; then
  PKG_TYPE="rpm"
  PKG_INSTALL="rpm -i"
else
  fatal "Neither dpkg nor rpm found. Install the binary manually."
fi

info "Package type: ${PKG_TYPE}"

# ── Download ──────────────────────────────────────────────────────────────────
PKG_NAME="phantex-sensor_${VERSION}_${ARCH}.${PKG_TYPE}"
DOWNLOAD_URL="${BASE_URL}/${VERSION}/${PKG_NAME}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${PKG_NAME}..."
if command -v curl &>/dev/null; then
  curl -fsSL -o "${TMP_DIR}/${PKG_NAME}" "$DOWNLOAD_URL"
elif command -v wget &>/dev/null; then
  wget -qO "${TMP_DIR}/${PKG_NAME}" "$DOWNLOAD_URL"
else
  fatal "Neither curl nor wget found."
fi

# ── Install ───────────────────────────────────────────────────────────────────
info "Installing ${PKG_NAME}..."
$PKG_INSTALL "${TMP_DIR}/${PKG_NAME}"

# ── Configure ─────────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"

CONFIG_FILE="${CONFIG_DIR}/sensor.yaml"

# Generate config if it doesn't exist (uses sensor's built-in init-config)
if [[ ! -f "$CONFIG_FILE" ]]; then
  info "Generating default config at ${CONFIG_FILE}..."
  /usr/local/bin/phantex-sensor --init-config --config "$CONFIG_FILE" || {
    warn "init-config failed — copying example config instead"
    cp "${CONFIG_DIR}/sensor.yaml.example" "$CONFIG_FILE" 2>/dev/null || true
  }
fi

if [[ -n "$SENSOR_TOKEN" ]] || [[ -n "$GATEWAY_ADDR" ]]; then
  info "Applying configuration..."

  if [[ -n "$GATEWAY_ADDR" ]]; then
    # Escape sed special characters in user input to prevent injection
    escaped_addr=$(printf '%s\n' "$GATEWAY_ADDR" | sed 's/[&/\]/\\&/g')
    sed -i "s|gateway_addr:.*|gateway_addr: \"${escaped_addr}\"|" "$CONFIG_FILE"
  fi

  if [[ -n "$SENSOR_TOKEN" ]]; then
    escaped_token=$(printf '%s\n' "$SENSOR_TOKEN" | sed 's/[&/\]/\\&/g')
    sed -i "s|auth_token:.*|auth_token: \"${escaped_token}\"|" "$CONFIG_FILE"
  fi
fi

# ── Start ─────────────────────────────────────────────────────────────────────
info "Starting phantex-sensor service..."
systemctl daemon-reload
systemctl enable --now phantex-sensor.service

# ── Verify ────────────────────────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet phantex-sensor.service; then
  info "✓ Phantex sensor is running!"
  info "  Status:  systemctl status phantex-sensor"
  info "  Logs:    journalctl -u phantex-sensor -f"
  info "  Config:  ${CONFIG_DIR}/sensor.yaml"
else
  warn "Sensor service started but may not be active yet."
  warn "Check: journalctl -u phantex-sensor -n 50"
fi
