# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# sensor/Makefile — Build the Phantex sensor binary
#
# Targets:
#   make            — build everything (probes + sign + Go binary)
#   make probes     — compile eBPF probes (.bpf.o)
#   make copy-bpf   — copy .bpf.o into embed directory
#   make sign-bpf   — Ed25519-sign all .bpf.o files (requires BPF_SIGN_KEY)
#   make build      — build Go binary (requires probes already compiled)
#   make build-windows — cross-compile for Windows (no eBPF needed)
#   make clean      — remove build artifacts
#
# Security targets (ADR-014):
#   make genkey     — generate Ed25519 keypair for eBPF signing
#   make vulncheck  — scan deps for known vulnerabilities (govulncheck)
#   make verify     — verify go.sum checksums match module content
#   make audit      — run all security checks (vulncheck + verify + vet)

GO       ?= go
BINARY   := phantex-sensor
BINARY_WIN   := phantex-sensor.exe
BINARY_CTL   := phantex-sensor-ctl.exe
CMD_DIR  := ./cmd/phantex-sensor
CMD_CTL_DIR := ./cmd/phantex-sensor-ctl
BPF_DIR  := ./ebpf
EMBED_DIR := ./internal/ebpf/bpf
SIGN_TOOL := ../scripts/sign-ebpf/main.go

# Ed25519 signing key for eBPF bytecode (set via env or default path)
BPF_SIGN_KEY ?= keys/ebpf-sign.seed
BPF_PUB_KEY  ?= keys/ebpf-sign.pub

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# If a public key file exists, bake it into the binary via ldflags
BPF_PUB_KEY_HEX := $(shell [ -f $(BPF_PUB_KEY) ] && cat $(BPF_PUB_KEY) | tr -d '[:space:]' || echo "")
LDFLAGS  := -ldflags "-s -w -X main.version=$(VERSION) -X github.com/AKiileX/Phantex/sensor/internal/ebpf.bpfPubKeyHex=$(BPF_PUB_KEY_HEX)"

# Use vendored deps for hermetic builds (ADR-014)
GOFLAGS  := -mod=vendor

.PHONY: all probes copy-bpf sign-bpf genkey build build-windows clean vulncheck verify audit vet

all: probes copy-bpf sign-bpf build

# ─── Build Targets ──────────────────────────────────────────────────────────

# Compile eBPF probes
probes:
	$(MAKE) -C $(BPF_DIR)

# Copy compiled .bpf.o files into the Go embed directory
copy-bpf: probes
	@mkdir -p $(EMBED_DIR)
	cp $(BPF_DIR)/build/*.bpf.o $(EMBED_DIR)/

# Sign all BPF objects with Ed25519 (ADR-014 supply chain integrity)
sign-bpf: copy-bpf
	@if [ -f "$(BPF_SIGN_KEY)" ]; then \
		echo "=== Signing eBPF bytecode (Ed25519) ==="; \
		$(GO) run $(SIGN_TOOL) -key $(BPF_SIGN_KEY) -dir $(EMBED_DIR); \
	else \
		echo "WARNING: BPF_SIGN_KEY not found at $(BPF_SIGN_KEY) — skipping eBPF signing"; \
		echo "  Run 'make genkey' to generate a keypair, or set BPF_SIGN_KEY=<path>"; \
	fi

# Generate Ed25519 keypair for eBPF signing
genkey:
	@mkdir -p keys
	$(GO) run $(SIGN_TOOL) -genkey -out keys/
	@echo ""
	@echo "Keys generated in keys/. KEEP keys/ebpf-sign.seed SECRET."
	@echo "Commit keys/ebpf-sign.pub to the repo. Add keys/ebpf-sign.seed to .gitignore."

# Build the Go sensor binary (static, no CGO for portability)
# Probes must be compiled and signed first — run 'make all' for a full build.
build: copy-bpf sign-bpf
	CGO_ENABLED=0 GOFLAGS="$(GOFLAGS)" $(GO) build $(LDFLAGS) -o $(BINARY) $(CMD_DIR)

# Build the Windows sensor binary (no eBPF — uses ETW)
build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOFLAGS="$(GOFLAGS)" $(GO) build $(LDFLAGS) -o $(BINARY_WIN) $(CMD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOFLAGS="$(GOFLAGS)" $(GO) build $(LDFLAGS) -o $(BINARY_CTL) $(CMD_CTL_DIR)

# ─── Security Targets (ADR-014) ────────────────────────────────────────────

# Scan dependencies for known vulnerabilities using call-graph analysis
vulncheck:
	@echo "=== govulncheck — scanning for known vulnerabilities ==="
	govulncheck ./...

# Verify that vendored modules match go.sum checksums
verify:
	@echo "=== go mod verify — checking module integrity ==="
	$(GO) mod verify

# Run Go static analysis
vet:
	@echo "=== go vet — static analysis ==="
	$(GO) vet ./...

# Run all security checks
audit: verify vulncheck vet
	@echo "=== All security checks passed ==="

# ─── Cleanup ───────────────────────────────────────────────────────────────

# Clean everything
clean:
	$(MAKE) -C $(BPF_DIR) clean
	rm -f $(BINARY) $(BINARY_WIN) $(BINARY_CTL)
	rm -f $(EMBED_DIR)/*.bpf.o
