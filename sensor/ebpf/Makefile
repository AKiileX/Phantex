# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# Phantex — eBPF Probe Build System
# ─────────────────────────────────────────────────────────────────────────────
#
# Generates vmlinux.h from kernel BTF, then compiles all .bpf.c probes
# into .bpf.o object files loadable by cilium/ebpf Go library.
#
# Usage:
#   make              — build all probes
#   make vmlinux      — generate vmlinux.h only
#   make clean        — remove all build artifacts
#   make check        — verify build prerequisites
#
# Requirements:
#   clang >= 15, bpftool, libbpf-dev headers
# ─────────────────────────────────────────────────────────────────────────────

# Architecture detection (eBPF needs target arch for tracing helpers)
ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' \
                               -e 's/aarch64/arm64/' \
                               -e 's/armv7l/arm/')

# Tools
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip

# Auto-detect bpftool: the wrapper in /usr/sbin may fail on WSL2 kernels
# because linux-tools-$(uname -r) isn't packaged for Microsoft WSL kernels.
# Fall back to the generic linux-tools path if the wrapper fails.
BPFTOOL ?= $(shell bpftool version >/dev/null 2>&1 && echo bpftool || \
              (ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | tail -1))

# Directories
PROBE_DIR  := probes
INCLUDE_DIR := include
OUTPUT_DIR := build

# Generated vmlinux header
VMLINUX_H := $(INCLUDE_DIR)/vmlinux.h

# BTF source (standard location on modern kernels)
BTF_FILE := /sys/kernel/btf/vmlinux

# Find all probe source files
PROBE_SRCS := $(wildcard $(PROBE_DIR)/*.bpf.c)
PROBE_OBJS := $(patsubst $(PROBE_DIR)/%.bpf.c,$(OUTPUT_DIR)/%.bpf.o,$(PROBE_SRCS))

# Compiler flags
#   -target bpf           → BPF bytecode output
#   -D__TARGET_ARCH_xxx   → architecture hint for bpf_tracing.h
#   -O2                   → required for BPF verification (verifier rejects -O0)
#   -g                    → BTF debug info (required for CO-RE relocations)
#   -Wall -Werror         → strict compilation
#   -I include paths      → vmlinux.h, events.h, maps.h, libbpf headers
BPF_CFLAGS := \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-O2 \
	-g \
	-Wall \
	-Werror \
	-I$(INCLUDE_DIR) \
	-I$(PROBE_DIR)

# ─── Targets ────────────────────────────────────────────────────────────────

.PHONY: all clean vmlinux check

all: $(OUTPUT_DIR) $(VMLINUX_H) $(PROBE_OBJS)
	@echo ""
	@echo "═══════════════════════════════════════════════════════"
	@echo "  Phantex eBPF probes built successfully"
	@echo "  Output: $(OUTPUT_DIR)/"
	@echo "  Probes: $(words $(PROBE_OBJS))"
	@echo "═══════════════════════════════════════════════════════"
	@ls -lh $(OUTPUT_DIR)/*.bpf.o

# Create output directory
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# ─── vmlinux.h generation ───────────────────────────────────────────────────
# Generate vmlinux.h from the running kernel's BTF information.
# This provides all kernel type definitions needed for CO-RE programs.

vmlinux: $(VMLINUX_H)

$(VMLINUX_H): $(BTF_FILE)
	@echo "[GEN]  vmlinux.h from kernel BTF"
	@test -f $(BTF_FILE) || (echo "ERROR: BTF not available at $(BTF_FILE)" && \
		echo "  Your kernel may not have BTF support enabled." && \
		echo "  Check: CONFIG_DEBUG_INFO_BTF=y in kernel config" && exit 1)
	$(BPFTOOL) btf dump file $(BTF_FILE) format c > $(VMLINUX_H)
	@echo "       → $(VMLINUX_H) ($$(wc -l < $(VMLINUX_H)) lines)"

# ─── Probe compilation ─────────────────────────────────────────────────────
# Each .bpf.c is compiled independently into a .bpf.o
# The .o files contain BTF info and CO-RE relocations for the Go loader.

$(OUTPUT_DIR)/%.bpf.o: $(PROBE_DIR)/%.bpf.c $(VMLINUX_H) $(INCLUDE_DIR)/events.h $(INCLUDE_DIR)/maps.h | $(OUTPUT_DIR)
	@echo "[BPF]  $< → $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "       → $(shell stat --printf='%s' $@ 2>/dev/null || stat -f '%z' $@ 2>/dev/null) bytes"

# ─── Check prerequisites ───────────────────────────────────────────────────

check:
	@echo "Checking eBPF build prerequisites..."
	@echo ""
	@printf "  clang:      "; $(CLANG) --version 2>/dev/null | head -1 || echo "NOT FOUND"
	@printf "  bpftool:    "; $(BPFTOOL) version 2>/dev/null | head -1 || echo "NOT FOUND"
	@printf "  llvm-strip: "; $(LLVM_STRIP) --version 2>/dev/null | head -1 || echo "NOT FOUND"
	@printf "  BTF:        "; test -f $(BTF_FILE) && echo "available ($(BTF_FILE))" || echo "NOT AVAILABLE"
	@printf "  libbpf:     "; test -d /usr/include/bpf && echo "headers found" || echo "NOT FOUND (install libbpf-dev)"
	@printf "  Arch:       "; echo "$(ARCH)"
	@echo ""
	@echo "Probe sources found:"
	@for f in $(PROBE_SRCS); do echo "  $$f"; done

# ─── Clean ──────────────────────────────────────────────────────────────────

clean:
	@echo "[CLEAN] Removing build artifacts"
	rm -rf $(OUTPUT_DIR)
	rm -f $(VMLINUX_H)
	@echo "       Done."
