# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ============================================================================
# Phantex Kernel Compatibility Test — Makefile
# Downloads kernel images and runs eBPF probe loading tests.
# ============================================================================

KERNEL_VERSION ?= 6.6.0
KERNEL_DIR     := kernels
RESULTS_DIR    := results

# Base URL for pre-built kernel images (vmtest project)
KERNEL_BASE_URL := https://github.com/danobi/vmtest/releases/download

.PHONY: all download-kernel test clean

all: download-kernel test

# ── Download pre-built kernel bzImage ────────────────────────────
download-kernel:
	@mkdir -p $(KERNEL_DIR)
	@echo "==> Downloading kernel $(KERNEL_VERSION)..."
	@if [ ! -f "$(KERNEL_DIR)/bzImage-$(KERNEL_VERSION)" ]; then \
		curl -L -o "$(KERNEL_DIR)/bzImage-$(KERNEL_VERSION)" \
			"$(KERNEL_BASE_URL)/v$(KERNEL_VERSION)/bzImage" || \
		echo "WARN: Could not download kernel $(KERNEL_VERSION) — will attempt local boot"; \
	fi
	@echo "==> Kernel $(KERNEL_VERSION) ready"

# ── Run probe test ───────────────────────────────────────────────
test:
	@mkdir -p $(RESULTS_DIR)
	bash test_probes.sh \
		--kernel "$(KERNEL_VERSION)" \
		--probes "../../sensor/ebpf" \
		--timeout 300

# ── Clean artifacts ──────────────────────────────────────────────
clean:
	rm -rf $(KERNEL_DIR) $(RESULTS_DIR)
