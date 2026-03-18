# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Sandbox Engine package.

Provides runtime isolation for AI agent tool calls and processes:
  wasm_executor       — Wasmtime-based WASM sandbox for tool-level isolation
  gvisor_manager      — gVisor (runsc) sandbox for full process isolation (Linux)
  firecracker_manager — Firecracker microVM for high-security isolation (Linux)
  quarantine          — Transparent quarantine sandbox with action interception
  policy              — Sandbox policy language (PRL extension) and enforcement
"""
