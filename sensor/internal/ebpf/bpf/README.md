# Compiled eBPF probe objects

This directory holds the compiled `.bpf.o` files that are embedded into the
Go sensor binary via `go:embed`.

Run `make` from `sensor/ebpf/` to compile the probes, then `make copy-bpf`
from `sensor/` (or use the top-level build) to copy them here.

The `.bpf.o` files are **not** checked into git — they are build artifacts.
