# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex Sensor — Multi-stage Dockerfile
#
# Stage 1: Compile eBPF probes (clang/llvm).
# Stage 2: Build static Go binary with pre-compiled BPF objects embedded.
# Stage 3: Minimal distroless runtime.
#
# MUST be built from the repo root (needs proto/gen/go for replace directive):
#   docker build -f sensor/Dockerfile -t phantex-sensor .
#
# Run (requires privileged for eBPF):
#   docker run --rm --privileged \
#     -v /sys/kernel/debug:/sys/kernel/debug:ro \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     phantex-sensor --config /etc/phantex/sensor.yaml

# ── Stage 1: eBPF probe compilation ──────────────────────────────────────────
FROM ubuntu:24.04 AS bpf-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang-18 llvm-18 libbpf-dev linux-headers-generic linux-tools-generic make && \
    ln -sf /usr/bin/clang-18 /usr/bin/clang && \
    ln -sf /usr/bin/llvm-strip-18 /usr/bin/llvm-strip && \
    BPFTOOL=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | tail -1) && \
    [ -n "$BPFTOOL" ] && ln -sf "$BPFTOOL" /usr/local/bin/bpftool && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build/sensor/ebpf
COPY sensor/ebpf/ .
RUN make all

# ── Stage 2: Go binary build ─────────────────────────────────────────────────
FROM golang:1.23-alpine AS go-builder

RUN apk add --no-cache git make

WORKDIR /build

# Copy proto generated code (needed by replace directive in go.mod)
COPY proto/gen/go/ proto/gen/go/

# Copy sensor source
COPY sensor/ sensor/

# Copy compiled BPF objects from stage 1
COPY --from=bpf-builder /build/sensor/ebpf/build/ sensor/internal/ebpf/bpf/

WORKDIR /build/sensor

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -trimpath \
    -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo docker)" \
    -o /phantex-sensor ./cmd/phantex-sensor/

# ── Stage 3: Runtime ─────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=go-builder /phantex-sensor /usr/local/bin/phantex-sensor

# Sensor needs to run as root for eBPF capabilities
USER root

ENTRYPOINT ["/usr/local/bin/phantex-sensor"]
CMD ["--config", "/etc/phantex/sensor.yaml"]
