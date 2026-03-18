# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex Trust Engine — Multi-stage Dockerfile
#
# Stage 1: Compile Rust binary with release optimisations (LTO, strip).
# Stage 2: Copy binary into minimal Debian runtime image.
#
# Build (from repo root — needs proto/ context):
#   docker build -t phantex-trust-engine -f trust-engine/Dockerfile .
#
# Run:
#   docker run --rm -p 50052:50052 phantex-trust-engine

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy proto definitions first (needed by build.rs)
COPY proto/ /build/proto/

# Copy Cargo manifest for dependency caching (lock regenerated to pick up new features)
COPY trust-engine/Cargo.toml /build/trust-engine/

# Create a dummy main.rs to cache dependency compilation
RUN mkdir -p /build/trust-engine/src && \
    echo "fn main() {}" > /build/trust-engine/src/main.rs && \
    echo "fn main() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }" > /build/trust-engine/build.rs && \
    cd /build/trust-engine && \
    cargo build --release 2>/dev/null || true && \
    rm -rf /build/trust-engine/src /build/trust-engine/build.rs

# Copy actual source
COPY trust-engine/src/ /build/trust-engine/src/
COPY trust-engine/build.rs /build/trust-engine/build.rs
COPY trust-engine/benches/ /build/trust-engine/benches/

# Build the real binary
RUN cd /build/trust-engine && \
    touch src/main.rs && \
    cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1000 phantex && \
    useradd --uid 1000 --gid phantex --shell /bin/false phantex

# Snapshot persistence directory
RUN mkdir -p /data/snapshots && chown phantex:phantex /data/snapshots

COPY --from=builder /build/trust-engine/target/release/phantex-trust-engine /usr/local/bin/phantex-trust-engine

USER phantex

ENV TRUST_ENGINE_GRPC_ADDR="0.0.0.0:50052" \
    TRUST_ENGINE_SNAPSHOT__DIR="/data/snapshots" \
    RUST_LOG="info"

EXPOSE 50052

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["phantex-trust-engine", "--health"] || exit 1

CMD ["phantex-trust-engine"]
