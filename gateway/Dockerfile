# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex Gateway — Multi-stage Dockerfile
#
# Builds both phantex-gateway and phantex-consumer from the same image.
# Uses distroless runtime (non-root).
#
# MUST be built from the repo root (needs proto/gen/go for replace directive):
#   docker build -f gateway/Dockerfile -t phantex-gateway .
#
# Run gateway:
#   docker run --rm -p 50051:50051 phantex-gateway gateway
#
# Run consumer (Kafka → DB bridge):
#   docker run --rm phantex-gateway consumer

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build

# Copy proto generated code (needed by replace directive in go.mod)
COPY proto/gen/go/ proto/gen/go/

# Copy gateway source
COPY gateway/ gateway/

WORKDIR /build/gateway

# Build gateway binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo docker)" \
    -o /phantex-gateway ./cmd/phantex-gateway/

# Build consumer binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo docker)" \
    -o /phantex-consumer ./cmd/phantex-consumer/

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /phantex-gateway /usr/local/bin/phantex-gateway
COPY --from=builder /phantex-consumer /usr/local/bin/phantex-consumer

USER nonroot

EXPOSE 50051

ENTRYPOINT ["/usr/local/bin/phantex-gateway"]
