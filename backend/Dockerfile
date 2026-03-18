# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex Backend — Multi-stage Dockerfile
#
# Stage 1: Install Python deps in a venv.
# Stage 2: Copy venv + app code into slim runtime image.
#
# Non-root, read-only-capable, no secrets baked in.
# All config via PHANTEX_* environment variables.
#
# Build:
#   docker build -t phantex-backend backend/
#
# Run:
#   docker run --rm -p 8000:8000 \
#     -e PHANTEX_DB_HOST=host.docker.internal:5432 \
#     phantex-backend

# ── Stage 0: SDK source (copied from parent context) ──────────────────────────
# Uses a scratch stage so the SDK can be COPY'd into the builder without
# requiring a broader build context.  docker-compose sets:
#   build.additional_contexts.sdk-src: ./sdk/python
# When additional_contexts overrides this stage, files land at / (root).
# The fallback scratch stage also places files at / so the COPY path is
# consistent in both modes.
FROM scratch AS sdk-src
COPY . /

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# OS deps for asyncpg (libpq) and bcrypt (gcc)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

# Install Phantex SDK from local source (zero hard deps)
COPY --from=sdk-src / /build/sdk-python
RUN /opt/venv/bin/pip install --no-cache-dir /build/sdk-python

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# libpq is needed at runtime for asyncpg
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1000 phantex && \
    useradd --uid 1000 --gid phantex --shell /bin/false phantex

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy application code
COPY app/ ./app/
COPY engine/ ./engine/
COPY migrations/ ./migrations/
COPY ml/ ./ml/
COPY models/ ./models/

# Switch to non-root
USER phantex

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"]

# Uvicorn with production settings (workers overridden by env / compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info", "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
