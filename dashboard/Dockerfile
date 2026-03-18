# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex Dashboard — Multi-stage Dockerfile
#
# Stage 1: Build React app with Vite.
# Stage 2: Serve static bundle via Nginx with API reverse-proxy.
#
# Build:
#   docker build -t phantex-dashboard dashboard/
#
# Run:
#   docker run --rm -p 3000:80 phantex-dashboard
#
# The Nginx config proxies /api/* and /ws/* to the backend service.
# In Docker Compose / K8s, set BACKEND_URL env (default: http://phantex-backend:8000).

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /build

# Install deps first (layer cache)
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# Copy source and build
COPY . .
RUN npm run build

# ── Stage 2: Nginx runtime ───────────────────────────────────────────────────
# Use Alpine's own nginx + headers-more module (built together, guaranteed
# binary-compatible). This fully strips the Server header — not just the version.
FROM alpine:3.21 AS runtime

# Install nginx + headers-more module from Alpine repos
RUN apk add --no-cache nginx nginx-mod-http-headers-more \
 && mkdir -p /var/cache/nginx /var/log/nginx /usr/share/nginx/html /run/nginx \
 && rm -f /etc/nginx/http.d/default.conf

# Composable nginx.conf: load the headers-more module + include our site config
RUN printf 'load_module /usr/lib/nginx/modules/ngx_http_headers_more_filter_module.so;\n\
worker_processes auto;\n\
error_log /var/log/nginx/error.log warn;\n\
pid /run/nginx/nginx.pid;\n\
events { worker_connections 1024; }\n\
http {\n\
  include /etc/nginx/mime.types;\n\
  default_type application/octet-stream;\n\
  sendfile on;\n\
  keepalive_timeout 65;\n\
  include /etc/nginx/http.d/*.conf;\n\
}\n' > /etc/nginx/nginx.conf

# Nginx config with API proxy (Alpine uses http.d/ not conf.d/)
COPY --from=builder /build/nginx.conf /etc/nginx/http.d/phantex.conf

# Copy built assets
COPY --from=builder /build/dist /usr/share/nginx/html

# Non-root: nginx user already exists in Alpine
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /run/nginx

USER nginx

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["wget", "-qO-", "http://127.0.0.1:80/"]

CMD ["nginx", "-g", "daemon off;"]
