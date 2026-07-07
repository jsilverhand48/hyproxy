# syntax=docker/dockerfile:1
#
# hyproxy control plane image (IdP, admin API, authz). One image, three
# entrypoints selected by the compose `command`. The admin service also serves
# the built React SPA, so the UI is compiled in a stage and copied in.
#
# Build context is the repo root (compose sets `context: .`) so this Dockerfile
# can reach both server/ and ui/.

# --- UI build stage ---------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
# The SPA's IdP issuer and client id are compiled into the bundle by Vite. Pass
# them as build args (compose forwards them from .env) so a staging/prod image
# targets the real issuer; the defaults keep local/dev builds unchanged.
ARG VITE_IDP_ISSUER=https://idp.localhost:8300
ARG VITE_ADMIN_UI_CLIENT_ID=admin-ui
ARG VITE_PORTAL_HOST=""
ENV VITE_IDP_ISSUER=$VITE_IDP_ISSUER \
    VITE_ADMIN_UI_CLIENT_ID=$VITE_ADMIN_UI_CLIENT_ID \
    VITE_PORTAL_HOST=$VITE_PORTAL_HOST
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build   # emits /ui/dist (bakes VITE_IDP_ISSUER)

# --- Python runtime ---------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS runtime

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/server/.venv \
    PATH=/app/server/.venv/bin:$PATH \
    HYPROXY_ADMIN_UI_DIST=/app/ui/dist

WORKDIR /app/server

# tpm2-tools backs the TPM secrets backend (core/secrets.py tpm_unseal shells
# out to tpm2_unseal). The device itself is passed through by compose only in
# TPM deployments (deploy/docker-compose.tpm.yml); harmless otherwise.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first for layer caching. --no-dev drops the test/lint toolchain.
COPY server/pyproject.toml server/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application source + migrations, then install the project itself.
COPY server/src ./src
COPY server/alembic ./alembic
COPY server/alembic.ini ./alembic.ini
RUN uv sync --frozen --no-dev

# The compiled SPA the admin app serves from HYPROXY_ADMIN_UI_DIST.
COPY --from=ui /ui/dist /app/ui/dist

# Drop privileges.
RUN useradd --system --uid 10001 --home-dir /app app && chown -R app /app
USER app

# Loopback-published by compose; the baremetal data plane reverse-proxies here.
EXPOSE 8300 8400 8500

# No default CMD: compose supplies the per-service command (uvicorn ... / alembic).
