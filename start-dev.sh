#!/usr/bin/env bash
#
# start-dev.sh: start hyproxy end to end for local development.
#
# Brings up the database, applies migrations, generates dev keys and certs,
# builds the admin UI and the Go data plane, then launches every long-running
# service (IdP, admin API, authz, data plane) together. Ctrl-C stops all of
# them cleanly.
#
# This is the DEV launcher. For a production first run use bootstrap-prod.sh.
#
# Optional environment toggles:
#   SKIP_UI=1        skip the admin UI install/build step
#   WITH_TUNNEL=1    also start the guacamole-lite tunnel (needs a running guacd)
#   FORCE_UI=1       rebuild the UI even if ui/dist already exists
#   BIND_HOST=addr   interface the Python services bind (default 127.0.0.1).
#                    Set BIND_HOST=0.0.0.0 to reach them from the LAN for
#                    manual component testing. DEV ONLY: no auth fronts these
#                    ports, so only do this on a trusted network.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$ROOT/server"
DATAPLANE="$ROOT/dataplane"
UI="$ROOT/ui"
TUNNEL="$ROOT/tunnel"

# Paths of dev artifacts, relative to their owning tool's working directory.
MASTER_KEYS="$SERVER/.dev/master.keys"
CERT="$SERVER/.dev/certs/idp.localhost.pem"
ENV_FILE="$SERVER/.env"
DP_BIN="$DATAPLANE/bin/dataplane"

SKIP_UI="${SKIP_UI:-0}"
WITH_TUNNEL="${WITH_TUNNEL:-0}"
FORCE_UI="${FORCE_UI:-0}"
BIND_HOST="${BIND_HOST:-127.0.0.1}"

# Dev origin the SPA is served from (the admin app itself). Enables the IdP CORS
# allowance and the step-up return target.
ADMIN_UI_ORIGIN="http://127.0.0.1:8400"
ADMIN_UI_REDIRECT="http://127.0.0.1:8400/callback"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Preflight ---------------------------------------------------------------
log "preflight: checking toolchain"
command -v uv >/dev/null   || die "uv not found (https://docs.astral.sh/uv/)"
command -v go >/dev/null   || die "go toolchain not found (needed for the data plane)"
if [ "$SKIP_UI" != "1" ]; then
  command -v npm >/dev/null || die "npm not found (set SKIP_UI=1 to skip the UI)"
fi

# server/.env drives every Python service (pydantic-settings reads it from the
# server working directory). Seed it from the example on first run.
if [ ! -f "$ENV_FILE" ]; then
  log "creating server/.env from .env.example"
  cp "$ROOT/.env.example" "$ENV_FILE"
  warn "review server/.env; defaults target the local dev database"
fi

# --- Database ----------------------------------------------------------------
log "starting database (docker compose, or user-space pgserver fallback)"
make -C "$ROOT" up

log "applying migrations"
make -C "$ROOT" db-migrate

# --- Keys and certs ----------------------------------------------------------
if [ -f "$MASTER_KEYS" ]; then
  log "dev master key present, keeping it"
else
  log "generating dev master key"
  make -C "$ROOT" gen-keys
fi

if [ -f "$CERT" ]; then
  log "dev TLS certs present, keeping them"
else
  log "generating self-signed dev TLS certs (WebAuthn needs a secure context)"
  make -C "$ROOT" gen-certs
fi

# --- Admin UI ----------------------------------------------------------------
if [ "$SKIP_UI" = "1" ]; then
  warn "SKIP_UI=1: admin UI will not be built or served"
else
  log "registering the admin-ui OIDC client (idempotent)"
  make -C "$ROOT" create-admin-ui-client args="--redirect-uri $ADMIN_UI_REDIRECT" \
    || warn "admin-ui client likely already registered, continuing"

  if [ ! -d "$UI/node_modules" ]; then
    log "installing UI dependencies"
    make -C "$ROOT" ui-install
  fi

  if [ "$FORCE_UI" = "1" ] || [ ! -d "$UI/dist" ]; then
    log "building the admin UI"
    if make -C "$ROOT" ui-build; then
      export HYPROXY_ADMIN_UI_ORIGIN="$ADMIN_UI_ORIGIN"
    else
      warn "UI build failed; admin app will run API-only"
    fi
  else
    log "admin UI already built (ui/dist), set FORCE_UI=1 to rebuild"
    export HYPROXY_ADMIN_UI_ORIGIN="$ADMIN_UI_ORIGIN"
  fi
fi

# --- Data plane --------------------------------------------------------------
log "building the Go data plane"
make -C "$ROOT" dp-build

# --- Launch ------------------------------------------------------------------
# Each service runs in its own process group (setsid) so cleanup can kill the
# whole tree, including the python/uvicorn child spawned by `uv run`.
PIDS=()

start_svc() {
  local name="$1"; shift
  log "starting $name"
  setsid "$@" &
  PIDS+=("$!")
}

cleanup() {
  printf '\n'
  log "shutting down"
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] || continue
    kill -TERM "-$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

start_svc idp bash -c "cd '$SERVER' && exec uv run uvicorn hyproxy.idp.app:app \
  --host $BIND_HOST --port 8300 \
  --ssl-keyfile .dev/certs/idp.localhost-key.pem \
  --ssl-certfile .dev/certs/idp.localhost.pem"

start_svc admin bash -c "cd '$SERVER' && exec uv run uvicorn hyproxy.admin.app:app \
  --host $BIND_HOST --port 8400"

start_svc authz bash -c "cd '$SERVER' && exec uv run uvicorn hyproxy.authz.app:app \
  --host $BIND_HOST --port 8500"

start_svc dataplane bash -c "cd '$DATAPLANE' && exec ./bin/dataplane -config config.example.json"

if [ "$WITH_TUNNEL" = "1" ]; then
  if [ ! -d "$TUNNEL/node_modules" ]; then
    log "installing tunnel dependencies"
    make -C "$ROOT" tunnel-install
  fi
  start_svc tunnel bash -c "cd '$TUNNEL' && exec npm start"
fi

cat <<EOF

$(printf '\033[1;32mhyproxy is up.\033[0m')

  IdP        https://idp.localhost:8300     (bound to $BIND_HOST)
  Admin API  http://$BIND_HOST:8400   (UI served here when built)
  Authz      http://$BIND_HOST:8500   (internal only)
  Data plane https://localhost:8443  (Host-routed to backends in dataplane/config.example.json)

Note: the routes use *.localhost hostnames (idp.localhost, auth.localhost,
photos.localhost, ...). Most resolvers map *.localhost to 127.0.0.1; if yours
does not, add entries to /etc/hosts yourself.

Press Ctrl-C to stop everything.
EOF

# Block until a service exits or the user interrupts.
wait -n 2>/dev/null || true
warn "a service exited; shutting the rest down"
