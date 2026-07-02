#!/usr/bin/env bash
#
# start-prod.sh: start hyproxy end to end in a production environment.
#
# Unlike run.sh (dev), this BUILDS NOTHING and RELAXES NOTHING. It hard-requires
# Docker, fail-closes if any production dependency, framework, artifact, or
# configuration value is missing, and only then starts the stack:
#
#   Postgres (docker compose) -> migrations -> signing keys ->
#   IdP + admin + authz (loopback, behind the data plane) -> data plane (public).
#
# Run bootstrap-prod.sh once before the first start (it creates the admin,
# registers clients, and builds the UI + data-plane binary this script expects).
#
# Configuration is read from server/.env (production values). Optional:
#   WEB_CONCURRENCY=<n>   uvicorn workers per Python service (default 2)
#   WITH_TUNNEL=1         also start the guacamole-lite tunnel (needs guacd)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$ROOT/server"
DATAPLANE="$ROOT/dataplane"
UI="$ROOT/ui"
TUNNEL="$ROOT/tunnel"

ENV_FILE="$SERVER/.env"
DP_CONFIG="$DATAPLANE/config.json"
DP_BIN="$DATAPLANE/bin/dataplane"
UI_DIST="$UI/dist"
WORKERS="${WEB_CONCURRENCY:-2}"
WITH_TUNNEL="${WITH_TUNNEL:-0}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Docker is mandatory --------------------------------------------------
# Per the production contract the datastore runs under Docker. No Docker, no run.
command -v docker >/dev/null || die "docker not found. Production start requires Docker; aborting."
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required (docker compose); aborting."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable; aborting."

# --- 1. Fail-closed preflight ------------------------------------------------
# Accumulate every problem, then refuse to start if anything is missing.
FAIL=0
need_cmd()  { command -v "$1" >/dev/null || { warn "missing dependency: $1 ($2)"; FAIL=1; }; }
need_file() { [ -e "$1" ] || { warn "missing required artifact: $1 ($2)"; FAIL=1; }; }

log "preflight: production dependencies and frameworks"
need_cmd uv  "Python runtime + dependency manager"
need_cmd go  "data-plane build/verify toolchain"

log "preflight: build artifacts (produced by bootstrap-prod.sh)"
need_file "$ENV_FILE"  "production settings; copy .env.example and fill in prod values"
need_file "$DP_CONFIG" "production data-plane config; copy dataplane/config.example.json"
need_file "$DP_BIN"    "compiled data plane; run 'make dp-build' or bootstrap-prod.sh"
need_file "$UI_DIST"   "built admin UI; run 'make ui-build' or bootstrap-prod.sh"

[ "$FAIL" -eq 0 ] || die "preflight failed; not starting. Resolve the items above (bootstrap-prod.sh covers most)."

# Load production configuration so both this script and the child services see
# the same values. server/.env holds simple KEY=VALUE lines.
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# --- 2. Reject dev stand-ins -------------------------------------------------
log "preflight: rejecting dev configuration"
: "${HYPROXY_DB_URL:?HYPROXY_DB_URL must be set in server/.env}"
: "${HYPROXY_ISSUER:?HYPROXY_ISSUER must be set in server/.env}"
case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// in production (got: $HYPROXY_ISSUER)" ;;
esac

BACKEND="${HYPROXY_SECRETS_BACKEND:-file}"
case "$BACKEND" in
  tpm)
    [ -n "${HYPROXY_TPM_SEALED_BLOB:-}" ] || die "HYPROXY_SECRETS_BACKEND=tpm but HYPROXY_TPM_SEALED_BLOB is unset"
    [ -f "$HYPROXY_TPM_SEALED_BLOB" ] || die "TPM sealed blob not found: $HYPROXY_TPM_SEALED_BLOB"
    ;;
  file)
    warn "file secrets backend in use: docs/production.md requires migrating to TPM"
    warn "before the public port faces the internet."
    [ -n "${HYPROXY_MASTER_KEY_FILE:-}" ] && [ -f "$HYPROXY_MASTER_KEY_FILE" ] \
      || die "HYPROXY_MASTER_KEY_FILE missing for the file backend"
    ;;
  *) die "unknown HYPROXY_SECRETS_BACKEND=$BACKEND" ;;
esac

# Verify the TLS material the data plane serves actually exists (parse the JSON
# config with the Python already required above; no ad-hoc JSON parsing in bash).
log "preflight: data-plane TLS material"
( cd "$SERVER" && uv run python - "$DP_CONFIG" <<'PY'
import json, sys, os
cfg = json.load(open(sys.argv[1]))
base = os.path.dirname(os.path.abspath(sys.argv[1]))
missing = []
for k in ("tls_cert", "tls_key"):
    p = cfg.get(k)
    if not p:
        missing.append(f"{k} not set in config")
        continue
    full = p if os.path.isabs(p) else os.path.join(base, p)
    if not os.path.exists(full):
        missing.append(f"{k} -> {p} (resolved {full}) does not exist")
if not cfg.get("listen"):
    missing.append("listen not set (public bind address)")
if missing:
    sys.stderr.write("data-plane config problems:\n  - " + "\n  - ".join(missing) + "\n")
    sys.exit(1)
print(f"data plane will listen on {cfg['listen']}")
PY
) || die "data-plane TLS/config preflight failed; obtain certs via your ACME client (docs/production.md section 2)."

# --- 3. Database -------------------------------------------------------------
log "starting Postgres via docker compose"
docker compose -f "$ROOT/docker-compose.yml" up -d --wait

log "applying migrations"
( cd "$SERVER" && uv run alembic upgrade head )

log "ensuring signing keys exist"
( cd "$SERVER" && uv run python -m hyproxy.cli bootstrap-keys )

# --- 4. Launch ---------------------------------------------------------------
# The IdP, admin, and authz services bind loopback ONLY. The Go data plane is
# the sole public listener; it terminates TLS and reverse-proxies to them by
# Host. --proxy-headers trusts the forwarded client IP from the loopback proxy.
PIDS=()
start_svc() {
  local name="$1"; shift
  log "starting $name"
  setsid "$@" &
  PIDS+=("$!")
}
cleanup() {
  printf '\n'
  log "stopping services"
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] || continue
    kill -TERM "-$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

UVICORN_COMMON="--host 127.0.0.1 --proxy-headers --forwarded-allow-ips 127.0.0.1 --workers $WORKERS --no-use-colors"

start_svc idp bash -c "cd '$SERVER' && exec uv run uvicorn hyproxy.idp.app:app --port 8300 $UVICORN_COMMON"
start_svc admin bash -c "cd '$SERVER' && exec uv run uvicorn hyproxy.admin.app:app --port 8400 $UVICORN_COMMON"
start_svc authz bash -c "cd '$SERVER' && exec uv run uvicorn hyproxy.authz.app:app --port 8500 $UVICORN_COMMON"
start_svc dataplane bash -c "cd '$DATAPLANE' && exec ./bin/dataplane -config config.json"

if [ "$WITH_TUNNEL" = "1" ]; then
  need_file "$TUNNEL/node_modules" "tunnel deps; run 'make tunnel-install'" || true
  start_svc tunnel bash -c "cd '$TUNNEL' && exec npm start"
fi

cat <<EOF

$(printf '\033[1;32mhyproxy production stack is up.\033[0m')

  Public         data plane on $HYPROXY_ISSUER (single public port from dataplane/config.json)
  IdP / admin / authz   loopback only (127.0.0.1:8300 / :8400 / :8500), reverse-proxied by the data plane
  Admin plane    reach the admin API over WireGuard/LAN only (docs/admin-access.md)

Supervising in the foreground. Under a real deployment, prefer systemd units per
service (see docs/production.md). Press Ctrl-C to stop everything.
EOF

wait -n 2>/dev/null || true
warn "a service exited; stopping the rest"
