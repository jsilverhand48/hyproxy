#!/usr/bin/env bash
#
# start-prod.sh: start hyproxy end to end in a production environment.
#
# Hybrid model (docs/deployment.md):
#   - Containerized: Postgres + control plane (idp/admin/authz) + guac bridge,
#     brought up via docker compose, published on 127.0.0.1 only.
#   - Baremetal: the Go data plane, the single public TLS ingress, started here
#     in the foreground. It reverse-proxies to the containers over loopback.
#
# This BUILDS NOTHING and RELAXES NOTHING. It hard-requires Docker and
# fail-closes if any production dependency, artifact, or config value is
# missing. Run bootstrap-prod.sh once first (it builds the images and the
# data-plane binary, migrates, and creates the admin).
#
# Configuration is read from the repo-root .env (compose variable substitution).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATAPLANE="$ROOT/dataplane"
ENV_FILE="$ROOT/.env"
DP_CONFIG="$DATAPLANE/config.json"
DP_BIN="$DATAPLANE/bin/dataplane"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Docker is mandatory --------------------------------------------------
command -v docker >/dev/null || die "docker not found. Production start requires Docker; aborting."
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required; aborting."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable; aborting."

# --- 1. Load configuration ---------------------------------------------------
[ -f "$ENV_FILE" ] || die "repo-root .env not found. Copy .env.example to .env and set production values."
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# --- 2. Fail-closed preflight ------------------------------------------------
FAIL=0
need_file() { [ -e "$1" ] || { warn "missing required artifact: $1 ($2)"; FAIL=1; }; }

log "preflight: baremetal data-plane artifacts"
need_file "$DP_BIN"    "compiled data plane; run bootstrap-prod.sh or 'make dp-build'"
need_file "$DP_CONFIG" "production data-plane config; copy dataplane/config.example.json"

log "preflight: rejecting dev configuration"
: "${HYPROXY_ISSUER:?HYPROXY_ISSUER must be set in .env}"
case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// in production (got: $HYPROXY_ISSUER)" ;;
esac
[ "${POSTGRES_PASSWORD:-devonly}" = "devonly" ] && warn "POSTGRES_PASSWORD is the dev default; set a real password in .env"

BACKEND="${HYPROXY_SECRETS_BACKEND:-file}"
case "$BACKEND" in
  tpm)
    warn "TPM backend selected. Containers need the TPM device passed through, or run"
    warn "the control plane on baremetal (docs/deployment.md). Verify before relying on it."
    ;;
  file)
    warn "file secrets backend: docs/production.md requires migrating to TPM before exposure."
    KEY_SRC="${HYPROXY_MASTER_KEY_FILE:-$ROOT/server/.dev/master.keys}"
    need_file "$KEY_SRC" "master key file for the file backend (compose mounts it as a secret)"
    ;;
  *) die "unknown HYPROXY_SECRETS_BACKEND=$BACKEND" ;;
esac

# Verify the TLS material the data plane serves actually exists. Extract the
# paths from the JSON config without a JSON parser (flat config, one per line).
log "preflight: data-plane TLS material"
for key in tls_cert tls_key; do
  val="$(sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*/\1/p" "$DP_CONFIG" | head -n1)"
  [ -n "$val" ] || { warn "$key not set in $DP_CONFIG"; FAIL=1; continue; }
  case "$val" in
    /*) full="$val" ;;
    *)  full="$DATAPLANE/$val" ;;
  esac
  need_file "$full" "$key referenced by the data-plane config (obtain via ACME, docs/production.md section 2)"
done

[ "$FAIL" -eq 0 ] || die "preflight failed; not starting. bootstrap-prod.sh covers most of these."

# --- 3. Bring up the containerized stack -------------------------------------
PROFILES=(--profile app)
if [ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ]; then
  log "guac enabled (HYPROXY_GUAC_CYPHER_KEY set): including the guac profile"
  PROFILES+=(--profile guac)
else
  log "guac disabled (HYPROXY_GUAC_CYPHER_KEY unset)"
fi

log "starting Postgres"
"${COMPOSE[@]}" up -d --wait postgres

log "applying migrations (one-shot container)"
"${COMPOSE[@]}" run --rm migrate

log "starting the control plane${HYPROXY_GUAC_CYPHER_KEY:+ + guac bridge}"
"${COMPOSE[@]}" "${PROFILES[@]}" up -d --wait

# --- 4. Start the baremetal data plane (foreground) --------------------------
cleanup() {
  printf '\n'
  log "stopping the containerized stack"
  "${COMPOSE[@]}" "${PROFILES[@]}" stop 2>/dev/null || true
  [ -n "${DP_PID:-}" ] && kill -TERM "-$DP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

log "starting the baremetal data plane (public ingress)"
setsid bash -c "cd '$DATAPLANE' && exec ./bin/dataplane -config config.json" &
DP_PID=$!

cat <<EOF

$(printf '\033[1;32mhyproxy production stack is up.\033[0m')

  Public         data plane (baremetal) on $HYPROXY_ISSUER, single public port from dataplane/config.json
  Control plane  containers on 127.0.0.1: idp:8300 admin:8400 authz:8500 (reverse-proxied by the data plane)
  Guac bridge    ${HYPROXY_GUAC_CYPHER_KEY:+tunnel:8600 + guacd (internal)}${HYPROXY_GUAC_CYPHER_KEY:-disabled}
  Admin plane    reach admin over WireGuard/LAN only (docs/admin-access.md)

Container logs:  docker compose ${PROFILES[*]} logs -f
The data plane runs in the foreground here; Ctrl-C stops it and the containers.
For a real deployment, run the data plane under systemd too (docs/deployment.md).
EOF

wait "$DP_PID" 2>/dev/null || true
warn "the data plane exited; stopping the stack"
