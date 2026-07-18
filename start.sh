#!/usr/bin/env bash
#
# start.sh: start the full hyproxy stack in the foreground.
#
# Brings up the containerized services (Postgres, migrations, control plane,
# optional guac bridge) with Docker Compose, ensures the ACME renewal timer
# is running, then runs the baremetal data plane in the foreground. Ctrl-C
# stops the data plane and the containers. For unattended operation use the
# hyproxy.service systemd unit that install.sh writes.
#
# Flags (environment variables):
#   REBUILD=1        rebuild container images before starting
#   SKIP_TIMER=1     skip enabling/checking the hyproxy-acme.timer unit


set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATAPLANE="$ROOT/dataplane"
ENV_FILE="$ROOT/.env"
DP_CONFIG="$DATAPLANE/config.json"
DP_BIN="$DATAPLANE/bin/dataplane"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

REBUILD="${REBUILD:-0}"
SKIP_TIMER="${SKIP_TIMER:-0}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Docker is mandatory --------------------------------------------------
log "preflight: toolchain"
command -v docker >/dev/null || die "docker not found; the containerized stack requires Docker. Aborting."
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required; aborting."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable; aborting."

# --- 1. Load configuration from .env ------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  if [ -f "$ROOT/.env.example" ]; then
    cp "$ROOT/.env.example" "$ENV_FILE"
    warn "seeded repo-root .env from .env.example."
  fi
  die "edit .env with your HYPROXY_DOMAIN, HYPROXY_ISSUER, HYPROXY_ADMIN_UI_ORIGIN, and POSTGRES_PASSWORD, then re-run."
fi
set -a
. "$ENV_FILE"
set +a

# The master key is sealed in the TPM; these let the control-plane containers
# unseal it (docker-compose.yml x-tpm-access). Missing values fail closed.
export HYPROXY_TPM_DEVICE="${HYPROXY_TPM_DEVICE:-/dev/tpmrm0}"
: "${TSS_GID:?TSS_GID must be set in .env to the gid of the host 'tss' group}"
: "${HYPROXY_TPM_SEALED_BLOB:?HYPROXY_TPM_SEALED_BLOB must be set in .env (persistent handle of the sealed master key)}"

# --- 2. Validate config values, derive gateway settings (fail closed) --------
log "preflight: config values"
: "${HYPROXY_ISSUER:?HYPROXY_ISSUER must be set in .env}"
case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// (got: $HYPROXY_ISSUER)" ;;
esac
: "${HYPROXY_DOMAIN:?HYPROXY_DOMAIN must be set in .env}"
case "$HYPROXY_ISSUER" in
  *example.com*) die "HYPROXY_ISSUER still points at example.com; set your real HYPROXY_DOMAIN hosts in .env" ;;
esac

export HYPROXY_AUTH_HOST="${HYPROXY_AUTH_HOST:-auth.$HYPROXY_DOMAIN}"
export HYPROXY_EXTERNAL_SCHEME="${HYPROXY_EXTERNAL_SCHEME:-https}"
export HYPROXY_GATEWAY_COOKIE_DOMAIN="${HYPROXY_GATEWAY_COOKIE_DOMAIN:-$HYPROXY_DOMAIN}"
log "gateway auth host: $HYPROXY_EXTERNAL_SCHEME://$HYPROXY_AUTH_HOST (cookie domain: $HYPROXY_GATEWAY_COOKIE_DOMAIN)"
[ "${POSTGRES_PASSWORD:-change-me-strong}" = "change-me-strong" ] && \
  warn "POSTGRES_PASSWORD is the .env.example default; set a real password in .env"

# --- 3. Build artifacts if needed --------------------------------------------
if [ ! -x "$DP_BIN" ]; then
  if command -v go >/dev/null 2>&1; then
    log "data-plane binary missing; building it (make dp-build)"
    make -C "$ROOT" dp-build
  else
    die "missing $DP_BIN and no Go toolchain to build it; install Go, then run ./build.sh."
  fi
fi

if [ "$REBUILD" = "1" ]; then
  log "rebuilding container images (bakes current SPA + server code)"
  "${COMPOSE[@]}" build
fi

# --- 4. Fail-closed artifact + TLS preflight ---------------------------------
FAIL=0
need_file() { [ -e "$1" ] || { warn "missing required artifact: $1 ($2)"; FAIL=1; }; }

log "preflight: baremetal + TLS artifacts"
need_file "$DP_BIN"    "compiled data plane (run ./build.sh)"
need_file "$DP_CONFIG" "rendered data-plane config (run ./build.sh)"
need_file "$HYPROXY_TPM_DEVICE" "TPM device (passed into the control plane via docker-compose.yml)"

for key in tls_cert tls_key; do
  val="$(sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*/\1/p" "$DP_CONFIG" | head -n1)"
  [ -n "$val" ] || { warn "$key not set in $DP_CONFIG"; FAIL=1; continue; }
  case "$val" in
    /*) full="$val" ;;
    *)  full="$DATAPLANE/$val" ;;
  esac
  need_file "$full" "$key TLS material (issued by hyproxy-obtain-cert.sh, which install.sh sets up)"
done

[ "$FAIL" -eq 0 ] || die "preflight failed; not starting. build.sh produces the build artifacts; install.sh sets up TLS issuance."

# --- 5. Bring up the containerized stack -------------------------------------
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

log "ensuring the data plane forward-auth (gateway) OIDC client is registered"
"${COMPOSE[@]}" run --rm cli bootstrap-gateway-client \
  || die "failed to register the gateway client; protected resources will 400 at /oidc/authorize"

log "starting the control plane${HYPROXY_GUAC_CYPHER_KEY:+ + guac bridge}"
"${COMPOSE[@]}" "${PROFILES[@]}" up -d --wait

# --- 6. ACME renewal timer (service) -----------------------------------------
if [ "$SKIP_TIMER" != "1" ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl cat hyproxy-acme.timer >/dev/null 2>&1; then
    log "ensuring the ACME renewal timer is enabled and running"
    if systemctl enable --now hyproxy-acme.timer 2>/dev/null; then
      systemctl is-active --quiet hyproxy-acme.timer && log "hyproxy-acme.timer active"
    else
      warn "could not enable hyproxy-acme.timer (run as root: 'systemctl enable --now hyproxy-acme.timer')"
    fi
  else
    warn "hyproxy-acme.timer not installed; cert will not auto-renew. install.sh writes and enables it."
  fi
fi

# --- 7. Start the baremetal data plane (foreground) --------------------------
cleanup() {
  printf '\n'
  log "stopping the containerized stack"
  "${COMPOSE[@]}" "${PROFILES[@]}" stop 2>/dev/null || true
  [ -n "${DP_PID:-}" ] && kill -TERM "-$DP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

log "starting the baremetal data plane (ingress on ${DP_LISTEN:-:443})"
setsid bash -c "cd '$DATAPLANE' && exec ./bin/dataplane -config config.json" &
DP_PID=$!

cat <<EOF

$(printf '\033[1;32mhyproxy is up.\033[0m')

  IdP         https://idp.$HYPROXY_DOMAIN            (issuer: $HYPROXY_ISSUER)
  Admin UI    ${HYPROXY_ADMIN_UI_ORIGIN:-https://admin.$HYPROXY_DOMAIN}   (LAN only; OIDC + DPoP + step-up enforced)
  Auth host   https://auth.$HYPROXY_DOMAIN           (gateway / guac broker)
  Data plane  baremetal on ${DP_LISTEN:-:443}, Host-routed from dataplane/config.json
  Guac bridge $([ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ] && echo "enabled (tunnel + guacd)" || echo "disabled")

Ensure idp./admin./auth.$HYPROXY_DOMAIN resolve to this host from their intended networks.
Container logs:  docker compose ${PROFILES[*]} logs -f
The data plane runs in the foreground here; Ctrl-C stops it and the containers.
For persistence, enable the hyproxy.service systemd unit instead (install.sh writes it).
EOF

rc=0
wait "$DP_PID" 2>/dev/null || rc=$?
warn "the data plane exited (status $rc); stopping the stack"
exit "$rc"
