#!/usr/bin/env bash
#
# start.sh: start hyproxy end to end.
#
# Staging reuses the production topology (docs/staging.md, docs/deployment.md):
#   - Containerized: Postgres + control plane (idp/admin/authz) [+ guac bridge],
#     brought up via docker compose, published on 127.0.0.1 only.
#   - Baremetal: the Go data plane, the single LAN TLS ingress on :443, started
#     here in the foreground. It reverse-proxies to the containers over loopback.
#   - Service: the ACME (Let's Encrypt DNS-01) renewal timer, enabled if its unit
#     is installed, so the wildcard cert keeps renewing.
#
# This is the STAGING launcher; it drives the WHOLE flow: render the data-plane
# config, verify (or build) artifacts, bring up every container, start the cert
# renewal timer, and run the data plane. Ctrl-C stops the data plane and the
# containers. For the one-time first run (image build, migrate, first admin,
# cert issuance) run bootstrap-prod.sh and deploy/acme/obtain-cert.sh once first;
# see docs/staging.md.
#
# Optional environment toggles:
#   REBUILD=1         rebuild the container images before starting (bakes the
#                     current SPA + server code; use after pulling changes).
#   RENDER_CONFIG=1   re-render dataplane/config.json from .env even if present.
#   SKIP_TIMER=1      do not touch the ACME renewal systemd timer.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATAPLANE="$ROOT/dataplane"
ENV_FILE="$ROOT/.env"
DP_CONFIG="$DATAPLANE/config.json"
DP_BIN="$DATAPLANE/bin/dataplane"
RENDER="$ROOT/deploy/render-dataplane-config.sh"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

REBUILD="${REBUILD:-0}"
RENDER_CONFIG="${RENDER_CONFIG:-0}"
SKIP_TIMER="${SKIP_TIMER:-0}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Docker is mandatory --------------------------------------------------
log "preflight: toolchain"
command -v docker >/dev/null || die "docker not found. Staging requires Docker; aborting."
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required; aborting."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable; aborting."

# --- 1. Load staging configuration -------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  if [ -f "$ROOT/.env.staging.example" ]; then
    cp "$ROOT/.env.staging.example" "$ENV_FILE"
    warn "seeded repo-root .env from .env.staging.example."
  fi
  die "edit .env with your HYPROXY_DOMAIN, HYPROXY_ISSUER, HYPROXY_ADMIN_UI_ORIGIN, and POSTGRES_PASSWORD, then re-run."
fi
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# TPM secrets backend: layer the device-passthrough overlay onto every compose
# invocation (the explicit -f above bypasses any COMPOSE_FILE in .env).
if [ "${HYPROXY_SECRETS_BACKEND:-file}" = "tpm" ]; then
  COMPOSE+=(-f "$ROOT/deploy/docker-compose.tpm.yml")
fi

# --- 2. Reject dev configuration (fail closed) -------------------------------
log "preflight: staging config values"
: "${HYPROXY_ISSUER:?HYPROXY_ISSUER must be set in .env}"
case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// for staging (got: $HYPROXY_ISSUER)" ;;
esac
: "${HYPROXY_DOMAIN:?HYPROXY_DOMAIN must be set in .env for staging}"
case "$HYPROXY_ISSUER" in
  *example.com*) die "HYPROXY_ISSUER still points at example.com; set your real HYPROXY_DOMAIN hosts in .env" ;;
esac

# Gateway topology: derive from HYPROXY_DOMAIN unless the operator set it in .env.
# These reach the control-plane containers (docker-compose server-env) so the authz
# service and the cli agree on gateway_redirect_uri(); the cookie domain is the
# parent so the gateway session is shared across the auth host and app hosts.
export HYPROXY_AUTH_HOST="${HYPROXY_AUTH_HOST:-auth.$HYPROXY_DOMAIN}"
export HYPROXY_EXTERNAL_SCHEME="${HYPROXY_EXTERNAL_SCHEME:-https}"
export HYPROXY_GATEWAY_COOKIE_DOMAIN="${HYPROXY_GATEWAY_COOKIE_DOMAIN:-$HYPROXY_DOMAIN}"
log "gateway auth host: $HYPROXY_EXTERNAL_SCHEME://$HYPROXY_AUTH_HOST (cookie domain: $HYPROXY_GATEWAY_COOKIE_DOMAIN)"
[ "${POSTGRES_PASSWORD:-change-me-strong}" = "change-me-strong" ] && \
  warn "POSTGRES_PASSWORD is the staging example default; set a real password in .env"

# --- 3. Render the data-plane config -----------------------------------------
if [ "$RENDER_CONFIG" = "1" ] || [ ! -f "$DP_CONFIG" ]; then
  [ -x "$RENDER" ] || die "renderer not found or not executable: $RENDER"
  log "rendering dataplane/config.json from .env"
  "$RENDER"
else
  log "dataplane/config.json present (set RENDER_CONFIG=1 to re-render)"
fi

# --- 4. Build artifacts if needed --------------------------------------------
# Data-plane binary: build it when missing (needs the Go toolchain). A staging
# first run normally has bootstrap-prod.sh do this already.
if [ ! -x "$DP_BIN" ]; then
  if command -v go >/dev/null 2>&1; then
    log "data-plane binary missing; building it (make dp-build)"
    make -C "$ROOT" dp-build
  else
    die "missing $DP_BIN and no Go toolchain to build it. Run bootstrap-prod.sh first."
  fi
fi

# Container images: rebuild on request so a pulled change (SPA or server code)
# is baked in. The SPA's issuer is a build arg sourced from HYPROXY_ISSUER.
if [ "$REBUILD" = "1" ]; then
  log "rebuilding container images (bakes current SPA + server code)"
  "${COMPOSE[@]}" build
fi

# --- 5. Fail-closed artifact + TLS preflight ---------------------------------
FAIL=0
need_file() { [ -e "$1" ] || { warn "missing required artifact: $1 ($2)"; FAIL=1; }; }

log "preflight: baremetal + TLS artifacts"
need_file "$DP_BIN"    "compiled data plane"
need_file "$DP_CONFIG" "rendered data-plane config"

BACKEND="${HYPROXY_SECRETS_BACKEND:-file}"
case "$BACKEND" in
  file)
    warn "file secrets backend: docs/production.md requires migrating to TPM before exposure."
    need_file "${HYPROXY_MASTER_KEY_FILE:-$ROOT/server/.dev/master.keys}" \
      "master key file for the file backend (compose mounts it as a secret)"
    ;;
  tpm)
    need_file "/dev/tpmrm0" "TPM device (passed through via deploy/docker-compose.tpm.yml)"
    ;;
  *) die "unknown HYPROXY_SECRETS_BACKEND=$BACKEND" ;;
esac

# TLS material the data plane serves (paths live in the rendered JSON config).
for key in tls_cert tls_key; do
  val="$(sed -nE "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*/\1/p" "$DP_CONFIG" | head -n1)"
  [ -n "$val" ] || { warn "$key not set in $DP_CONFIG"; FAIL=1; continue; }
  case "$val" in
    /*) full="$val" ;;
    *)  full="$DATAPLANE/$val" ;;
  esac
  need_file "$full" "$key TLS material (issue via deploy/acme/obtain-cert.sh, docs/staging.md)"
done

[ "$FAIL" -eq 0 ] || die "preflight failed; not starting. bootstrap-prod.sh + obtain-cert.sh cover these."

# --- 6. Bring up the containerized stack -------------------------------------
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

# --- 7. ACME renewal timer (service) -----------------------------------------
if [ "$SKIP_TIMER" != "1" ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl cat hyproxy-acme.timer >/dev/null 2>&1; then
    log "ensuring the ACME renewal timer is enabled and running"
    if systemctl enable --now hyproxy-acme.timer 2>/dev/null; then
      systemctl is-active --quiet hyproxy-acme.timer && log "hyproxy-acme.timer active"
    else
      warn "could not enable hyproxy-acme.timer (run as root: 'systemctl enable --now hyproxy-acme.timer')"
    fi
  else
    warn "hyproxy-acme.timer not installed; cert will not auto-renew. See docs/staging.md step 2."
  fi
fi

# --- 8. Start the baremetal data plane (foreground) --------------------------
cleanup() {
  printf '\n'
  log "stopping the containerized stack"
  "${COMPOSE[@]}" "${PROFILES[@]}" stop 2>/dev/null || true
  [ -n "${DP_PID:-}" ] && kill -TERM "-$DP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

log "starting the baremetal data plane (LAN ingress on ${DP_LISTEN:-:443})"
setsid bash -c "cd '$DATAPLANE' && exec ./bin/dataplane -config config.json" &
DP_PID=$!

cat <<EOF

$(printf '\033[1;32mhyproxy staging is up.\033[0m')

  IdP         https://idp.$HYPROXY_DOMAIN            (issuer: $HYPROXY_ISSUER)
  Admin UI    ${HYPROXY_ADMIN_UI_ORIGIN:-https://admin.$HYPROXY_DOMAIN}   (LAN only; OIDC + DPoP + step-up enforced)
  Auth host   https://auth.$HYPROXY_DOMAIN           (gateway / guac broker)
  Data plane  baremetal on ${DP_LISTEN:-:443}, Host-routed from dataplane/config.json
  Guac bridge ${HYPROXY_GUAC_CYPHER_KEY:+enabled (tunnel + guacd)}${HYPROXY_GUAC_CYPHER_KEY:-disabled}

Point idp./admin./auth.$HYPROXY_DOMAIN at this VM's LAN IP (LAN DNS or /etc/hosts).
Container logs:  docker compose ${PROFILES[*]} logs -f
The data plane runs in the foreground here; Ctrl-C stops it and the containers.
For persistence, install deploy/systemd/hyproxy-dataplane.service instead (docs/staging.md).
EOF

wait "$DP_PID" 2>/dev/null || true
warn "the data plane exited; stopping the stack"
