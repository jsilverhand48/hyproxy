#!/usr/bin/env bash
#
# rebuild-staging.sh: rebuild the WHOLE staging stack in place, from current
# source, without a full first-run bootstrap.
#
# What it rebuilds:
#   - the control-plane image (idp/admin/authz share hyproxy-server:local). The
#     admin SPA is compiled inside this image (server/Dockerfile UI stage), so a
#     UI change only reaches staging by rebuilding it here.
#   - the baremetal Go data plane binary (make dp-build).
# Then it re-applies migrations and recreates the running containers so the new
# image is picked up, and restarts the data plane if it runs as a systemd unit.
#
# This is NOT the first-run path: it assumes bootstrap-prod.sh + obtain-cert.sh
# have already run (image existed, cert issued, first admin created). For a fresh
# VM use bootstrap-prod.sh (docs/staging.md).
#
# Run it ON THE STAGING VM, from the repo root, after checking out the code you
# want deployed (the image bakes whatever source is on this box, not elsewhere).
#
# Optional environment toggles:
#   PULL=1            git pull before building (fetch the change you want live)
#   NO_CACHE=1        docker compose build --no-cache (clean image rebuild)
#   RENDER_CONFIG=1   re-render dataplane/config.json from .env even if present
#   SKIP_DATAPLANE=1  do not rebuild/restart the baremetal data plane

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATAPLANE="$ROOT/dataplane"
ENV_FILE="$ROOT/.env"
DP_CONFIG="$DATAPLANE/config.json"
DP_BIN="$DATAPLANE/bin/dataplane"
RENDER="$ROOT/deploy/render-dataplane-config.sh"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

PULL="${PULL:-0}"
NO_CACHE="${NO_CACHE:-0}"
RENDER_CONFIG="${RENDER_CONFIG:-0}"
SKIP_DATAPLANE="${SKIP_DATAPLANE:-0}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Preflight ------------------------------------------------------------
log "preflight: toolchain"
command -v docker >/dev/null || die "docker not found. Staging requires Docker; aborting."
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required; aborting."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable; aborting."

[ -f "$ENV_FILE" ] || die "no .env at repo root. Copy .env.staging.example and edit it (docs/staging.md)."

# --- 1. Optionally fetch the code to deploy ----------------------------------
if [ "$PULL" = "1" ]; then
  command -v git >/dev/null || die "PULL=1 set but git not found."
  log "git pull (updating source to deploy)"
  git -C "$ROOT" pull --ff-only
fi
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --short HEAD >/dev/null 2>&1; then
  log "building from commit $(git -C "$ROOT" rev-parse --short HEAD) ($(git -C "$ROOT" rev-parse --abbrev-ref HEAD))"
fi

# --- 2. Load + sanity-check staging configuration ----------------------------
# .env must be exported before the image build so Vite bakes the real issuer
# (VITE_IDP_ISSUER <- HYPROXY_ISSUER) into the SPA. Without this the served UI
# would target the localhost dev issuer and login would break.
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

log "preflight: staging config values"
: "${HYPROXY_ISSUER:?HYPROXY_ISSUER must be set in .env}"
case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// for staging (got: $HYPROXY_ISSUER)" ;;
esac
case "$HYPROXY_ISSUER" in
  *example.com*|*localhost*) die "HYPROXY_ISSUER is still a placeholder ($HYPROXY_ISSUER); set your real staging host in .env" ;;
esac

# --- 3. Data-plane config ----------------------------------------------------
if [ "$RENDER_CONFIG" = "1" ] || [ ! -f "$DP_CONFIG" ]; then
  [ -x "$RENDER" ] || die "renderer not found or not executable: $RENDER"
  log "rendering dataplane/config.json from .env"
  "$RENDER"
else
  log "dataplane/config.json present (set RENDER_CONFIG=1 to re-render)"
fi

# --- 4. Rebuild the baremetal data-plane binary ------------------------------
if [ "$SKIP_DATAPLANE" != "1" ]; then
  command -v go >/dev/null 2>&1 || die "go toolchain not found (needed to rebuild the data plane; set SKIP_DATAPLANE=1 to skip)."
  log "rebuilding the data-plane binary (make dp-build)"
  make -C "$ROOT" dp-build
fi

# --- 5. Which container profiles are in play ---------------------------------
PROFILES=(--profile app)
if [ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ]; then
  log "guac enabled (HYPROXY_GUAC_CYPHER_KEY set): including the guac profile"
  PROFILES+=(--profile guac)
else
  log "guac disabled (HYPROXY_GUAC_CYPHER_KEY unset)"
fi

# --- 6. Rebuild the control-plane image (bakes the current SPA + server) ------
BUILD_ARGS=()
[ "$NO_CACHE" = "1" ] && BUILD_ARGS+=(--no-cache)
log "rebuilding container images${NO_CACHE:+ (no cache)}"
"${COMPOSE[@]}" "${PROFILES[@]}" build "${BUILD_ARGS[@]}"

# --- 7. Recreate the running stack -------------------------------------------
log "starting Postgres"
"${COMPOSE[@]}" up -d --wait postgres

log "applying migrations (one-shot container)"
"${COMPOSE[@]}" run --rm migrate

log "recreating the control plane with the new image${HYPROXY_GUAC_CYPHER_KEY:+ + guac bridge}"
# The rebuilt image has a new ID, so `up` recreates the control-plane containers
# on its own; the already-healthy Postgres is left untouched (no needless bounce).
"${COMPOSE[@]}" "${PROFILES[@]}" up -d --wait

# --- 8. Restart the baremetal data plane if it's a systemd service -----------
if [ "$SKIP_DATAPLANE" != "1" ]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl cat hyproxy-dataplane >/dev/null 2>&1; then
    log "restarting the hyproxy-dataplane service onto the new binary"
    if sudo systemctl restart hyproxy-dataplane 2>/dev/null; then
      systemctl is-active --quiet hyproxy-dataplane && log "hyproxy-dataplane active"
    else
      warn "could not restart hyproxy-dataplane (run: sudo systemctl restart hyproxy-dataplane)"
    fi
  else
    warn "hyproxy-dataplane systemd unit not installed; the data plane runs in the foreground."
    warn "restart it yourself to pick up the new binary (e.g. re-run ./start-staging.sh)."
  fi
fi

# --- 9. Summary --------------------------------------------------------------
cat <<EOF

$(printf '\033[1;32mstaging rebuild complete.\033[0m')

  Images     rebuilt (hyproxy-server:local — bakes SPA issuer $HYPROXY_ISSUER)
  Containers recreated: $("${COMPOSE[@]}" "${PROFILES[@]}" ps --services 2>/dev/null | paste -sd' ' -)
  Data plane $([ "$SKIP_DATAPLANE" = "1" ] && echo "skipped (SKIP_DATAPLANE=1)" || echo "binary rebuilt")

Next:
  - Hard-refresh the admin UI in the browser (Ctrl+Shift+R) to drop cached index.html.
  - Verify: "${COMPOSE[@]}" ${PROFILES[*]} ps        (services healthy)
            curl -sI https://admin.\${STAGING_DOMAIN:-<domain>}/ | head -n1
EOF
