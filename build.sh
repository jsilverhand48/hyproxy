#!/usr/bin/env bash
#
# build.sh: build the hyproxy stack from current source, verify it is
# functional, then STOP everything. Leaves NOTHING running.
#
# Builds the hyproxy app and dataplane. it does not start the data plane and does 
# not leave containers up. It brings the stack up only long enough to smoke-test it, 
# then tears it all down. No lingering processes, containers, or networks remain 
# when the script exits.
#
# Incremental by default: each component is rebuilt only when ITS OWN source
# inputs changed since the last successful build (content hashes cached under
# .build/). Nothing else is touched.
#   - control-plane image  <- server/src, alembic, pyproject/uv.lock, ui/,
#                             Dockerfile, compose, baked Vite build args
#                             (+ tunnel/ when guac is enabled)
#   - data-plane binary    <- dataplane/**.go (excluding *_test.go), go.mod, go.sum
#
#   --clean   rebuild the whole stack regardless of detected changes (image is
#             rebuilt --no-cache; the data-plane binary is rebuilt from scratch).
#
# Scope: this BUILDS and VERIFIES. It does NOT deploy: it never touches the
# hyproxy-dataplane systemd unit and never copies the binary into /opt (that is
# a deploy step; see docs/UPDATES.md).
#
# Env toggles:
#   RENDER_CONFIG=1   re-render dataplane/config.json from .env even if present
#   SKIP_DATAPLANE=1  build/verify the containers only (skip the data-plane binary)
#
# Run from the repo root, with a valid .env (see docs/prod.md).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATAPLANE="$ROOT/dataplane"
ENV_FILE="$ROOT/.env"
DP_CONFIG="$DATAPLANE/config.json"
DP_BIN="$DATAPLANE/bin/dataplane"
RENDER="$ROOT/deploy/render-dataplane-config.sh"
STATE_DIR="$ROOT/.build"
IMAGE_HASH_FILE="$STATE_DIR/image.hash"
DP_HASH_FILE="$STATE_DIR/dataplane.hash"
IMAGE="hyproxy-server:local"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

RENDER_CONFIG="${RENDER_CONFIG:-0}"
SKIP_DATAPLANE="${SKIP_DATAPLANE:-0}"
CLEAN=0

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --clean)   CLEAN=1 ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *)         die "unknown argument: $arg (supported: --clean, --help)" ;;
  esac
done

# --- 0. Preflight ------------------------------------------------------------
log "preflight: toolchain + config"
command -v docker >/dev/null || die "docker not found."
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable."
[ -f "$ENV_FILE" ] || die "no .env at repo root (copy .env.prod.example; see docs/prod.md)."

# .env must be exported before the image build so Vite bakes the real issuer
# (VITE_IDP_ISSUER <- HYPROXY_ISSUER) into the SPA; without it the served UI
# would target the localhost dev issuer and login would break.
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# TPM secrets backend: the device passthrough is built into docker-compose.yml
# (x-tpm-access) via HYPROXY_TPM_DEVICE / TSS_GID substitutions with no-op
# defaults for the file backend; resolve and validate them here.
if [ "${HYPROXY_SECRETS_BACKEND:-file}" = "tpm" ]; then
  export HYPROXY_TPM_DEVICE="${HYPROXY_TPM_DEVICE:-/dev/tpmrm0}"
  : "${TSS_GID:?TSS_GID must be set in .env to the gid of the host 'tss' group}"
  : "${HYPROXY_TPM_SEALED_BLOB:?HYPROXY_TPM_SEALED_BLOB must be set in .env (persistent handle of the sealed master key)}"
fi

log "preflight: config values"
: "${HYPROXY_ISSUER:?HYPROXY_ISSUER must be set in .env}"
case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// (got: $HYPROXY_ISSUER)" ;;
esac
case "$HYPROXY_ISSUER" in
  *example.com*|*localhost*) die "HYPROXY_ISSUER is still a placeholder ($HYPROXY_ISSUER); set your real host in .env" ;;
esac

# The file backend needs a real key file; the TPM backend keeps the key in the
# TPM (the compose master_key secret points at /dev/null and is never read).
if [ "${HYPROXY_SECRETS_BACKEND:-file}" != "tpm" ]; then
  MASTER_KEY_FILE="${HYPROXY_MASTER_KEY_FILE:-$ROOT/server/.dev/master.keys}"
  [ -f "$MASTER_KEY_FILE" ] || die "master key not found at $MASTER_KEY_FILE (run bootstrap-prod.sh / cli bootstrap-keys first)."
fi

# guac is a container too: include it only when its key is set, so its image is
# built and its inputs (tunnel/) count toward the control-plane build hash.
PROFILES=(--profile app)
GUAC=0
if [ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ]; then
  PROFILES+=(--profile guac)
  GUAC=1
  log "guac enabled (HYPROXY_GUAC_CYPHER_KEY set): including the guac profile"
else
  log "guac disabled (HYPROXY_GUAC_CYPHER_KEY unset)"
fi

# --- 1. Data-plane config (rendered artifact the data plane consumes) ---------
if [ "$RENDER_CONFIG" = "1" ] || [ ! -f "$DP_CONFIG" ]; then
  [ -x "$RENDER" ] || die "renderer not found or not executable: $RENDER"
  log "rendering dataplane/config.json from .env"
  "$RENDER"
else
  log "dataplane/config.json present (set RENDER_CONFIG=1 to re-render)"
fi

mkdir -p "$STATE_DIR"

# --- 2. Change detection: control-plane image --------------------------------
compute_image_hash() {
  local paths=(
    docker-compose.yml
    server/Dockerfile server/pyproject.toml server/uv.lock server/alembic.ini
    server/src server/alembic
    ui
  )
  [ "$GUAC" = "1" ] && paths+=(tunnel)
  {
    ( cd "$ROOT" && find "${paths[@]}" \
        -type d \( -name node_modules -o -name dist -o -name .venv -o -name __pycache__ \
                   -o -name .mypy_cache -o -name .pytest_cache -o -name .ruff_cache \
                   -o -name .hypothesis \) -prune -o \
        -type f -not -name '*.pyc' -print0 ) | LC_ALL=C sort -z | xargs -0 sha256sum
    # Build args are baked into the image, so a change must invalidate the cache.
    printf 'arg VITE_IDP_ISSUER=%s\n' "${HYPROXY_ISSUER:-}"
    printf 'arg VITE_ADMIN_UI_CLIENT_ID=%s\n' "${VITE_ADMIN_UI_CLIENT_ID:-admin-ui}"
  } | sha256sum | awk '{print $1}'
}

IMAGE_HASH="$(compute_image_hash)"
IMAGE_PREV="$(cat "$IMAGE_HASH_FILE" 2>/dev/null || true)"
IMAGE_PRESENT=0
docker image inspect "$IMAGE" >/dev/null 2>&1 && IMAGE_PRESENT=1

NEED_IMAGE=1
if [ "$CLEAN" = "1" ]; then
  log "image: --clean set; rebuilding --no-cache"
elif [ "$IMAGE_PRESENT" = "1" ] && [ "$IMAGE_HASH" = "$IMAGE_PREV" ]; then
  NEED_IMAGE=0
  log "image: no source changes since last build; reusing $IMAGE"
elif [ "$IMAGE_PRESENT" = "0" ]; then
  log "image: $IMAGE not present; building"
else
  log "image: source changed since last build; rebuilding"
fi

# --- 3. Change detection: data-plane binary ----------------------------------
compute_dataplane_hash() {
  ( cd "$ROOT" && find dataplane -type d -name bin -prune -o \
      -type f ! -name '*_test.go' \
        \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -print0 ) \
    | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
}

NEED_DP=0
DP_HASH=""
if [ "$SKIP_DATAPLANE" = "1" ]; then
  log "data plane: skipped (SKIP_DATAPLANE=1)"
else
  DP_HASH="$(compute_dataplane_hash)"
  DP_PREV="$(cat "$DP_HASH_FILE" 2>/dev/null || true)"
  NEED_DP=1
  if [ "$CLEAN" = "1" ]; then
    log "data plane: --clean set; rebuilding binary"
  elif [ -x "$DP_BIN" ] && [ "$DP_HASH" = "$DP_PREV" ]; then
    NEED_DP=0
    log "data plane: no source changes since last build; reusing $DP_BIN"
  elif [ ! -x "$DP_BIN" ]; then
    log "data plane: binary missing; building"
  else
    log "data plane: source changed since last build; rebuilding"
  fi
fi

# --- 4. Build the components that need it ------------------------------------
if [ "$NEED_IMAGE" = "1" ]; then
  BUILD_ARGS=()
  [ "$CLEAN" = "1" ] && BUILD_ARGS+=(--no-cache)
  log "building the control-plane image${CLEAN:+ (no cache)}"
  "${COMPOSE[@]}" "${PROFILES[@]}" build "${BUILD_ARGS[@]}"
  printf '%s\n' "$IMAGE_HASH" > "$IMAGE_HASH_FILE"
fi

if [ "$NEED_DP" = "1" ]; then
  command -v go >/dev/null 2>&1 || die "go toolchain not found (needed to build the data plane; set SKIP_DATAPLANE=1 to skip)."
  log "building the data-plane binary (make dp-build)"
  make -C "$ROOT" dp-build
  printf '%s\n' "$DP_HASH" > "$DP_HASH_FILE"
fi

# --- 5. Teardown guard: nothing survives this script -------------------------
cleanup() {
  log "stopping everything (leaving nothing running)"
  "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  # compose down only reaps THIS build's stack. Control-plane processes started
  # outside compose (uvicorn idp/admin/authz via start-dev.sh or `make run-*`,
  # the data plane, the dev Postgres) would otherwise survive and break the
  # "nothing running" guarantee, so hand off to the comprehensive stopper.
  
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  info() { printf '  %s\n' "$*"; }
  step() { printf '==> %s\n' "$*"; }

  # Gracefully TERM, then KILL after a short grace period, every process whose
  # full command line matches an extended-regex pattern.
  kill_pat() {
    local desc="$1" pat="$2" pids
    pids="$(pgrep -f "$pat" 2>/dev/null || true)"
    if [ -z "$pids" ]; then
      info "$desc: not running"
      return
    fi
    info "$desc: stopping ($(echo "$pids" | tr '\n' ' '))"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    for _ in 1 2 3 4 5 6; do
      sleep 0.3
      pgrep -f "$pat" >/dev/null 2>&1 || return
    done
    pids="$(pgrep -f "$pat" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      info "$desc: forcing (SIGKILL)"
      # shellcheck disable=SC2086
      kill -9 $pids 2>/dev/null || true
    fi
  }

  # --- 1. Frontend dev servers (Vite UI + guac tunnel) -------------------------
  step "frontend dev servers"
  kill_pat "ui dev server (vite)" "${ROOT}/ui/node_modules/.*vite"
  kill_pat "guac tunnel"          "${ROOT}/tunnel/node_modules/.*(vite|tunnel)|${ROOT}/tunnel .*npm"

  # --- 2. Go data plane --------------------------------------------------------
  step "data plane"
  kill_pat "dataplane binary" "bin/dataplane( |$)|/dataplane/bin/dataplane"

  # --- 3. Control-plane apps (uvicorn: idp / admin / authz) ---------------------
  step "control-plane apps"
  kill_pat "uvicorn (idp/admin/authz)" "uvicorn hyproxy\.(idp|admin|authz)\.app:app"

  # --- 4. Docker Compose stack -------------------------------------------------
  step "docker containers"
  if command -v docker >/dev/null 2>&1; then
    if [ -f "${ROOT}/docker-compose.yml" ]; then
      # `down` removes every service in the project regardless of profile; name it
      # explicitly so we hit the stack even when run from elsewhere.
      (cd "$ROOT" && docker compose -p hyproxy down --remove-orphans 2>/dev/null) \
        && info "compose project 'hyproxy' brought down" \
        || info "compose down reported nothing to do"
    else
      info "no docker-compose.yml here; skipping compose"
    fi
    # Belt and suspenders: stop any stray containers named hyproxy-*.
    cids="$(docker ps -q --filter 'name=hyproxy-' 2>/dev/null || true)"
    if [ -n "$cids" ]; then
      info "stopping leftover hyproxy-* containers"
      # shellcheck disable=SC2086
      docker stop $cids >/dev/null 2>&1 || true
    fi
  else
    info "docker not installed; skipping containers"
  fi

  # --- 5. systemd units (production installs only) -----------------------------
  step "systemd units"
  if command -v systemctl >/dev/null 2>&1; then
    for unit in hyproxy-dataplane.service hyproxy-acme.timer hyproxy-acme.service; do
      if systemctl cat "$unit" >/dev/null 2>&1; then
        if systemctl is-active --quiet "$unit"; then
          if systemctl stop "$unit" 2>/dev/null; then
            info "$unit: stopped"
          else
            info "$unit: active but stop failed (run as root: 'systemctl stop $unit')"
          fi
        else
          info "$unit: not active"
        fi
      fi
    done
  else
    info "systemctl not available; skipping units"
  fi

  # --- 6. Postgres dev cluster (user-space pgserver) ---------------------------
  step "postgres dev cluster"
  if [ -d "${ROOT}/server/.dev" ] && command -v uv >/dev/null 2>&1; then
    (cd "${ROOT}/server" && uv run python scripts/devdb.py stop 2>/dev/null) \
      && info "dev cluster stopped" \
      || info "dev cluster not running"
  else
    info "no user-space dev cluster (server/.dev absent or uv missing)"
  fi

  step "done - hyproxy stopped"
  log "done - all processes stopped"
}
trap cleanup EXIT

# --- 6. Bring the containers up just long enough to verify them --------------
log "starting Postgres"
"${COMPOSE[@]}" up -d --wait postgres

log "applying migrations (one-shot container)"
"${COMPOSE[@]}" run --rm migrate

log "starting the control plane${GUAC:+ + guac bridge}"
"${COMPOSE[@]}" "${PROFILES[@]}" up -d --wait

http_ok() {
  local url="$1" i code
  for i in $(seq 1 10); do
    if command -v curl >/dev/null 2>&1; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
    else
      code="$(python3 - "$url" <<'PY' 2>/dev/null || true
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=3) as r:
        print(r.status)
except Exception:
    print("000")
PY
)"
    fi
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  return 1
}

log "smoke-testing the control plane (/healthz)"
declare -A ENDPOINTS=(
  [idp]="http://127.0.0.1:8300/healthz"
  [admin]="http://127.0.0.1:8400/healthz"
  [authz]="http://127.0.0.1:8500/healthz"
)
FAILED=0
for svc in idp admin authz; do
  if http_ok "${ENDPOINTS[$svc]}"; then
    printf '  \033[1;32mok\033[0m   %s\n' "$svc"
  else
    printf '  \033[1;31mFAIL\033[0m %s (%s)\n' "$svc" "${ENDPOINTS[$svc]}"
    "${COMPOSE[@]}" logs --tail 30 "$svc" || true
    FAILED=1
  fi
done

# The data plane binds :443 with TLS and forward-auths against the running
# control plane, so a full runtime check belongs to start-prod.sh, not to a
# build. Here the functional guarantee is that it compiled and produced an
# executable binary (the build above would have failed otherwise).
if [ "$SKIP_DATAPLANE" != "1" ]; then
  log "verifying the data-plane binary"
  if [ -x "$DP_BIN" ]; then
    printf '  \033[1;32mok\033[0m   dataplane (compiled: %s)\n' "$DP_BIN"
  else
    printf '  \033[1;31mFAIL\033[0m dataplane (no executable at %s)\n' "$DP_BIN"
    FAILED=1
  fi
fi

[ "$FAILED" = "0" ] || die "one or more components did not verify as functional."

# --- 7. Summary --------------------------------------------------------------
cat <<EOF

$(printf '\033[1;32mbuild verified; stack stopped.\033[0m')

  Image      $([ "$NEED_IMAGE" = "1" ] && echo "rebuilt ($IMAGE, bakes SPA issuer $HYPROXY_ISSUER)" || echo "reused ($IMAGE)")
  Data plane $([ "$SKIP_DATAPLANE" = "1" ] && echo "skipped (SKIP_DATAPLANE=1)" || { [ "$NEED_DP" = "1" ] && echo "binary rebuilt" || echo "binary reused"; })
  Containers verified healthy, then stopped (no lingering processes)

This script only builds + verifies. Use start-prod.sh to run.
EOF
# cleanup() runs on EXIT and stops everything.
