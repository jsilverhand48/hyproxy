#!/usr/bin/env bash
#
# bootstrap-prod.sh: one-time preparation for the FIRST production run.
#
# Hybrid model (docs/deployment.md): the control plane runs in containers; the
# Go data plane runs on baremetal. This script therefore builds the container
# images, runs the one-time database + identity setup INSIDE containers, builds
# the baremetal data-plane binary on the host, runs the quality gates, and then
# STOPS short of opening the public port.
#
# It is fail-closed and idempotent where possible. Re-running is safe.
#
# Required repo-root .env (compose reads it for substitution; see .env.example):
#   POSTGRES_PASSWORD        production database password (not the dev default)
#   HYPROXY_ISSUER           public HTTPS issuer, e.g. https://idp.example.com
#   HYPROXY_ADMIN_UI_ORIGIN  admin origin the SPA is served from
# Secrets backend (docs/production.md section 1):
#   HYPROXY_SECRETS_BACKEND=file + HYPROXY_MASTER_KEY_FILE=<path>   (bridge)
#   HYPROXY_SECRETS_BACKEND=tpm  (see docs/deployment.md for device passthrough)
#
# Required shell environment (not app config):
#   ADMIN_EMAIL, ADMIN_NAME  the first (break-glass) admin to create
# Optional:
#   ADMIN_UI_REDIRECT        admin-ui redirect_uri (default: <origin>/callback)
#   HYPROXY_GUAC_CYPHER_KEY  enable guac (also give the same value to the tunnel)
#   SKIP_GATES=1             skip `make audit` + `make dp-test` (not recommended)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }
require_var() { [ -n "${!1:-}" ] || die "required env var $1 is not set (see the header of this script)"; }

# --- 0. Guardrails -----------------------------------------------------------
log "hyproxy production bootstrap (hybrid: containers + baremetal data plane)"
echo "This prepares a first production run: it builds images, touches the"
echo "production database, and creates the first admin. It will NOT open the"
echo "public port."
read -r -p "Type 'bootstrap' to continue: " confirm
[ "$confirm" = "bootstrap" ] || die "aborted"

# --- 1. Preflight ------------------------------------------------------------
log "preflight: toolchain"
command -v docker >/dev/null || die "docker not found (image build + containerized setup)"
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required"
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
command -v go >/dev/null || die "go toolchain not found (baremetal data-plane build)"
command -v uv >/dev/null || die "uv not found (quality gates); set SKIP_GATES=1 to skip"

[ -f "$ENV_FILE" ] || die "repo-root .env not found. Copy .env.example to .env and set production values."
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

log "preflight: required configuration"
require_var HYPROXY_ISSUER
require_var HYPROXY_ADMIN_UI_ORIGIN
require_var ADMIN_EMAIL
require_var ADMIN_NAME
case "$HYPROXY_ISSUER" in https://*) : ;; *) die "HYPROXY_ISSUER must be https:// in production" ;; esac
[ "${POSTGRES_PASSWORD:-devonly}" = "devonly" ] && warn "POSTGRES_PASSWORD is the dev default; set a real one in .env before real use"
ADMIN_UI_REDIRECT="${ADMIN_UI_REDIRECT:-${HYPROXY_ADMIN_UI_ORIGIN%/}/callback}"

# --- 2. Secrets backend ------------------------------------------------------
BACKEND="${HYPROXY_SECRETS_BACKEND:-file}"
log "secrets backend: $BACKEND"
case "$BACKEND" in
  tpm)
    warn "TPM backend: containers need the TPM device passed through or the control"
    warn "plane must run on baremetal. See docs/deployment.md before relying on it."
    ;;
  file)
    warn "file backend keeps unsealed key material on disk; migrate to TPM before exposure."
    KEY_SRC="${HYPROXY_MASTER_KEY_FILE:-$ROOT/server/.dev/master.keys}"
    if [ -f "$KEY_SRC" ]; then
      log "master key present at $KEY_SRC"
    else
      log "generating a master key at $KEY_SRC (compose mounts it as the master_key secret)"
      mkdir -p "$(dirname "$KEY_SRC")"
      ( cd "$ROOT/server" && HYPROXY_MASTER_KEY_FILE="$KEY_SRC" uv run python -m hyproxy.cli gen-keys )
    fi
    ;;
  *) die "unknown HYPROXY_SECRETS_BACKEND=$BACKEND (expected 'tpm' or 'file')" ;;
esac

# --- 3. Build images ---------------------------------------------------------
# The server image compiles the React UI in a stage and bakes it in; the tunnel
# image bundles guacamole-lite. guacd and postgres are pulled.
log "building container images (server + tunnel; UI compiled inside the server image)"
"${COMPOSE[@]}" --profile app --profile guac --profile tools build

# --- 4. Database + identity setup (in containers) ----------------------------
log "starting Postgres"
"${COMPOSE[@]}" up -d --wait postgres

log "applying migrations"
"${COMPOSE[@]}" run --rm migrate

log "ensuring signing keys exist (published in JWKS)"
"${COMPOSE[@]}" run --rm cli bootstrap-keys

log "creating the first admin: $ADMIN_EMAIL"
"${COMPOSE[@]}" run --rm cli bootstrap-admin --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" \
  || warn "bootstrap-admin reported an error (admin may already exist); continuing"

log "registering the admin-ui OIDC public client"
"${COMPOSE[@]}" run --rm cli create-client \
    --client-id admin-ui --name "Admin UI" --redirect-uri "$ADMIN_UI_REDIRECT" \
  || warn "admin-ui client already registered; continuing"

echo
echo "Register resource relying parties (gateway clients) later with:"
echo "  docker compose run --rm cli create-client --client-id <id> --name <name> --redirect-uri <uri>"

# --- 5. Guacamole ------------------------------------------------------------
if [ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ]; then
  log "guac enabled: the tunnel container receives HYPROXY_GUAC_CYPHER_KEY via compose"
else
  log "guac disabled (HYPROXY_GUAC_CYPHER_KEY unset)"
  echo "To enable later: mint a key with"
  echo "  docker compose run --rm cli gen-guac-key"
  echo "then set HYPROXY_GUAC_CYPHER_KEY in .env (the tunnel and broker share it)."
fi

# --- 6. Baremetal data plane -------------------------------------------------
log "building the baremetal Go data plane binary"
make -C "$ROOT" dp-build
[ -f "$ROOT/dataplane/config.json" ] \
  || warn "no dataplane/config.json yet: copy config.example.json and set prod routes + tls_cert/tls_key"

# --- 7. TLS certificates (no self-sign in prod) ------------------------------
log "TLS certificates"
cat <<'EOF'
Obtain real certificates with a VETTED ACME client (no hand-rolled crypto):
  - lego or certbot with a DNS-01 plugin (works behind CGNAT, wildcards). Stage first.
  - Point its output at the data plane's tls_cert / tls_key paths; the TLS
    hot-reload seam (internal/tlsconf) picks up new files with no restart.
See docs/production.md section 2.
EOF

# --- 8. Quality and security gates -------------------------------------------
if [ "${SKIP_GATES:-0}" = "1" ]; then
  warn "SKIP_GATES=1: skipping make audit and make dp-test"
else
  log "running security and quality gates"
  make -C "$ROOT" audit
  make -C "$ROOT" dp-test
fi

# --- 9. Final posture (do NOT open the port yet) -----------------------------
cat <<'EOF'

============================================================================
Bootstrap prepared. The public port is NOT open. Before exposing it, complete
docs/production.md section 5 and docs/deployment.md:

  [ ] Migrate to the TPM secrets backend; destroy any on-disk master key.
  [ ] Enforce backend TLS verification; trust/pin the internal CA. No skip-verify.
  [ ] Retire the dev-only idp_verify_tls=false backchannel setting.
  [ ] Segment the network: the control-plane containers publish on 127.0.0.1
      only; guacd stays internal; only the baremetal data plane's public port and
      the WireGuard admin path face any network (docs/admin-access.md).
  [ ] Wire off-box logging: `docker compose run --rm cli ship-logs`, alert on
      severity:"high".
  [ ] Run the dedicated security review against docs/security-notes.md; resolve
      every dev-only accepted risk.

Then start everything with ./start-prod.sh, and only after review sign-off, open
the public port.
============================================================================
EOF
