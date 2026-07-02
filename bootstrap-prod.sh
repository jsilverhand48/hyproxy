#!/usr/bin/env bash
#
# bootstrap-prod.sh: one-time preparation for the FIRST production run.
#
# This does the irreversible-ish, once-per-deployment setup and then STOPS
# short of opening the public port. It never self-signs certs and never relaxes
# a security invariant. After it finishes, follow docs/production.md section 5
# (final posture + security review) before exposing the single public port.
#
# It is deliberately fail-closed: missing production config aborts the run.
# Re-running is safe; steps that already completed are detected and skipped.
#
# Required environment (no dev defaults are assumed):
#   HYPROXY_DB_URL           production Postgres URL (asyncpg)
#   HYPROXY_ISSUER           public HTTPS issuer, e.g. https://idp.example.com
#   HYPROXY_ADMIN_UI_ORIGIN  admin origin the SPA is served from
#   ADMIN_EMAIL              email of the first (break-glass) admin to create
#   ADMIN_NAME               display name of that admin
#
# Secrets backend (pick one, per docs/production.md section 1):
#   HYPROXY_SECRETS_BACKEND=tpm  + HYPROXY_TPM_SEALED_BLOB=<path>   (recommended)
#   HYPROXY_SECRETS_BACKEND=file + HYPROXY_MASTER_KEY_FILE=<path>   (bridge only)
#
# Optional:
#   HYPROXY_GUAC_CYPHER_KEY  set (or let this script mint one) to enable guac
#   ADMIN_UI_REDIRECT        admin-ui OIDC redirect_uri (default: <origin>/callback)
#   SKIP_GATES=1             skip `make audit` + `make dp-test` (not recommended)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$ROOT/server"
DATAPLANE="$ROOT/dataplane"
UI="$ROOT/ui"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

require_var() {
  local name="$1"
  [ -n "${!name:-}" ] || die "required env var $name is not set (see the header of this script)"
}

# --- 0. Guardrails -----------------------------------------------------------
log "hyproxy production bootstrap"
echo "This prepares a first production run. It will touch the production"
echo "database and create the first admin. It will NOT open the public port."
read -r -p "Type 'bootstrap' to continue: " confirm
[ "$confirm" = "bootstrap" ] || die "aborted"

# --- 1. Preflight ------------------------------------------------------------
log "preflight: toolchain and required configuration"
command -v uv >/dev/null  || die "uv not found"
command -v go >/dev/null  || die "go toolchain not found (data plane build)"
command -v npm >/dev/null || die "npm not found (admin UI build)"

require_var HYPROXY_DB_URL
require_var HYPROXY_ISSUER
require_var HYPROXY_ADMIN_UI_ORIGIN
require_var ADMIN_EMAIL
require_var ADMIN_NAME

case "$HYPROXY_ISSUER" in
  https://*) : ;;
  *) die "HYPROXY_ISSUER must be https:// in production" ;;
esac
case "$HYPROXY_DB_URL" in
  *devonly*|*localhost*|*127.0.0.1*)
    die "HYPROXY_DB_URL looks like a dev database; refusing to bootstrap prod against it" ;;
esac

ADMIN_UI_REDIRECT="${ADMIN_UI_REDIRECT:-${HYPROXY_ADMIN_UI_ORIGIN%/}/callback}"

# The Python services read configuration from server/.env at runtime. Persist
# the exported production settings there so the bootstrap and the eventual
# service start agree.
ENV_FILE="$SERVER/.env"
if [ ! -f "$ENV_FILE" ]; then
  die "server/.env not found. Create it from .env.example with production values first."
fi
grep -q 'devonly' "$ENV_FILE" && warn "server/.env still contains dev placeholders; review it before starting services"

# --- 2. Python dependencies (locked) -----------------------------------------
log "installing pinned Python dependencies"
( cd "$SERVER" && uv sync --frozen )

# --- 3. Secrets backend ------------------------------------------------------
BACKEND="${HYPROXY_SECRETS_BACKEND:-file}"
log "secrets backend: $BACKEND"
case "$BACKEND" in
  tpm)
    require_var HYPROXY_TPM_SEALED_BLOB
    [ -f "$HYPROXY_TPM_SEALED_BLOB" ] || die "HYPROXY_TPM_SEALED_BLOB=$HYPROXY_TPM_SEALED_BLOB does not exist. Seal a master key to the TPM first (docs/production.md section 1)."
    command -v tpm2_unseal >/dev/null || warn "tpm2-tools not on PATH; ensure core/secrets.tpm_unseal is wired to your unseal command"
    ;;
  file)
    warn "file backend keeps unsealed master-key material on disk. docs/production.md"
    warn "requires migrating to the TPM backend before the port faces the internet."
    require_var HYPROXY_MASTER_KEY_FILE
    if [ -f "$HYPROXY_MASTER_KEY_FILE" ]; then
      log "master key file present, keeping it"
    else
      log "generating a master key file"
      ( cd "$SERVER" && uv run python -m hyproxy.cli gen-keys )
    fi
    ;;
  *) die "unknown HYPROXY_SECRETS_BACKEND=$BACKEND (expected 'tpm' or 'file')" ;;
esac

# --- 4. Database schema ------------------------------------------------------
log "applying migrations to the production database"
( cd "$SERVER" && uv run alembic upgrade head )

log "ensuring signing keys exist (published in JWKS)"
( cd "$SERVER" && uv run python -m hyproxy.cli bootstrap-keys )

# --- 5. First admin ----------------------------------------------------------
# bootstrap-admin is idempotent on email in the CLI; if not, a duplicate simply
# errors and we continue (the admin already exists).
log "creating the first admin: $ADMIN_EMAIL"
( cd "$SERVER" && uv run python -m hyproxy.cli bootstrap-admin \
    --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" ) \
  || warn "bootstrap-admin reported an error (admin may already exist); continuing"

# --- 6. OIDC clients ---------------------------------------------------------
log "registering the admin-ui OIDC public client"
( cd "$SERVER" && uv run python -m hyproxy.cli create-client \
    --client-id admin-ui --name "Admin UI" --redirect-uri "$ADMIN_UI_REDIRECT" ) \
  || warn "admin-ui client already registered; continuing"

echo
echo "Register your resource relying parties (gateway clients) with:"
echo "  ( cd server && uv run python -m hyproxy.cli create-client --client-id <id> --name <name> --redirect-uri <uri> )"

# --- 7. Guacamole key (optional) ---------------------------------------------
if [ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ]; then
  log "guac enabled: HYPROXY_GUAC_CYPHER_KEY provided"
  echo "Give the SAME value to the tunnel service as GUAC_CYPHER_KEY."
else
  log "guac cypher key not set; guac bridges disabled"
  echo "To enable later: ( cd server && uv run python -m hyproxy.cli gen-guac-key )"
  echo "then set HYPROXY_GUAC_CYPHER_KEY on the control plane and GUAC_CYPHER_KEY on the tunnel."
fi

# --- 8. Admin UI build -------------------------------------------------------
log "building the admin UI against $HYPROXY_ADMIN_UI_ORIGIN"
( cd "$UI" && npm ci && npm run build )

# --- 9. Data plane build -----------------------------------------------------
log "building the Go data plane binary"
make -C "$ROOT" dp-build

# --- 10. TLS certificates (no self-sign in prod) -----------------------------
log "TLS certificates"
DP_CONFIG="$DATAPLANE/config.json"
if [ -f "$DP_CONFIG" ]; then
  echo "Data plane config: $DP_CONFIG (ensure tls_cert / tls_key point at ACME output)."
else
  warn "no dataplane/config.json found. Copy config.example.json and set production"
  warn "routes, authz_url, auth_host, and tls_cert / tls_key paths."
fi
cat <<'EOF'
Obtain real certificates with a VETTED ACME client (do not hand-roll crypto):
  - lego or certbot with a DNS-01 plugin for your DNS provider (works behind CGNAT,
    supports wildcards). Use the ACME staging directory first, then production.
  - Point its output at the data plane's tls_cert / tls_key paths; the TLS
    hot-reload seam (internal/tlsconf) picks up new files with no restart.
  - Store DNS provider credentials sealed or in the client's protected store.
  - Schedule renewal (renew < 30 days to expiry) and alert on failure.
See docs/production.md section 2.
EOF

# --- 11. Quality and security gates ------------------------------------------
if [ "${SKIP_GATES:-0}" = "1" ]; then
  warn "SKIP_GATES=1: skipping make audit and make dp-test"
else
  log "running security and quality gates"
  make -C "$ROOT" audit
  make -C "$ROOT" dp-test
fi

# --- 12. Final posture (do NOT open the port yet) ----------------------------
cat <<'EOF'

============================================================================
Bootstrap prepared. The public port is NOT open. Before exposing it, complete
docs/production.md section 5:

  [ ] Migrate to the TPM secrets backend; destroy any on-disk master key.
  [ ] Enforce backend TLS verification; trust/pin the internal CA. No skip-verify.
  [ ] Retire the dev-only idp_verify_tls=false backchannel setting.
  [ ] Segment the network: admin API, /authz/check, /guac/consume, the guac
      tunnel, and guacd stay internal. Only the single public port and the
      out-of-band WireGuard admin path face any network (docs/admin-access.md).
  [ ] Wire off-box logging: cron `ship-logs`, alert on severity:"high".
  [ ] Run the dedicated security review against docs/security-notes.md; resolve
      every dev-only accepted risk. Close findings.

Then start the services (behind your process manager / systemd units), and only
after review sign-off, open the public port.
============================================================================
EOF
