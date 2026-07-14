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
# Supported OS: Rocky Linux only (uses dnf + firewalld). When the toolchain is
# missing it installs Docker, the Go toolchain, make, uv, and lego, and opens
# the public data-plane port in firewalld. It still does NOT start the public
# ingress (that is ./start-prod.sh).
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

# --- Host provisioning helpers (Rocky Linux) ---------------------------------
# This RP currently supports Rocky Linux only, so dependency install and port
# opening use dnf and firewalld directly. Everything below is idempotent: it
# checks first and only acts on what is missing.
have() { command -v "$1" >/dev/null 2>&1; }
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
dnf_install() { log "dnf install: $*"; $SUDO dnf install -y "$@"; }

require_rocky() {
  local ids; ids="$(. /etc/os-release 2>/dev/null && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")"
  case " $ids " in
    *" rocky "*|*" rhel "*) : ;;
    *) die "unsupported OS '$(printf '%s' "$ids" | tr -s ' ')'; this bootstrap supports Rocky Linux only" ;;
  esac
}

ensure_base() { have curl || dnf_install curl; have tar || dnf_install tar; }
ensure_go()   { have go   || dnf_install golang; }
ensure_make() { have make || dnf_install make; }

ensure_docker() {
  if ! have docker; then
    log "installing Docker CE (dnf, Docker upstream repo)"
    dnf_install dnf-plugins-core
    $SUDO dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  $SUDO systemctl enable --now docker
  docker compose version >/dev/null 2>&1 || dnf_install docker-compose-plugin
  docker info >/dev/null 2>&1 || die "Docker installed but the daemon is unreachable (see 'systemctl status docker')"
}

ensure_uv() {
  if have uv; then return 0; fi
  log "installing uv (astral standalone installer -> /usr/local/bin)"
  curl -LsSf https://astral.sh/uv/install.sh \
    | $SUDO env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
}

ensure_lego() {
  if have lego; then return 0; fi
  log "installing lego ACME client (latest GitHub release -> /usr/local/bin)"
  local arch ver url tmp
  case "$(uname -m)" in
    x86_64)  arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m) for the lego binary" ;;
  esac
  ver="$(curl -fsSL https://api.github.com/repos/go-acme/lego/releases/latest \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$ver" ] || die "could not determine the latest lego release"
  url="https://github.com/go-acme/lego/releases/download/${ver}/lego_${ver}_linux_${arch}.tar.gz"
  tmp="$(mktemp -d)"
  curl -fsSL "$url" -o "$tmp/lego.tar.gz"
  tar -C "$tmp" -xzf "$tmp/lego.tar.gz" lego
  $SUDO install -m 0755 "$tmp/lego" /usr/local/bin/lego
  rm -rf "$tmp"
}

# Open the public data-plane port in firewalld. The control-plane ports
# (8300/8400/8500) are published on 127.0.0.1 only and are deliberately NOT
# opened. The port is taken from DP_LISTEN, else dataplane/config.json, else 443.
ensure_public_port_open() {
  local listen port already
  listen="${DP_LISTEN:-}"
  if [ -z "$listen" ] && [ -f "$ROOT/dataplane/config.json" ]; then
    listen="$(sed -nE 's/.*"listen"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$ROOT/dataplane/config.json" | head -n1)"
  fi
  listen="${listen:-:443}"
  port="${listen##*:}"
  case "$port" in ''|*[!0-9]*) warn "could not parse a public port from '$listen'; skipping firewall"; return 0 ;; esac

  if ! have firewall-cmd; then
    warn "firewalld not present; ensure $port/tcp is open in your firewall"
    return 0
  fi
  $SUDO systemctl enable --now firewalld >/dev/null 2>&1 || true
  if ! $SUDO firewall-cmd --state >/dev/null 2>&1; then
    warn "firewalld installed but not running; not opening $port/tcp"
    return 0
  fi
  already=1
  $SUDO firewall-cmd --query-port="$port/tcp" >/dev/null 2>&1 || already=0
  if [ "$already" -eq 0 ] && [ "$port" = 443 ]; then
    $SUDO firewall-cmd --query-service=https >/dev/null 2>&1 && already=1
  fi
  if [ "$already" -eq 1 ]; then
    log "firewall: $port/tcp already open"
  else
    log "firewall: opening $port/tcp (public data-plane ingress)"
    $SUDO firewall-cmd --permanent --add-port="$port/tcp" >/dev/null
    $SUDO firewall-cmd --reload >/dev/null
  fi
}

# --- 0. Guardrails -----------------------------------------------------------
log "hyproxy production bootstrap (hybrid: containers + baremetal data plane)"
echo "This prepares a first production run: it installs missing dependencies,"
echo "builds images, touches the production database, creates the first admin,"
echo "and opens the public port in the host firewall. It does NOT start the"
echo "public ingress (that is ./start-prod.sh)."
if [ "${HYPROXY_ASSUME_YES:-0}" = "1" ]; then
  echo "HYPROXY_ASSUME_YES=1: proceeding without the interactive confirmation"
else
  read -r -p "Type 'bootstrap' to continue: " confirm
  [ "$confirm" = "bootstrap" ] || die "aborted"
fi

# --- 1. Preflight: OS + toolchain (install anything missing) -----------------
require_rocky
log "preflight: toolchain (Rocky Linux; installing anything missing)"
ensure_base
ensure_docker
ensure_go
ensure_make
ensure_uv
ensure_lego

[ -f "$ENV_FILE" ] || die "repo-root .env not found. Copy .env.example to .env and set production values."
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

log "preflight: required configuration"
require_var HYPROXY_ISSUER
require_var HYPROXY_ADMIN_UI_ORIGIN
require_var ADMIN_EMAIL
require_var ADMIN_NAME
case "$HYPROXY_ISSUER" in https://*) : ;; *) die "HYPROXY_ISSUER must be https:// in production" ;; esac
[ "${POSTGRES_PASSWORD:-devonly}" = "devonly" ] && warn "POSTGRES_PASSWORD is the dev default; set a real one in .env before real use"
ADMIN_UI_REDIRECT="${ADMIN_UI_REDIRECT:-${HYPROXY_ADMIN_UI_ORIGIN%/}/callback}"

# --- 1b. Host firewall (open the public data-plane port) ---------------------
# The ingress is not started here, but the firewall is prepared so start-prod.sh
# can serve without a separate manual step.
log "preflight: host firewall"
ensure_public_port_open

# --- 2. Secrets backend ------------------------------------------------------
BACKEND="${HYPROXY_SECRETS_BACKEND:-file}"
log "secrets backend: $BACKEND"
case "$BACKEND" in
  tpm)
    log "TPM backend: $HYPROXY_TPM_DEVICE is passed into the control plane via docker-compose.yml"
    [ -e "$HYPROXY_TPM_DEVICE" ] || die "HYPROXY_SECRETS_BACKEND=tpm but $HYPROXY_TPM_DEVICE is missing"
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

log "creating the first admin (or resetting its temporary password): $ADMIN_EMAIL"
"${COMPOSE[@]}" run --rm cli bootstrap-admin --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" \
  || warn "bootstrap-admin reported an error; continuing"

log "registering the admin-ui OIDC public client"
"${COMPOSE[@]}" run --rm cli create-client \
    --client-id admin-ui --name "Admin UI" --redirect-uri "$ADMIN_UI_REDIRECT" \
  || warn "admin-ui client already registered; continuing"

log "registering the data plane forward-auth (gateway) OIDC client"
"${COMPOSE[@]}" run --rm cli bootstrap-gateway-client \
  || die "failed to register the gateway client; protected resources will 400 at /oidc/authorize"

echo
echo "Register additional OIDC relying parties (extra apps) with:"
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
Bootstrap prepared. The host firewall now permits the public port, but the
ingress is NOT running. Before starting it, complete docs/production.md
section 5 and docs/deployment.md:

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

Then, only after review sign-off, start everything with ./start-prod.sh.
============================================================================
EOF
