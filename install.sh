#!/bin/sh
#
# install.sh: one-command production installer for hyproxy (Rocky Linux only).
#
# Usage (review first is recommended over piping straight to a shell):
#   curl -fsSL https://raw.githubusercontent.com/jsilverhand48/hyproxy/master/install.sh | sh
#   # safer:
#   curl -fsSL https://raw.githubusercontent.com/jsilverhand48/hyproxy/master/install.sh -o install.sh
#   less install.sh && sh install.sh
#
# It prompts (on the terminal, so it works under `curl | sh`) for the domain,
# admin identity, DNS-01 provider credentials, and a few options, then:
#   - clones the repo into $HYPROXY_INSTALL_DIR (default /opt/hyproxy),
#   - writes .env and a root-owned /etc/hyproxy/acme.env,
#   - runs bootstrap-prod.sh (installs deps, opens the firewall, builds images,
#     migrates, creates the first admin, builds the data-plane binary),
#   - issues the Let's Encrypt wildcard cert via lego DNS-01,
#   - installs and enables the systemd units (data plane + renewal timer),
#   - brings up the control plane and starts the data plane.
#
# It deliberately does NOT do: the TPM secrets backend (a code task), WireGuard
# admin access, your public DNS records, or the final security review. Those
# remain manual; see docs/production-checklist.md.
#
# Overridable via environment:
#   HYPROXY_REPO_URL, HYPROXY_REPO_BRANCH, HYPROXY_INSTALL_DIR, HYPROXY_RUN_GATES

set -eu

REPO_URL="${HYPROXY_REPO_URL:-https://github.com/jsilverhand48/hyproxy.git}"
REPO_BRANCH="${HYPROXY_REPO_BRANCH:-main}"
INSTALL_DIR="${HYPROXY_INSTALL_DIR:-/opt/hyproxy}"
ACME_ENV="/etc/hyproxy/acme.env"

c_info() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
c_warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
c_die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }

# Prompts read from the controlling terminal, not stdin, so this works when the
# script itself arrives on stdin via `curl | sh`.
TTY=/dev/tty
[ -r "$TTY" ] || c_die "no terminal for prompts; download and run directly: sh install.sh"

prompt() {  # prompt VAR "question" ["default"]
  _v="$1"; _q="$2"; _d="${3:-}"
  if [ -n "$_d" ]; then printf '%s [%s]: ' "$_q" "$_d" >"$TTY"; else printf '%s: ' "$_q" >"$TTY"; fi
  IFS= read -r _ans <"$TTY" || _ans=""
  [ -n "$_ans" ] || _ans="$_d"
  eval "$_v=\$_ans"
}

prompt_secret() {  # prompt_secret VAR "question"
  _v="$1"; _q="$2"
  printf '%s: ' "$_q" >"$TTY"
  stty -echo <"$TTY" 2>/dev/null || true
  IFS= read -r _ans <"$TTY" || _ans=""
  stty echo <"$TTY" 2>/dev/null || true
  printf '\n' >"$TTY"
  eval "$_v=\$_ans"
}

prompt_yn() {  # prompt_yn VAR "question" [Y|N]
  _v="$1"; _q="$2"; _d="${3:-N}"
  case "$_d" in [Yy]*) _h="Y/n" ;; *) _h="y/N" ;; esac
  printf '%s [%s]: ' "$_q" "$_h" >"$TTY"
  IFS= read -r _ans <"$TTY" || _ans=""
  [ -n "$_ans" ] || _ans="$_d"
  case "$_ans" in [Yy]*) eval "$_v=yes" ;; *) eval "$_v=no" ;; esac
}

genpass() {
  if have openssl; then openssl rand -base64 24 | tr -d '/+=' | cut -c1-32
  else head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# --- 0. Preflight ------------------------------------------------------------
c_info "hyproxy production installer"
[ "$(id -u)" -eq 0 ] || c_die "run as root (needs dnf, firewalld, systemd, /opt, /etc/hyproxy)"

ids="$(. /etc/os-release 2>/dev/null && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")"
case " $ids " in
  *" rocky "*|*" rhel "*) : ;;
  *) c_die "unsupported OS '$ids'; this installer supports Rocky Linux only" ;;
esac
have git  || dnf install -y git
have curl || dnf install -y curl

# --- 1. Gather configuration -------------------------------------------------
c_info "configuration (press Enter to accept a [default])"
prompt DOMAIN "Base domain (public, e.g. example.com)"
[ -n "$DOMAIN" ] || c_die "a base domain is required"
prompt ADMIN_EMAIL "Admin + ACME email" "admin@$DOMAIN"
prompt ADMIN_NAME  "Admin display name" "Admin"
prompt LEGO_DNS_PROVIDER "lego DNS-01 provider code (e.g. godaddy, cloudflare, route53)"
[ -n "$LEGO_DNS_PROVIDER" ] || c_die "a DNS provider is required for ACME DNS-01"

c_info "DNS provider API credentials"
printf 'Enter the credential lines lego needs for %s as VAR=VALUE (see\n' "$LEGO_DNS_PROVIDER" >"$TTY"
printf 'https://go-acme.github.io/lego/dns/%s ). One per line; empty line to finish.\n' "$LEGO_DNS_PROVIDER" >"$TTY"
PROVIDER_CREDS=""
while : ; do
  printf 'cred> ' >"$TTY"
  IFS= read -r _line <"$TTY" || _line=""
  [ -n "$_line" ] || break
  case "$_line" in
    *=*) PROVIDER_CREDS="${PROVIDER_CREDS}${_line}
" ;;
    *) c_warn "ignoring '$_line' (not VAR=VALUE)" ;;
  esac
done
[ -n "$PROVIDER_CREDS" ] || c_warn "no credentials entered; add them to $ACME_ENV before the cert can issue"

prompt_yn GENPW "Auto-generate a strong POSTGRES_PASSWORD?" Y
if [ "$GENPW" = yes ]; then POSTGRES_PASSWORD="$(genpass)"; else prompt_secret POSTGRES_PASSWORD "POSTGRES_PASSWORD"; fi
[ -n "$POSTGRES_PASSWORD" ] || c_die "POSTGRES_PASSWORD cannot be empty"

prompt_yn ENABLE_GUAC "Enable the Guacamole remote-desktop bridge?" N

ISSUER="https://idp.$DOMAIN"
ADMIN_ORIGIN="https://admin.$DOMAIN"

c_info "review"
{
  printf '  Install dir:     %s\n' "$INSTALL_DIR"
  printf '  Repo:            %s (%s)\n' "$REPO_URL" "$REPO_BRANCH"
  printf '  Domain:          %s\n' "$DOMAIN"
  printf '  Issuer:          %s\n' "$ISSUER"
  printf '  Admin origin:    %s\n' "$ADMIN_ORIGIN"
  printf '  Admin:           %s <%s>\n' "$ADMIN_NAME" "$ADMIN_EMAIL"
  printf '  DNS provider:    %s\n' "$LEGO_DNS_PROVIDER"
  printf '  Postgres pw:     (hidden)\n'
  printf '  Guac bridge:     %s\n' "$ENABLE_GUAC"
  printf '  Secrets backend: file (migrate to TPM later; docs/production-checklist.md)\n'
} >"$TTY"
prompt_yn GO "Proceed with installation?" Y
[ "$GO" = yes ] || c_die "aborted"

# --- 2. Clone or update the repo ---------------------------------------------
c_info "fetching the repository into $INSTALL_DIR"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" fetch --depth 1 origin "$REPO_BRANCH"
  git -C "$INSTALL_DIR" checkout -q "$REPO_BRANCH"
  git -C "$INSTALL_DIR" reset --hard "origin/$REPO_BRANCH"
else
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --branch "$REPO_BRANCH" --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# --- 3. Write config files ---------------------------------------------------
MASTER_KEY_FILE="$INSTALL_DIR/server/.dev/master.keys"
c_info "writing $INSTALL_DIR/.env"
umask 077
cat > "$INSTALL_DIR/.env" <<EOF
# Generated by install.sh on $(date -u +%FT%TZ). Production values.
HYPROXY_DOMAIN=$DOMAIN
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
HYPROXY_ISSUER=$ISSUER
HYPROXY_ADMIN_UI_ORIGIN=$ADMIN_ORIGIN
HYPROXY_SECRETS_BACKEND=file
HYPROXY_MASTER_KEY_FILE=$MASTER_KEY_FILE
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_NAME=$ADMIN_NAME
DP_TLS_CERT=/etc/hyproxy/certs/fullchain.pem
DP_TLS_KEY=/etc/hyproxy/certs/privkey.pem
DP_LISTEN=:443
DP_TLS_GROUP=hyproxy
EOF
chmod 600 "$INSTALL_DIR/.env"

c_info "writing $ACME_ENV (root-owned, 0600)"
install -d -m 0700 /etc/hyproxy
umask 077
{
  printf '# Generated by install.sh. Consumed by /usr/local/sbin/hyproxy-obtain-cert.sh.\n'
  printf 'HYPROXY_DOMAIN=%s\n' "$DOMAIN"
  printf 'ACME_EMAIL=%s\n' "$ADMIN_EMAIL"
  printf 'LEGO_DNS_PROVIDER=%s\n' "$LEGO_DNS_PROVIDER"
  printf 'DP_TLS_GROUP=hyproxy\n'
  printf '%s' "$PROVIDER_CREDS"
} > "$ACME_ENV"
chmod 600 "$ACME_ENV"

# --- 4. Bootstrap (deps, firewall, images, migrate, admin, binary) -----------
c_info "running bootstrap-prod.sh"
c_warn "SAVE the admin one-time password printed below; it is shown only once."
SKIP_GATES=1; [ "${HYPROXY_RUN_GATES:-0}" = "1" ] && SKIP_GATES=0
HYPROXY_ASSUME_YES=1 SKIP_GATES="$SKIP_GATES" \
  ADMIN_EMAIL="$ADMIN_EMAIL" ADMIN_NAME="$ADMIN_NAME" \
  bash "$INSTALL_DIR/bootstrap-prod.sh"

# Optional guac cipher key, minted now that images exist.
if [ "$ENABLE_GUAC" = yes ]; then
  c_info "minting a Guacamole cipher key"
  GKEY="$(docker compose run --rm cli gen-guac-key 2>/dev/null | tr -d '\r' | tail -n1)"
  if [ -n "$GKEY" ]; then printf 'HYPROXY_GUAC_CYPHER_KEY=%s\n' "$GKEY" >> "$INSTALL_DIR/.env"
  else c_warn "could not mint a guac key; set HYPROXY_GUAC_CYPHER_KEY in .env by hand"; fi
fi

# File secrets backend bridge: the container user (uid 10001) must read the
# mounted master key. TPM is the real fix (docs/production-checklist.md).
[ -f "$MASTER_KEY_FILE" ] && chmod 0644 "$MASTER_KEY_FILE"

# --- 5. Render the data-plane config -----------------------------------------
# The data plane is the single LAN TLS ingress. idp and admin are proxied with
# auth disabled (they authenticate independently); application routes are
# DB-driven and hot-loaded from the control plane, so only the infra routes are
# rendered here. Static routes win on host conflict.
c_info "rendering dataplane/config.json"
set -a; . "$INSTALL_DIR/.env"; set +a
DP_OUT="${DP_OUT:-$INSTALL_DIR/dataplane/config.json}"
IDP_BACKEND="${IDP_BACKEND:-http://127.0.0.1:8300}"
ADMIN_BACKEND="${ADMIN_BACKEND:-http://127.0.0.1:8400}"
AUTHZ_BACKEND="${AUTHZ_BACKEND:-http://127.0.0.1:8500}"
GUAC_BACKEND="${GUAC_BACKEND:-http://127.0.0.1:8600}"
ROUTES_REFRESH_SECS="${ROUTES_REFRESH_SECS:-10}"
case "${DP_UPSTREAM_INSECURE_SKIP_VERIFY:-false}" in
  true|1|yes) UPSTREAM_INSECURE=true ;;
  *) UPSTREAM_INSECURE=false ;;
esac
cat > "$DP_OUT" <<EOF
{
  "listen": "$DP_LISTEN",
  "tls_cert": "$DP_TLS_CERT",
  "tls_key": "$DP_TLS_KEY",
  "authz_url": "$AUTHZ_BACKEND",
  "auth_host": "auth.$HYPROXY_DOMAIN",
  "auth_backend": "$AUTHZ_BACKEND",
  "gateway_cookie_name": "__Secure-gw",
  "guac_backend": "$GUAC_BACKEND",
  "routes_refresh_secs": $ROUTES_REFRESH_SECS,
  "upstream_insecure_skip_verify": $UPSTREAM_INSECURE,
  "routes": {
    "idp.$HYPROXY_DOMAIN": { "backend": "$IDP_BACKEND", "auth": false },
    "admin.$HYPROXY_DOMAIN": { "backend": "$ADMIN_BACKEND", "auth": false }
  }
}
EOF
echo "wrote $DP_OUT (ingress $DP_LISTEN, hosts: idp/admin/auth.$HYPROXY_DOMAIN)"

# --- 6. TLS certificate (Let's Encrypt via DNS-01) ---------------------------
# The issue/renew script is embedded here and written to /usr/local/sbin so the
# daily systemd renewal timer has a stable path to execute, independent of the
# repo checkout.
CERT_SCRIPT=/usr/local/sbin/hyproxy-obtain-cert.sh
c_info "installing $CERT_SCRIPT"
cat > "$CERT_SCRIPT" <<'OBTAIN_CERT'
#!/usr/bin/env bash
#
# hyproxy-obtain-cert.sh: issue or renew the wildcard Let's Encrypt cert for the
# domain via ACME DNS-01 (lego) and install it where the data plane hot-reloads
# it (internal/tlsconf re-reads the files live, so no restart is needed).
#
# DNS-01 is used deliberately: it issues a browser-trusted cert for the LAN-only
# admin/idp hosts WITHOUT exposing anything to the internet (the challenge is a
# DNS TXT record). It also permits the wildcard.
#
# Usage:
#   hyproxy-obtain-cert.sh            # issue if missing, else renew (<30d)
#   hyproxy-obtain-cert.sh renew      # renew only
#
# Configuration (put secrets in an env file OUTSIDE the repo, default
# /etc/hyproxy/acme.env, and reference it via ACME_ENV_FILE):
#   HYPROXY_DOMAIN          base domain; cert covers *.<domain> and <domain>
#   ACME_EMAIL              registration/expiry-notice email
#   LEGO_DNS_PROVIDER       lego DNS provider code (e.g. cloudflare, route53)
#   <provider creds>        provider-specific env vars (e.g. CLOUDFLARE_DNS_API_TOKEN)
#   LEGO_PATH               lego state dir (default /etc/hyproxy/lego)
#   DP_TLS_CERT/DP_TLS_KEY  install targets (default /etc/hyproxy/certs/{fullchain,privkey}.pem)
#   ACME_STAGING=1          use the Let's Encrypt STAGING CA first (untrusted, for dry runs)

set -euo pipefail

ACME_ENV_FILE="${ACME_ENV_FILE:-/etc/hyproxy/acme.env}"
if [ -f "$ACME_ENV_FILE" ]; then
  set -a; . "$ACME_ENV_FILE"; set +a
fi

: "${HYPROXY_DOMAIN:?set HYPROXY_DOMAIN}"
: "${ACME_EMAIL:?set ACME_EMAIL}"
: "${LEGO_DNS_PROVIDER:?set LEGO_DNS_PROVIDER (lego provider code, e.g. cloudflare)}"
command -v lego >/dev/null || { echo "lego not found (install from https://go-acme.github.io/lego/)" >&2; exit 1; }

LEGO_PATH="${LEGO_PATH:-/etc/hyproxy/lego}"
DP_TLS_CERT="${DP_TLS_CERT:-/etc/hyproxy/certs/fullchain.pem}"
DP_TLS_KEY="${DP_TLS_KEY:-/etc/hyproxy/certs/privkey.pem}"

server_args=()
[ "${ACME_STAGING:-0}" = "1" ] && server_args=(--server https://acme-staging-v02.api.letsencrypt.org/directory)

common=(--accept-tos --email "$ACME_EMAIL" --dns "$LEGO_DNS_PROVIDER"
        --domains "*.$HYPROXY_DOMAIN" --domains "$HYPROXY_DOMAIN"
        --path "$LEGO_PATH" "${server_args[@]}")

mode="${1:-auto}"
# lego stores the wildcard cert under a sanitized name: *. -> _.
crt="$LEGO_PATH/certificates/_.$HYPROXY_DOMAIN.crt"
key="$LEGO_PATH/certificates/_.$HYPROXY_DOMAIN.key"

# lego v5 folds get + renew into a single `run` command, and all these flags are
# subcommand-scoped, so they must follow `run` (v4 accepted them before it).
if { [ "$mode" = "auto" ] && [ ! -f "$crt" ]; }; then
  echo "==> issuing wildcard cert for *.$HYPROXY_DOMAIN via DNS-01 ($LEGO_DNS_PROVIDER)"
  lego run "${common[@]}"
else
  echo "==> renewing (if within 30 days) *.$HYPROXY_DOMAIN"
  lego run "${common[@]}" --renew-days 30 || true
fi

[ -f "$crt" ] || { echo "expected issued cert at $crt not found" >&2; exit 1; }

# Install atomically into the data-plane paths; hot-reload picks them up live.
# DP_TLS_GROUP (optional): group granted read on the private key, so a
# de-privileged data-plane service user can read it (0640 instead of 0600).
install -d -m 0755 "$(dirname "$DP_TLS_CERT")"
install -m 0644 "$crt" "$DP_TLS_CERT.tmp" && mv -f "$DP_TLS_CERT.tmp" "$DP_TLS_CERT"
if [ -n "${DP_TLS_GROUP:-}" ]; then
  install -m 0640 -g "$DP_TLS_GROUP" "$key" "$DP_TLS_KEY.tmp"
else
  install -m 0600 "$key" "$DP_TLS_KEY.tmp"
fi
mv -f "$DP_TLS_KEY.tmp" "$DP_TLS_KEY"
echo "installed cert -> $DP_TLS_CERT, key -> $DP_TLS_KEY (data plane hot-reloads)"
OBTAIN_CERT
chmod 0755 "$CERT_SCRIPT"

c_info "issuing the real Let's Encrypt wildcard cert"
"$CERT_SCRIPT" || c_die "ACME issuance failed (see output above)"

# --- 7. Data-plane user, SELinux, systemd units ------------------------------
c_info "creating the de-privileged data-plane user and installing units"
getent group hyproxy  >/dev/null 2>&1 || groupadd --system hyproxy
getent passwd hyproxy >/dev/null 2>&1 || useradd --system --gid hyproxy --shell /sbin/nologin hyproxy

# The cert script needs no fcontext: /usr/local/sbin is bin_t by default.
if have getenforce && [ "$(getenforce)" != "Disabled" ]; then
  have semanage || dnf install -y policycoreutils-python-utils
  f="$INSTALL_DIR/dataplane/bin/dataplane"
  semanage fcontext -a -t bin_t "$f" 2>/dev/null || semanage fcontext -m -t bin_t "$f"
  restorecon -v "$f"
fi

# Supervise the baremetal Go data plane (the single LAN TLS ingress). The
# containers are managed by docker compose; this unit keeps the public edge
# restarting on failure.
cat > /etc/systemd/system/hyproxy-dataplane.service <<EOF
[Unit]
Description=hyproxy data plane (LAN TLS ingress)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
User=hyproxy
Group=hyproxy
WorkingDirectory=$INSTALL_DIR/dataplane
ExecStart=$INSTALL_DIR/dataplane/bin/dataplane -config config.json
Restart=on-failure
RestartSec=2
# Bind :443 without full root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/hyproxy/certs
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Issue/renew the wildcard cert via DNS-01 and install it into the data-plane
# cert paths. Oneshot, driven by hyproxy-acme.timer.
cat > /etc/systemd/system/hyproxy-acme.service <<EOF
[Unit]
Description=hyproxy ACME wildcard cert issuance/renewal (lego DNS-01)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$ACME_ENV
ExecStart=$CERT_SCRIPT
EOF

# Daily cert-renewal check (lego renews only when <30 days remain, so a daily
# run with jitter is safe and self-throttling).
cat > /etc/systemd/system/hyproxy-acme.timer <<'EOF'
[Unit]
Description=Daily hyproxy Let's Encrypt renewal check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

chmod 0644 /etc/systemd/system/hyproxy-dataplane.service \
           /etc/systemd/system/hyproxy-acme.service \
           /etc/systemd/system/hyproxy-acme.timer
systemctl daemon-reload

# --- 8. Start the stack ------------------------------------------------------
c_info "starting the control plane (containers)"
PROFILES="--profile app"
[ "$ENABLE_GUAC" = yes ] && PROFILES="$PROFILES --profile guac"
# shellcheck disable=SC2086
docker compose $PROFILES up -d --wait

c_info "enabling + starting the data plane and renewal timer"
systemctl enable --now hyproxy-dataplane
systemctl enable --now hyproxy-acme.timer

# --- 9. Summary --------------------------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
c_info "installation complete"
cat <<EOF

hyproxy is installed at $INSTALL_DIR and running.

  Public ingress : :443 (data plane, systemd 'hyproxy-dataplane')
  Control plane  : idp/admin/authz containers on 127.0.0.1
  Cert renewal   : hyproxy-acme.timer (daily)

NEXT STEPS (not automated):
  1. Public DNS: point idp.$DOMAIN, admin.$DOMAIN, auth.$DOMAIN (and each app
     host) at this server's public IP${IP:+ ($IP)}.
  2. First login at https://idp.$DOMAIN/auth/login as $ADMIN_EMAIL with the
     one-time password printed by bootstrap above; enroll two passkeys at
     /auth/enroll/webauthn.
  3. Work through docs/production-checklist.md before internet exposure:
     TPM secrets backend, WireGuard admin access, backend TLS verification,
     off-box logging, and the security review.

SECURITY NOTE: under the 'file' secrets backend the master key sits on disk
(readable by the container). This is a bridge; migrate to TPM before exposure.
EOF
