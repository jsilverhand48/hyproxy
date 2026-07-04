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
prompt_yn ACME_DRYRUN "Dry-run against the Let's Encrypt STAGING CA first?" Y

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
  printf '  ACME staging DR: %s\n' "$ACME_DRYRUN"
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
STAGING_DOMAIN=$DOMAIN
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
  printf '# Generated by install.sh. Consumed by deploy/acme/obtain-cert.sh.\n'
  printf 'STAGING_DOMAIN=%s\n' "$DOMAIN"
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
c_info "rendering dataplane/config.json"
set -a; . "$INSTALL_DIR/.env"; set +a
"$INSTALL_DIR/deploy/render-dataplane-config.sh"

# --- 6. TLS certificate (Let's Encrypt via DNS-01) ---------------------------
if [ "$ACME_DRYRUN" = yes ]; then
  c_info "ACME dry-run against the Let's Encrypt STAGING CA"
  ACME_STAGING=1 "$INSTALL_DIR/deploy/acme/obtain-cert.sh" \
    || c_die "ACME staging dry-run failed; fix DNS/credentials in $ACME_ENV and re-run"
  # The staging and production certs share lego's certificates/ dir; clear the
  # staging artifact so the real run issues fresh instead of "renew (no-op)".
  rm -f "/etc/hyproxy/lego/certificates/_.$DOMAIN".*
fi
c_info "issuing the real Let's Encrypt wildcard cert"
"$INSTALL_DIR/deploy/acme/obtain-cert.sh" || c_die "ACME issuance failed (see output above)"

# --- 7. Data-plane user, SELinux, systemd units ------------------------------
c_info "creating the de-privileged data-plane user and installing units"
getent group hyproxy  >/dev/null 2>&1 || groupadd --system hyproxy
getent passwd hyproxy >/dev/null 2>&1 || useradd --system --gid hyproxy --shell /sbin/nologin hyproxy

if have getenforce && [ "$(getenforce)" != "Disabled" ]; then
  have semanage || dnf install -y policycoreutils-python-utils
  for f in "$INSTALL_DIR/dataplane/bin/dataplane" "$INSTALL_DIR/deploy/acme/obtain-cert.sh"; do
    semanage fcontext -a -t bin_t "$f" 2>/dev/null || semanage fcontext -m -t bin_t "$f"
    restorecon -v "$f"
  done
fi

sed "s#/opt/hyproxy#$INSTALL_DIR#g" \
  "$INSTALL_DIR/deploy/systemd/hyproxy-dataplane.service" > /etc/systemd/system/hyproxy-dataplane.service
sed "s#/opt/hyproxy#$INSTALL_DIR#g" \
  "$INSTALL_DIR/deploy/acme/hyproxy-acme.service" > /etc/systemd/system/hyproxy-acme.service
install -m 0644 "$INSTALL_DIR/deploy/acme/hyproxy-acme.timer" /etc/systemd/system/hyproxy-acme.timer
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
