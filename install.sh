#!/bin/sh
#
# install.sh: one-command installer for hyproxy (Rocky Linux only).
#
# Usage (review first is recommended over piping straight to a shell):
#   curl -fsSL https://raw.githubusercontent.com/jsilverhand48/hyproxy/master/install.sh | sh
#   # safer:
#   curl -fsSL https://raw.githubusercontent.com/jsilverhand48/hyproxy/master/install.sh -o install.sh
#   less install.sh && sh install.sh
#
# Hybrid model: the control plane runs in containers; the Go data plane runs
# on baremetal. This single script takes a host from bare Rocky Linux to a
# running stack. It is fail-closed and idempotent where possible; re-running
# is safe.
#
# If a complete .env already exists ($HYPROXY_INSTALL_DIR/.env from a previous
# run, or a .env in the directory the installer is launched from), it is reused
# verbatim and no prompts are shown. Otherwise it prompts (on the terminal, so
# it works under `curl | sh`) for the domain, admin identity, DNS-01 provider
# credentials, and a few options. Either way it then:
#   - clones the repo into $HYPROXY_INSTALL_DIR (default /opt/hyproxy),
#   - creates the 'hyproxy' service account that owns and runs the stack,
#   - generates the master key and seals it into the TPM 2.0 under a PCR
#     policy; the plaintext is printed EXACTLY ONCE so it can be copied to a
#     FIPS backup device, and never touches disk,
#   - writes a single service-account-owned .env (0600) with everything the
#     stack needs, including the ACME DNS-01 provider credentials,
#   - installs the missing host toolchain (Docker CE, Go, make, uv, lego),
#   - opens the public data-plane port in firewalld (the control-plane ports
#     are published on 127.0.0.1 only and deliberately stay closed),
#   - builds the container images (the server image compiles the React UI in
#     a stage and bakes it in; the tunnel image bundles guacamole-lite),
#   - applies migrations and identity setup inside containers: signing keys,
#     the first (break-glass) admin, and the OIDC clients; on a re-run the
#     break-glass admin gets a FRESH one-time temporary password,
#   - builds the baremetal Go data-plane binary on the host (and runs the
#     quality gates when HYPROXY_RUN_GATES=1),
#   - renders dataplane/config.json (infra routes only; app routes are
#     DB-driven and hot-loaded),
#   - issues the Let's Encrypt wildcard cert via lego DNS-01 (no propagation
#     wait: lego is pointed at the domain's authoritative nameservers, so the
#     self-check passes as soon as the provider API writes the record),
#   - installs and enables the systemd units: the 'hyproxy' stack unit
#     (control-plane containers + baremetal data plane via start.sh/stop.sh),
#     the daily cert-renewal timer, and the audit-log-shipping timer,
#   - enables BBR congestion control (WAN streaming throughput),
#   - starts the control-plane containers, re-wraps stored secrets whenever a
#     new master key was sealed, and starts the stack unit.
#
# A TPM 2.0 (/dev/tpmrm0) is REQUIRED: the master key exists only sealed in
# the TPM (and on the FIPS backup device it is copied to during the one-time
# printout). There is no on-disk key and no alternative secrets backend.
#
# An existing sealed blob is kept only after it VERIFIABLY unseals to
# master-key material under the PCR policy. On a fresh image the configured
# handle may hold a foreign object from a different setup; that object is left
# untouched and the new key is sealed to the next free persistent handle,
# which is recorded in .env (HYPROXY_TPM_SEALED_BLOB). A sealed object that
# no longer unseals (PCR drift) fails closed: restore the key from the FIPS
# backup and reseal it under the current PCR values, or set
# HYPROXY_TPM_FORCE_RESEAL=1 to discard it and seal a brand-new key.
#
# It deliberately does NOT do: WireGuard admin access, your public DNS records,
# or the final security review. Those remain manual; see the NEXT STEPS
# printed at the end of the run.
#
# Overridable via environment:
#   HYPROXY_REPO_URL, HYPROXY_REPO_BRANCH, HYPROXY_INSTALL_DIR, HYPROXY_RUN_GATES,
#   HYPROXY_TPM_FORCE_RESEAL

set -eu

: "${HYPROXY_REPO_URL:=https://github.com/jsilverhand48/hyproxy.git}"
: "${HYPROXY_REPO_BRANCH:=master}"
: "${HYPROXY_INSTALL_DIR:=/opt/hyproxy}"
LAUNCH_DIR="$(pwd)"

c_info() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
c_warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
c_die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }

# Prompts read from the controlling terminal, not stdin, so this works when the
# script itself arrives on stdin via `curl | sh`. A missing terminal is fatal
# only if prompting turns out to be needed (a complete .env avoids it).
TTY=/dev/tty
HAVE_TTY=yes
[ -r "$TTY" ] || { HAVE_TTY=no; TTY=/dev/null; }

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

dnf_install() { c_info "dnf install: $*"; dnf install -y "$@"; }

# The stack's compose file lives in the install dir; everything below the
# clone step runs from there, but the explicit -f keeps it unambiguous.
compose() { docker compose -f "$HYPROXY_INSTALL_DIR/docker-compose.yml" "$@"; }

# --- 0. Preflight ------------------------------------------------------------
c_info "hyproxy installer"
[ "$(id -u)" -eq 0 ] || c_die "run as root (needs dnf, firewalld, systemd, /opt, /etc/hyproxy)"

ids="$(. /etc/os-release 2>/dev/null && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")"
case " $ids " in
  *" rocky "*|*" rhel "*) : ;;
  *) c_die "unsupported OS '$ids'; this installer supports Rocky Linux only" ;;
esac
have git  || dnf_install git
have curl || dnf_install curl
have tar  || dnf_install tar
have openssl || dnf_install openssl
have dig  || dnf_install bind-utils  # cert script pins lego to the authoritative NS

# TPM 2.0 is mandatory: the master key is sealed to hardware, never kept on disk.
[ -e /dev/tpmrm0 ] || c_die "no TPM 2.0 resource manager at /dev/tpmrm0; a TPM 2.0 is required"
have tpm2_unseal || dnf_install tpm2-tools
tpm2_pcrread sha256:0 >/dev/null 2>&1 || c_die "TPM present but tpm2_pcrread failed (check /dev/tpmrm0)"

# --- 1. Gather configuration -------------------------------------------------
# A complete pre-existing .env (previous run in $HYPROXY_INSTALL_DIR, or one prepared
# in the launch directory) is reused verbatim and skips every prompt.
REQUIRED_VARS="HYPROXY_DOMAIN POSTGRES_PASSWORD ADMIN_EMAIL ADMIN_NAME ACME_EMAIL LEGO_DNS_PROVIDER"

env_missing() (  # env_missing FILE: print the required vars FILE does not set
  set +eu  # sourcing must not kill the check (unset $refs in cred values)
  set -a; . "$1" 2>/dev/null || { printf ' (unreadable)'; exit 0; }; set +a
  _miss=""
  for _f in $REQUIRED_VARS; do
    eval "_val=\${$_f:-}"
    [ -n "$_val" ] || _miss="$_miss $_f"
  done
  printf '%s' "$_miss"
)

REUSE_ENV=no
ENV_SRC=""
for _cand in "$HYPROXY_INSTALL_DIR/.env" "$LAUNCH_DIR/.env"; do
  [ "$_cand" = "$LAUNCH_DIR/.env" ] && [ "$LAUNCH_DIR" = "$HYPROXY_INSTALL_DIR" ] && continue
  [ -f "$_cand" ] || continue
  # A syntax error in the candidate aborts the subshell; treat as unusable.
  _miss="$(env_missing "$_cand")" || _miss=" (unparseable)"
  if [ -z "$_miss" ]; then REUSE_ENV=yes; ENV_SRC="$_cand"; break
  else c_warn "$_cand exists but is missing:$_miss (ignoring it)"; fi
done

if [ "$REUSE_ENV" = yes ]; then
  c_info "reusing configuration from $ENV_SRC (skipping all prompts)"
  set -a; . "$ENV_SRC"; set +a
  : "${HYPROXY_ISSUER:=https://idp.$HYPROXY_DOMAIN}"
  : "${HYPROXY_ADMIN_UI_ORIGIN:=https://admin.$HYPROXY_DOMAIN}"
  : "${HYPROXY_APPS_UI_ORIGIN:=https://apps.$HYPROXY_DOMAIN}"
  case "${HYPROXY_ENABLE_GUAC:-no}" in [Yy]*|1|true) HYPROXY_ENABLE_GUAC=yes ;; *) HYPROXY_ENABLE_GUAC=no ;; esac
  PROVIDER_CREDS=""
  printf '  Domain:       %s\n' "$HYPROXY_DOMAIN"
  printf '  Admin:        %s <%s>\n' "$ADMIN_NAME" "$ADMIN_EMAIL"
  printf '  DNS provider: %s\n' "$LEGO_DNS_PROVIDER"
  printf '  Guac bridge:  %s\n' "$HYPROXY_ENABLE_GUAC"
else

[ "$HAVE_TTY" = yes ] || c_die "no terminal for prompts and no complete .env found (checked $HYPROXY_INSTALL_DIR/.env and $LAUNCH_DIR/.env)"
c_info "configuration (press Enter to accept a [default])"
prompt HYPROXY_DOMAIN "Base domain (public, e.g. example.com)"
[ -n "$HYPROXY_DOMAIN" ] || c_die "a base domain is required"
: "${HYPROXY_ISSUER:=https://idp.$HYPROXY_DOMAIN}"
: "${HYPROXY_ADMIN_UI_ORIGIN:=https://admin.$HYPROXY_DOMAIN}"
: "${HYPROXY_APPS_UI_ORIGIN:=https://apps.$HYPROXY_DOMAIN}"
prompt ADMIN_EMAIL "Admin + ACME email" "admin@$HYPROXY_DOMAIN"
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
[ -n "$PROVIDER_CREDS" ] || c_warn "no credentials entered; add them to $HYPROXY_INSTALL_DIR/.env before the cert can issue"

prompt_yn GENPW "Auto-generate a strong POSTGRES_PASSWORD?" Y
if [ "$GENPW" = yes ]; then POSTGRES_PASSWORD="$(genpass)"; else prompt_secret POSTGRES_PASSWORD "POSTGRES_PASSWORD"; fi
[ -n "$POSTGRES_PASSWORD" ] || c_die "POSTGRES_PASSWORD cannot be empty"

prompt_yn HYPROXY_ENABLE_GUAC "Enable the Guacamole remote-desktop bridge?" N


c_info "review"
{
  printf '  Install dir:     %s\n' "$HYPROXY_INSTALL_DIR"
  printf '  Repo:            %s (%s)\n' "$HYPROXY_REPO_URL" "$HYPROXY_REPO_BRANCH"
  printf '  Domain:          %s\n' "$HYPROXY_DOMAIN"
  printf '  Issuer:          %s\n' "$HYPROXY_ISSUER"
  printf '  Admin origin:    %s\n' "$HYPROXY_ADMIN_UI_ORIGIN"
  printf '  Apps origin:     %s\n' "$HYPROXY_APPS_UI_ORIGIN"
  printf '  Admin:           %s <%s>\n' "$ADMIN_NAME" "$ADMIN_EMAIL"
  printf '  DNS provider:    %s\n' "$LEGO_DNS_PROVIDER"
  printf '  Service user:    hyproxy (system account, nologin)\n'
  printf '  Postgres pw:     (hidden)\n'
  printf '  Guac bridge:     %s\n' "$HYPROXY_ENABLE_GUAC"
  printf '  Secrets backend: tpm (key sealed to TPM 2.0; plaintext shown ONCE for FIPS backup)\n'
} >"$TTY"
prompt_yn GO "Proceed with installation?" Y
[ "$GO" = yes ] || c_die "aborted"

fi  # REUSE_ENV

# --- 2. Clone or update the repo ---------------------------------------------
c_info "fetching the repository into $HYPROXY_INSTALL_DIR"
if [ -d "$HYPROXY_INSTALL_DIR/.git" ]; then
  git -C "$HYPROXY_INSTALL_DIR" fetch --depth 1 origin "$HYPROXY_REPO_BRANCH"
  git -C "$HYPROXY_INSTALL_DIR" checkout -q "$HYPROXY_REPO_BRANCH"
  git -C "$HYPROXY_INSTALL_DIR" reset --hard "origin/$HYPROXY_REPO_BRANCH"
else
  mkdir -p "$(dirname "$HYPROXY_INSTALL_DIR")"
  git clone --branch "$HYPROXY_REPO_BRANCH" --depth 1 "$HYPROXY_REPO_URL" "$HYPROXY_INSTALL_DIR"
fi
cd "$HYPROXY_INSTALL_DIR"

# --- 3. Service account --------------------------------------------------------
# The whole stack (compose containers, the data plane, cert renewal) runs as
# this de-privileged system account, never as root.
c_info "creating the 'hyproxy' service account (owns and runs the stack)"
getent group hyproxy  >/dev/null 2>&1 || groupadd --system hyproxy
getent passwd hyproxy >/dev/null 2>&1 || \
  useradd --system --gid hyproxy --home-dir "$HYPROXY_INSTALL_DIR" --no-create-home \
          --shell /sbin/nologin hyproxy
chown -R hyproxy:hyproxy "$HYPROXY_INSTALL_DIR"

# --- 4. Master key: generate, seal into the TPM, print once -------------------
# The master key lives ONLY inside the TPM (sealed under a PCR policy) and on
# the FIPS backup device it is copied to when printed below. No plaintext on
# disk, ever: the sealing scratch space is tmpfs and shredded.
umask 077
: "${HYPROXY_TPM_SEALED_BLOB:=0x81010001}"
: "${HYPROXY_TPM_PCRS:=sha256:0,2,4,7}"
TSS_GID="$(getent group tss | cut -d: -f3)"
[ -n "$TSS_GID" ] || c_die "host group 'tss' not found (tpm2-tools should have provided it)"

# An existing blob is trusted only after a full unseal round-trip: the handle
# must unseal under the PCR policy AND yield master-key lines. tpm2_readpublic
# alone is not enough: a fresh image can carry a foreign object (another
# application's key, or a blob from a different setup) at the configured
# handle, and treating it as ours leaves the stack with no usable secret.
blob_unseals() {  # blob_unseals HANDLE: payload parses as master-key lines
  tpm2_unseal -c "$1" -p "pcr:$HYPROXY_TPM_PCRS" 2>/dev/null \
    | grep -q '^mk-[0-9]'
}

# master_key_fp_of: read master-key lines on stdin, print the fingerprint of the
# CURRENT (last) key: first 16 hex of sha256 over the raw 32-byte key. MUST match
# core/secrets.py:master_key_fingerprint so the app's startup guard agrees. This
# non-secret value is recorded in .env (HYPROXY_MASTER_KEY_FP); the raw key is
# only ever piped in-memory here, never written.
master_key_fp_of() {
  grep -v '^[[:space:]]*#' | grep . | tail -n1 | cut -d: -f2- \
    | openssl base64 -d -A | openssl dgst -sha256 -r | cut -c1-16
}

handle_in_use() { tpm2_readpublic -c "$1" >/dev/null 2>&1; }

find_free_handle() {  # first unoccupied persistent handle at/after the configured one
  _used=" $(tpm2_getcap handles-persistent 2>/dev/null | sed -n 's/^-[[:space:]]*//p' | tr '\n' ' ') "
  _h=$(printf '%d' "$HYPROXY_TPM_SEALED_BLOB")
  _end=$((_h + 32))
  while [ "$_h" -le "$_end" ]; do
    _cand="$(printf '0x%08x' "$_h")"
    case "$_used" in
      *" $_cand "*) _h=$((_h + 1)) ;;
      *) printf '%s' "$_cand"; return 0 ;;
    esac
  done
  return 1
}

NEW_KEY_SEALED=no
if [ "$REUSE_ENV" = yes ] && blob_unseals "$HYPROXY_TPM_SEALED_BLOB"; then
  c_info "master key already sealed in the TPM at $HYPROXY_TPM_SEALED_BLOB (unseal verified; keeping it)"
  # Record the kept key's fingerprint so .env pins the key the database is
  # already encrypted under (idempotent: same blob -> same fingerprint).
  MASTER_KEY_FP="$(tpm2_unseal -c "$HYPROXY_TPM_SEALED_BLOB" -p "pcr:$HYPROXY_TPM_PCRS" | master_key_fp_of)"
else
  NEW_KEY_SEALED=yes
  # A new key is about to be sealed. If the configured handle is occupied by
  # an object that is not a usable hyproxy blob, never destroy it:
  #   - a keyedhash that no longer unseals may be an older hyproxy master key
  #     whose PCR state drifted -> fail closed, unless
  #     HYPROXY_TPM_FORCE_RESEAL=1 explicitly discards it;
  #   - anything else is a foreign object from a different setup -> leave it
  #     intact and seal to the next free handle instead (recorded in .env).
  if handle_in_use "$HYPROXY_TPM_SEALED_BLOB" && ! blob_unseals "$HYPROXY_TPM_SEALED_BLOB"; then
    if [ "${HYPROXY_TPM_FORCE_RESEAL:-0}" = 1 ]; then
      c_warn "HYPROXY_TPM_FORCE_RESEAL=1: discarding the object at $HYPROXY_TPM_SEALED_BLOB"
      tpm2_evictcontrol -C o -c "$HYPROXY_TPM_SEALED_BLOB" >/dev/null
    elif tpm2_readpublic -c "$HYPROXY_TPM_SEALED_BLOB" 2>/dev/null | grep -q keyedhash; then
      c_die "handle $HYPROXY_TPM_SEALED_BLOB holds a sealed object that does not unseal under pcr:$HYPROXY_TPM_PCRS.
       If it is an earlier hyproxy master key, the PCR state has drifted: restore the
       key from the FIPS backup and reseal it under the current PCR values. To discard
       it and seal a NEW key (any data sealed under it becomes unrecoverable), re-run
       with HYPROXY_TPM_FORCE_RESEAL=1."
    else
      c_warn "handle $HYPROXY_TPM_SEALED_BLOB holds a foreign (non-hyproxy) object; leaving it untouched"
      HYPROXY_TPM_SEALED_BLOB="$(find_free_handle)" \
        || c_die "no free persistent handle found near the configured one"
      c_info "using free persistent handle $HYPROXY_TPM_SEALED_BLOB instead (will be recorded in .env)"
    fi
  fi
  c_info "sealing the master key into the TPM (handle $HYPROXY_TPM_SEALED_BLOB, policy $HYPROXY_TPM_PCRS)"
  SEAL_DIR="$(mktemp -d /dev/shm/hyproxy-seal.XXXXXX)"   # tmpfs: never hits disk
  PLAIN="$SEAL_DIR/master.keys"
  : > "$PLAIN"
  _n=1
  # Random suffix makes the id globally unique: a fresh seal can never reuse an
  # earlier id (e.g. a second 'mk-1' with different bytes) and silently shadow
  # ciphertext still wrapped under the original. See core/secrets.py.
  printf 'mk-%s-%s:%s\n' "$_n" "$(openssl rand -hex 4)" "$(openssl rand -base64 32)" >> "$PLAIN"
  MASTER_KEY_FP="$(master_key_fp_of < "$PLAIN")"

  tpm2_createprimary -C o -g sha256 -G ecc -c "$SEAL_DIR/primary.ctx" >/dev/null
  tpm2_startauthsession -S "$SEAL_DIR/session.dat"
  tpm2_policypcr -S "$SEAL_DIR/session.dat" -l "$HYPROXY_TPM_PCRS" -L "$SEAL_DIR/pcr.policy" >/dev/null
  tpm2_flushcontext "$SEAL_DIR/session.dat"
  tpm2_create -C "$SEAL_DIR/primary.ctx" -g sha256 \
      -u "$SEAL_DIR/sealed.pub" -r "$SEAL_DIR/sealed.priv" \
      -L "$SEAL_DIR/pcr.policy" -i "$PLAIN" >/dev/null
  tpm2_load -C "$SEAL_DIR/primary.ctx" -u "$SEAL_DIR/sealed.pub" -r "$SEAL_DIR/sealed.priv" \
      -c "$SEAL_DIR/sealed.ctx" >/dev/null
  # Free the handle if a stale object holds it, then persist the new one.
  tpm2_evictcontrol -C o -c "$HYPROXY_TPM_SEALED_BLOB" >/dev/null 2>&1 || true
  tpm2_evictcontrol -C o -c "$SEAL_DIR/sealed.ctx" "$HYPROXY_TPM_SEALED_BLOB" >/dev/null

  # Round-trip through the TPM before anything depends on the blob (and
  # before the one and only printout).
  [ "$(tpm2_unseal -c "$HYPROXY_TPM_SEALED_BLOB" -p "pcr:$HYPROXY_TPM_PCRS")" = "$(cat "$PLAIN")" ] \
    || c_die "TPM unseal round-trip verification failed; not proceeding"

  cat <<KEYOUT

  ================ MASTER KEY: COPY TO YOUR FIPS DEVICE NOW =================
  This is the complete master-key payload just sealed into the TPM. It is
  printed exactly this once and stored nowhere else. If the TPM or its PCR
  state is lost, this backup is the only way to recover encrypted data.

$(sed 's/^/      /' "$PLAIN")
  ===========================================================================

KEYOUT
  shred -u "$PLAIN" "$SEAL_DIR/sealed.priv" "$SEAL_DIR/sealed.pub" 2>/dev/null || rm -f "$PLAIN"
  rm -rf "$SEAL_DIR"
fi

# --- 4b. Write config files ----------------------------------------------------
if [ "$REUSE_ENV" = yes ]; then
  if [ "$ENV_SRC" = "$HYPROXY_INSTALL_DIR/.env" ]; then
    c_info "keeping the existing $HYPROXY_INSTALL_DIR/.env"
  else
    c_info "installing $ENV_SRC as $HYPROXY_INSTALL_DIR/.env"
    cp "$ENV_SRC" "$HYPROXY_INSTALL_DIR/.env"
  fi
else
c_info "writing $HYPROXY_INSTALL_DIR/.env (the single config/secrets file)"
cat > "$HYPROXY_INSTALL_DIR/.env" <<EOF
# Generated by install.sh on $(date -u +%FT%TZ).
HYPROXY_DOMAIN=$HYPROXY_DOMAIN
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
HYPROXY_ISSUER=$HYPROXY_ISSUER
HYPROXY_ADMIN_UI_ORIGIN=$HYPROXY_ADMIN_UI_ORIGIN
HYPROXY_APPS_UI_ORIGIN=$HYPROXY_APPS_UI_ORIGIN
# TPM master-key lines (HYPROXY_TPM_SEALED_BLOB etc.) are appended below,
# outside this heredoc, so fresh and reused .env files get the same block.
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_NAME=$ADMIN_NAME
HYPROXY_ENABLE_GUAC=$HYPROXY_ENABLE_GUAC
DP_TLS_CERT=/etc/hyproxy/certs/fullchain.pem
DP_TLS_KEY=/etc/hyproxy/certs/privkey.pem
DP_LISTEN=:443
DP_TLS_GROUP=hyproxy
# ACME (lego DNS-01) settings; consumed by /usr/local/sbin/hyproxy-obtain-cert.sh
# via the hyproxy-acme systemd unit. Provider credentials follow below.
ACME_EMAIL=$ADMIN_EMAIL
LEGO_DNS_PROVIDER=$LEGO_DNS_PROVIDER
LEGO_PATH=/etc/hyproxy/lego
EOF
# Appended with printf, not the heredoc above, so tokens containing $ or
# backquotes land in the file literally.
printf '%s' "$PROVIDER_CREDS" >> "$HYPROXY_INSTALL_DIR/.env"
fi

# Rewrite the master-key block whatever the .env's origin: drop stale secrets
# lines (including settings retired with the removed file backend) and append
# the canonical TPM block.
sed -i -e '/^HYPROXY_SECRETS_BACKEND=/d' -e '/^HYPROXY_MASTER_KEY_FILE=/d' \
       -e '/^HYPROXY_TPM_SEALED_BLOB=/d' -e '/^HYPROXY_TPM_PCRS=/d' \
       -e '/^HYPROXY_TPM_DEVICE=/d' -e '/^HYPROXY_MASTER_KEY_FP=/d' \
       -e '/^TSS_GID=/d' -e '/^COMPOSE_FILE=/d' "$HYPROXY_INSTALL_DIR/.env"
[ -n "${MASTER_KEY_FP:-}" ] || c_die "internal: master key fingerprint not computed before writing .env"
cat >> "$HYPROXY_INSTALL_DIR/.env" <<EOF
HYPROXY_TPM_SEALED_BLOB=$HYPROXY_TPM_SEALED_BLOB
HYPROXY_TPM_PCRS=$HYPROXY_TPM_PCRS
HYPROXY_TPM_DEVICE=/dev/tpmrm0
# Fingerprint (sha256[:16]) of the current master key. The control plane fails
# closed at startup if the unsealed key does not match this, catching a reseal
# or blob swap without a re-wrap before it becomes a runtime decrypt failure.
HYPROXY_MASTER_KEY_FP=$MASTER_KEY_FP
TSS_GID=$TSS_GID
EOF
# Centralized logging: default the log dir on fresh AND reused .env files,
# preserving an operator-customized value. The hyproxy group's gid lets the
# tunnel container (runs as the node user, not uid 10001) join the group via
# compose group_add and write the setgid log dir.
grep -q '^HYPROXY_LOG_DIR=' "$HYPROXY_INSTALL_DIR/.env" \
  || echo "HYPROXY_LOG_DIR=/var/log/hyproxy" >> "$HYPROXY_INSTALL_DIR/.env"
HYPROXY_GID="$(getent group hyproxy | cut -d: -f3)"
sed -i -e '/^HYPROXY_GID=/d' "$HYPROXY_INSTALL_DIR/.env"
echo "HYPROXY_GID=$HYPROXY_GID" >> "$HYPROXY_INSTALL_DIR/.env"
chown hyproxy:hyproxy "$HYPROXY_INSTALL_DIR/.env"
chmod 600 "$HYPROXY_INSTALL_DIR/.env"

c_info "preparing /etc/hyproxy (lego state + cert install dirs)"
install -d -m 0755 /etc/hyproxy
# The lego state dir holds the ACME account key and issued private keys:
# owner-only, service-account owned so issuance/renewal never runs as root.
install -d -m 0700 -o hyproxy -g hyproxy /etc/hyproxy/lego
install -d -m 0755 -o hyproxy -g hyproxy /etc/hyproxy/certs

# Centralized log dir. Owner uid 10001 is the control-plane container user
# (server/Dockerfile); group hyproxy covers the baremetal dataplane and the
# tunnel container (joined via compose group_add). Setgid keeps group
# ownership on files each writer creates; each writer only rotates its own
# files, so only directory write access matters.
HYPROXY_LOG_DIR="$(sed -n 's/^HYPROXY_LOG_DIR=//p' "$HYPROXY_INSTALL_DIR/.env" | tail -n 1)"
HYPROXY_LOG_DIR="${HYPROXY_LOG_DIR:-/var/log/hyproxy}"
install -d -m 2775 -o 10001 -g hyproxy "$HYPROXY_LOG_DIR"

# The finished .env is the single source of truth from here on: every later
# phase (compose substitution, the config render, cert issuance) reads the
# same values the stack will run with.
set -a
# shellcheck disable=SC1091
. "$HYPROXY_INSTALL_DIR/.env"
set +a
case "$HYPROXY_ISSUER" in https://*) : ;; *) c_die "HYPROXY_ISSUER must be an https:// URL" ;; esac
[ "${POSTGRES_PASSWORD:-devonly}" = "devonly" ] && c_warn "POSTGRES_PASSWORD is still the compose placeholder; set a real one in .env before real use"
case "${HYPROXY_ENABLE_GUAC:-no}" in [Yy]*|1|true) HYPROXY_ENABLE_GUAC=yes ;; *) HYPROXY_ENABLE_GUAC=no ;; esac
export HYPROXY_TPM_DEVICE="${HYPROXY_TPM_DEVICE:-/dev/tpmrm0}"
ADMIN_UI_REDIRECT="${ADMIN_UI_REDIRECT:-${HYPROXY_ADMIN_UI_ORIGIN%/}/callback}"
# The admin-ui SPA is also served as the portal on the apps.* host; it logs in
# with the same client_id=admin-ui but derives its redirect_uri from its own
# origin, so that callback must be a registered redirect_uri too.
APPS_UI_REDIRECT="${APPS_UI_REDIRECT:-${HYPROXY_APPS_UI_ORIGIN%/}/callback}"

# --- 5. Host toolchain ---------------------------------------------------------
# Everything here is idempotent: it checks first and only acts on what is
# missing. Rocky Linux only, so dnf is used directly.
c_info "host toolchain (installing anything missing)"

if ! have docker; then
  c_info "installing Docker CE (dnf, Docker upstream repo)"
  dnf_install dnf-plugins-core
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  dnf_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
docker compose version >/dev/null 2>&1 || dnf_install docker-compose-plugin
docker info >/dev/null 2>&1 || c_die "Docker installed but the daemon is unreachable (see 'systemctl status docker')"

# The service account drives docker compose in the running stack. runuser does
# a fresh initgroups, so the new membership applies immediately, no re-login.
getent group docker >/dev/null 2>&1 || c_die "docker group not found after the Docker install"
usermod -aG docker hyproxy

have go   || dnf_install golang
have make || dnf_install make

if ! have uv; then
  c_info "installing uv (astral standalone installer -> /usr/local/bin)"
  curl -LsSf https://astral.sh/uv/install.sh \
    | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
fi

if ! have lego; then
  c_info "installing lego ACME client (latest GitHub release -> /usr/local/bin)"
  case "$(uname -m)" in
    x86_64)  _arch=amd64 ;;
    aarch64) _arch=arm64 ;;
    *) c_die "unsupported architecture $(uname -m) for the lego binary" ;;
  esac
  _ver="$(curl -fsSL https://api.github.com/repos/go-acme/lego/releases/latest \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$_ver" ] || c_die "could not determine the latest lego release"
  _tmp="$(mktemp -d)"
  curl -fsSL "https://github.com/go-acme/lego/releases/download/${_ver}/lego_${_ver}_linux_${_arch}.tar.gz" \
    -o "$_tmp/lego.tar.gz"
  tar -C "$_tmp" -xzf "$_tmp/lego.tar.gz" lego
  install -m 0755 "$_tmp/lego" /usr/local/bin/lego
  rm -rf "$_tmp"
fi

# --- 5b. Host firewall ---------------------------------------------------------
# Open the public data-plane port so start.sh can serve without a separate
# manual step; the ingress itself is not started until the end. The
# control-plane ports (8300/8400/8500) are published on 127.0.0.1 only and are
# deliberately NOT opened. The port is taken from DP_LISTEN, else
# dataplane/config.json, else 443.
c_info "host firewall (public data-plane port)"
_listen="${DP_LISTEN:-}"
if [ -z "$_listen" ] && [ -f "$HYPROXY_INSTALL_DIR/dataplane/config.json" ]; then
  _listen="$(sed -nE 's/.*"listen"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$HYPROXY_INSTALL_DIR/dataplane/config.json" | head -n1)"
fi
_listen="${_listen:-:443}"
_port="${_listen##*:}"
case "$_port" in
  ''|*[!0-9]*) c_warn "could not parse a public port from '$_listen'; skipping firewall" ;;
  *)
    if ! have firewall-cmd; then
      c_warn "firewalld not present; ensure $_port/tcp is open in your firewall"
    else
      systemctl enable --now firewalld >/dev/null 2>&1 || true
      if ! firewall-cmd --state >/dev/null 2>&1; then
        c_warn "firewalld installed but not running; not opening $_port/tcp"
      else
        _open=1
        firewall-cmd --query-port="$_port/tcp" >/dev/null 2>&1 || _open=0
        if [ "$_open" -eq 0 ] && [ "$_port" = 443 ]; then
          firewall-cmd --query-service=https >/dev/null 2>&1 && _open=1
        fi
        if [ "$_open" -eq 1 ]; then
          c_info "firewall: $_port/tcp already open"
        else
          c_info "firewall: opening $_port/tcp (public data-plane ingress)"
          firewall-cmd --permanent --add-port="$_port/tcp" >/dev/null
          firewall-cmd --reload >/dev/null
        fi
      fi
    fi
    ;;
esac

# --- 6. Container images -------------------------------------------------------
# The server image compiles the React UI in a stage and bakes it in; the tunnel
# image bundles guacamole-lite. guacd and postgres are pulled.
c_info "building container images (server + tunnel; UI compiled inside the server image)"
compose --profile app --profile guac --profile tools build

# --- 7. Database + identity setup (in containers) ------------------------------
c_info "starting Postgres"
compose up -d --wait postgres

c_info "applying migrations"
compose run --rm migrate

c_info "ensuring signing keys exist (published in JWKS)"
compose run --rm cli bootstrap-keys

# The one-time temporary password in the output is captured so the final
# summary can re-print it instead of letting it scroll away; it lives only in
# this process's memory, never on disk.
c_info "creating the first admin (or resetting its temporary password): $ADMIN_EMAIL"
c_warn "SAVE the admin one-time password below; it is shown only once (and re-printed in the final summary)."
_admin_out="$(compose run --rm cli bootstrap-admin --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" 2>&1)" \
  || c_warn "bootstrap-admin reported an error; continuing"
printf '%s\n' "$_admin_out"
ADMIN_TEMP_PW="$(printf '%s\n' "$_admin_out" | sed -n 's/^temporary password (shown once): //p' | tail -n 1)"
unset _admin_out

c_info "registering the admin-ui OIDC public client"
compose run --rm cli create-client \
    --client-id admin-ui --name "Admin UI" \
    --redirect-uri "$ADMIN_UI_REDIRECT" --redirect-uri "$APPS_UI_REDIRECT" \
  || c_warn "admin-ui client already registered; continuing"

c_info "registering the data plane forward-auth (gateway) OIDC client"
compose run --rm cli bootstrap-gateway-client \
  || c_die "failed to register the gateway client; protected resources will 400 at /oidc/authorize"

echo
echo "Register additional OIDC relying parties (extra apps) with:"
echo "  docker compose run --rm cli create-client --client-id <id> --name <name> --redirect-uri <uri>"

# --- 8. Baremetal data plane ---------------------------------------------------
# The repo is owned by the hyproxy service account but the installer runs as
# root, so git refuses to stamp VCS info ("dubious ownership") and `go build`
# fails. Mark the tree safe for the building user; idempotent across reruns.
git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$HYPROXY_INSTALL_DIR" \
  || git config --global --add safe.directory "$HYPROXY_INSTALL_DIR"
c_info "building the baremetal Go data plane binary"
make -C "$HYPROXY_INSTALL_DIR" dp-build

if [ "${HYPROXY_RUN_GATES:-0}" = 1 ]; then
  c_info "running security and quality gates"
  make -C "$HYPROXY_INSTALL_DIR" audit
  make -C "$HYPROXY_INSTALL_DIR" dp-test
else
  c_warn "skipping make audit and make dp-test (set HYPROXY_RUN_GATES=1 to run them)"
fi

# --- 8b. Guacamole cipher key --------------------------------------------------
# Minted now that the images exist; the tunnel container and the broker share
# the key via compose.
if [ "$HYPROXY_ENABLE_GUAC" = yes ]; then
  if [ -n "${HYPROXY_GUAC_CYPHER_KEY:-}" ]; then
    c_info "guac enabled: keeping the existing HYPROXY_GUAC_CYPHER_KEY from .env"
  else
    c_info "minting a Guacamole cipher key"
    GKEY="$(runuser -u hyproxy -- docker compose run --rm cli gen-guac-key 2>/dev/null | tr -d '\r' | tail -n1)"
    if [ -n "$GKEY" ]; then printf 'HYPROXY_GUAC_CYPHER_KEY=%s\n' "$GKEY" >> "$HYPROXY_INSTALL_DIR/.env"
    else c_warn "could not mint a guac key; set HYPROXY_GUAC_CYPHER_KEY in .env by hand"; fi
  fi
else
  c_info "guac disabled (enable later: docker compose run --rm cli gen-guac-key, then set HYPROXY_GUAC_CYPHER_KEY in .env)"
fi

# --- 9. Render the data-plane config -------------------------------------------
# The data plane is the sole public TLS ingress. idp and admin are proxied with
# auth disabled (they authenticate independently); application routes are
# DB-driven and hot-loaded from the control plane, so only the infra routes are
# rendered here. Static routes win on host conflict.
c_info "rendering dataplane/config.json"
DP_OUT="${DP_OUT:-$HYPROXY_INSTALL_DIR/dataplane/config.json}"
IDP_BACKEND="${IDP_BACKEND:-http://127.0.0.1:8300}"
ADMIN_BACKEND="${ADMIN_BACKEND:-http://127.0.0.1:8400}"
AUTHZ_BACKEND="${AUTHZ_BACKEND:-http://127.0.0.1:8500}"
GUAC_BACKEND="${GUAC_BACKEND:-http://127.0.0.1:8600}"
ROUTES_REFRESH_SECS="${ROUTES_REFRESH_SECS:-10}"
case "${DP_UPSTREAM_INSECURE_SKIP_VERIFY:-false}" in
  true|1|yes) UPSTREAM_INSECURE=true ;;
  *) UPSTREAM_INSECURE=false ;;
esac
HYPROXY_LOG_MAX_BYTES="${HYPROXY_LOG_MAX_BYTES:-52428800}"
DP_LOG_LEVEL="${DP_LOG_LEVEL:-info}"
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
  "log_dir": "$HYPROXY_LOG_DIR",
  "log_level": "$DP_LOG_LEVEL",
  "log_max_bytes": $HYPROXY_LOG_MAX_BYTES,
  "log_backup_count": 2,
  "routes": {
    "idp.$HYPROXY_DOMAIN": { "backend": "$IDP_BACKEND", "auth": false },
    "admin.$HYPROXY_DOMAIN": { "backend": "$ADMIN_BACKEND", "auth": false },
    "apps.$HYPROXY_DOMAIN": { "backend": "$ADMIN_BACKEND", "auth": false, "guac_tunnel_path": true }
  }
}
EOF
echo "wrote $DP_OUT (ingress $DP_LISTEN, hosts: idp/admin/apps/auth.$HYPROXY_DOMAIN)"

# The build and render above ran as root; re-own so the service account can
# read everything it runs (including the 0600 config.json).
chown -R hyproxy:hyproxy "$HYPROXY_INSTALL_DIR"

# --- 10. TLS certificate (Let's Encrypt via DNS-01) ----------------------------
# The issue/renew script is embedded here and written to /usr/local/sbin so the
# daily systemd renewal timer has a stable path to execute, independent of the
# repo checkout.
CERT_SCRIPT=/usr/local/sbin/hyproxy-obtain-cert.sh
c_info "installing $CERT_SCRIPT"
cat > "$CERT_SCRIPT" <<'OBTAIN_CERT'
#!/usr/bin/env bash

set -euo pipefail

ACME_ENV_FILE="${ACME_ENV_FILE:-}"
if [ -n "$ACME_ENV_FILE" ] && [ -f "$ACME_ENV_FILE" ]; then
  set -a; . "$ACME_ENV_FILE"; set +a
fi

: "${HYPROXY_DOMAIN:?set HYPROXY_DOMAIN}"
: "${ACME_EMAIL:?set ACME_EMAIL}"
: "${LEGO_DNS_PROVIDER:?set LEGO_DNS_PROVIDER (lego provider code, e.g. cloudflare)}"
command -v lego >/dev/null || { echo "lego not found (install from https://go-acme.github.io/lego/)" >&2; exit 1; }

LEGO_PATH="${LEGO_PATH:-/etc/hyproxy/lego}"
DP_TLS_CERT="${DP_TLS_CERT:-/etc/hyproxy/certs/fullchain.pem}"
DP_TLS_KEY="${DP_TLS_KEY:-/etc/hyproxy/certs/privkey.pem}"

common=(--accept-tos --email "$ACME_EMAIL" --dns "$LEGO_DNS_PROVIDER"
        --domains "*.$HYPROXY_DOMAIN" --domains "$HYPROXY_DOMAIN"
        --path "$LEGO_PATH")

# Point lego's propagation self-check at the domain's authoritative
# nameservers so issuance proceeds as soon as the provider API writes the
# TXT record, instead of waiting out public-resolver caches.
for _ns in $(dig +short NS "$HYPROXY_DOMAIN" 2>/dev/null); do
  common+=(--dns.resolvers "${_ns%.}:53")
done

mode="${1:-auto}"
crt="$LEGO_PATH/certificates/_.$HYPROXY_DOMAIN.crt"
key="$LEGO_PATH/certificates/_.$HYPROXY_DOMAIN.key"

if { [ "$mode" = "auto" ] && [ ! -f "$crt" ]; }; then
  echo "==> issuing wildcard cert for *.$HYPROXY_DOMAIN via DNS-01 ($LEGO_DNS_PROVIDER)"
  lego run "${common[@]}"
else
  echo "==> renewing (if within 30 days) *.$HYPROXY_DOMAIN"
  lego run "${common[@]}" --renew-days 30 || true
fi

[ -f "$crt" ] || { echo "expected issued cert at $crt not found" >&2; exit 1; }

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

c_info "issuing the Let's Encrypt wildcard cert (as the hyproxy user)"
runuser -u hyproxy -- env ACME_ENV_FILE="$HYPROXY_INSTALL_DIR/.env" "$CERT_SCRIPT" \
  || c_die "ACME issuance failed (see output above)"

# --- 11. SELinux, systemd units ------------------------------------------------
c_info "installing the systemd units"

# The cert script needs no fcontext: /usr/local/sbin is bin_t by default.
if have getenforce && [ "$(getenforce)" != "Disabled" ]; then
  have semanage || dnf install -y policycoreutils-python-utils
  f="$HYPROXY_INSTALL_DIR/dataplane/bin/dataplane"
  semanage fcontext -a -t bin_t "$f" 2>/dev/null || semanage fcontext -m -t bin_t "$f"
  restorecon -v "$f"
fi

# Written only if absent, so operator edits to the unit survive re-runs.
if [ ! -f /etc/systemd/system/hyproxy.service ]; then
cat > /etc/systemd/system/hyproxy.service <<EOF
[Unit]
Description=hyproxy stack (control-plane containers + baremetal data plane)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
User=hyproxy
Group=hyproxy
WorkingDirectory=$HYPROXY_INSTALL_DIR
ExecStart=$HYPROXY_INSTALL_DIR/start.sh
ExecStop=$HYPROXY_INSTALL_DIR/stop.sh
Restart=on-failure
RestartSec=5
# The data plane (a child of start.sh) binds :443 without root; ambient caps
# are inherited across exec by non-root children.
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
fi

cat > /etc/systemd/system/hyproxy-acme.service <<EOF
[Unit]
Description=hyproxy ACME wildcard cert issuance/renewal (lego DNS-01)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=hyproxy
Group=hyproxy
EnvironmentFile=$HYPROXY_INSTALL_DIR/.env
ExecStart=$CERT_SCRIPT
EOF

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

cat > /etc/systemd/system/hyproxy-ship-logs.service <<EOF
[Unit]
Description=hyproxy audit log shipping to $HYPROXY_LOG_DIR/audit.log
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=hyproxy
Group=hyproxy
WorkingDirectory=$HYPROXY_INSTALL_DIR
ExecStart=/usr/bin/docker compose run --rm cli ship-logs --to-file
EOF

cat > /etc/systemd/system/hyproxy-ship-logs.timer <<'EOF'
[Unit]
Description=hyproxy audit log shipping (every 5 minutes)

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

chmod 0644 /etc/systemd/system/hyproxy.service \
           /etc/systemd/system/hyproxy-acme.service \
           /etc/systemd/system/hyproxy-acme.timer \
           /etc/systemd/system/hyproxy-ship-logs.service \
           /etc/systemd/system/hyproxy-ship-logs.timer
systemctl daemon-reload

systemctl enable hyproxy
systemctl enable hyproxy-acme
systemctl enable hyproxy-ship-logs

# --- 11b. kernel network tuning (BBR congestion control) -----------------------
c_info "enabling BBR congestion control (WAN streaming throughput)"

cat > /etc/sysctl.d/99-hyproxy-net.conf <<'EOF'
# hyproxy: WAN streaming throughput. BBR + fq (fair-queue pacing) so a single
# high-bitrate flow is not throttled by cubic's loss-based backoff.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

echo tcp_bbr > /etc/modules-load.d/hyproxy-bbr.conf
if modprobe tcp_bbr 2>/dev/null; then
  sysctl --system >/dev/null
  iface=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
  [ -n "$iface" ] && tc qdisc replace dev "$iface" root fq 2>/dev/null || true
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  if [ "$cc" = bbr ]; then
    c_info "congestion control now: bbr"
  else
    c_warn "BBR drop-in written but active cc is '$cc'; verify after reboot"
  fi
else
  c_warn "tcp_bbr module unavailable on this kernel; drop-in left in place for a kernel that has it"
fi

# --- 12. Start the stack -------------------------------------------------------
c_info "starting the control plane (containers, as the hyproxy user)"
PROFILES="--profile app"
[ "$HYPROXY_ENABLE_GUAC" = yes ] && PROFILES="$PROFILES --profile guac"
# shellcheck disable=SC2086
runuser -u hyproxy -- docker compose $PROFILES up -d --wait

if [ "$NEW_KEY_SEALED" = yes ]; then
  c_info "re-wrapping all sealed secrets to the current TPM master key"
  runuser -u hyproxy -- docker compose run --rm cli rotate-master-key \
    || c_die "re-wrap failed: the database holds ciphertext that the newly sealed
     master key cannot decrypt. The key it was encrypted under is not in this blob
     (an orphaned reseal). Restore the original key from the FIPS backup and reseal
     under the current PCR policy before retrying."
fi

c_info "enabling + starting the stack, renewal timer, and log shipping timer"
systemctl enable --now hyproxy
systemctl enable --now hyproxy-acme.timer
systemctl enable --now hyproxy-ship-logs.timer

# --- 13. Summary ---------------------------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
c_info "installation complete"
cat <<EOF

hyproxy is installed at $HYPROXY_INSTALL_DIR and running.

  Public ingress : :443 (data plane, part of the systemd 'hyproxy' stack unit)
  Control plane  : idp/admin/authz containers on 127.0.0.1
  Cert renewal   : hyproxy-acme.timer (daily, runs as 'hyproxy')
  Logs           : $HYPROXY_LOG_DIR (JSON lines, 50 MB rotation, 2 archives kept;
                   audit.log drained every 5 min by hyproxy-ship-logs.timer)
  Service user   : 'hyproxy' (nologin; owns $HYPROXY_INSTALL_DIR and runs the stack)

NEXT STEPS (not automated):
  1. Public DNS: point idp.$HYPROXY_DOMAIN, admin.$HYPROXY_DOMAIN, auth.$HYPROXY_DOMAIN (and each app
     host) at this server's public IP${IP:+ ($IP)}.
  2. First login at https://idp.$HYPROXY_DOMAIN/auth/login as $ADMIN_EMAIL with the
     one-time password${ADMIN_TEMP_PW:+ shown below}; enroll two passkeys at
     /auth/enroll/webauthn.
$(if [ -n "$ADMIN_TEMP_PW" ]; then
    printf '\n     ADMIN ONE-TIME PASSWORD for %s (shown once; save it NOW):\n         %s\n' "$ADMIN_EMAIL" "$ADMIN_TEMP_PW"
  else
    printf '\n     (could not capture the one-time password from the bootstrap-admin\n     output; look for the "temporary password (shown once)" line above. Every\n     run resets the break-glass admin to a fresh temporary password.)\n'
  fi)
  3. Before exposing the server to the internet: set up WireGuard admin
     access, enforce backend TLS verification, wire off-box logging, and
     complete a security review.

SECURITY NOTES:
  - $HYPROXY_INSTALL_DIR/.env (0600, hyproxy-owned) holds ALL secrets: the Postgres
    password and the DNS provider API credentials. Guard it and any backups.
  - The 'hyproxy' account is in the 'docker' group, which is root-equivalent
    on most hosts; treat a compromise of that account as a host compromise.
  - The master key is sealed in the TPM (handle in HYPROXY_TPM_SEALED_BLOB)
    under PCR policy HYPROXY_TPM_PCRS; nothing unsealed is on disk. Keep the
    one-time printout on the FIPS device only. A firmware/kernel update that
    changes the bound PCRs makes unsealing fail closed; reseal
    before rebooting into such an update.
EOF
