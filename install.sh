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
#   - runs bootstrap.sh (installs deps, opens the firewall, builds images,
#     migrates, creates the first admin, builds the data-plane binary); on a
#     re-run the break-glass admin gets a FRESH one-time temporary password,
#   - issues the Let's Encrypt wildcard cert via lego DNS-01 (no wait on DNS
#     propagation: the challenge record is assumed applied and Let's Encrypt
#     validates from its own resolvers),
#   - installs and enables the systemd units (data plane + renewal timer),
#   - brings up the control plane and starts the data plane.
#
# A TPM 2.0 (/dev/tpmrm0) is REQUIRED: production installs always use the TPM
# secrets backend; the on-disk 'file' backend is dev-only and never used here.
# If a previous install used the file backend, its key is folded into the
# sealed blob, all sealed data is re-wrapped to a fresh key, and the on-disk
# key file is destroyed.
#
# An existing sealed blob is kept only after it VERIFIABLY unseals to
# master-key material under the PCR policy. On a fresh image the configured
# handle may hold a foreign object from a different setup; that object is left
# untouched and the new key is sealed to the next free persistent handle,
# which is recorded in .env (HYPROXY_TPM_SEALED_BLOB). A sealed object that
# no longer unseals (PCR drift) fails closed; see docs/TPM_STEPS.md, or set
# HYPROXY_TPM_FORCE_RESEAL=1 to discard it and seal a brand-new key.
#
# It deliberately does NOT do: WireGuard admin access, your public DNS records,
# or the final security review. Those remain manual; see
# docs/production-checklist.md.
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
have openssl || dnf install -y openssl

# TPM 2.0 is mandatory: the master key is sealed to hardware, never kept on disk.
[ -e /dev/tpmrm0 ] || c_die "no TPM 2.0 resource manager at /dev/tpmrm0; production installs require a TPM"
have tpm2_unseal || dnf install -y tpm2-tools
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
# disk, ever: the sealing scratch space is tmpfs and shredded, and the compose
# master_key secret is pointed at /dev/null.
umask 077
: "${HYPROXY_TPM_SEALED_BLOB:=0x81010001}"
: "${HYPROXY_TPM_PCRS:=sha256:0,2,4,7}"
TSS_GID="$(getent group tss | cut -d: -f3)"
[ -n "$TSS_GID" ] || c_die "host group 'tss' not found (tpm2-tools should have provided it)"

# A previous file-backend install is migrated: its key lines are folded into
# the sealed blob so existing ciphertext still decrypts, a fresh key is added
# as current, and once the stack is up everything is re-wrapped to it and the
# old key file destroyed (section 9).
OLD_KEY_FILE=""
case "${HYPROXY_MASTER_KEY_FILE:-}" in ""|/dev/null) ;; *)
  [ -f "$HYPROXY_MASTER_KEY_FILE" ] && OLD_KEY_FILE="$HYPROXY_MASTER_KEY_FILE" ;;
esac
if [ -z "$OLD_KEY_FILE" ] && [ "${HYPROXY_SECRETS_BACKEND:-file}" != tpm ] \
   && [ -f "$HYPROXY_INSTALL_DIR/server/.dev/master.keys" ]; then
  OLD_KEY_FILE="$HYPROXY_INSTALL_DIR/server/.dev/master.keys"
fi

# An existing blob is trusted only after a full unseal round-trip: the handle
# must unseal under the PCR policy AND yield master-key lines. tpm2_readpublic
# alone is not enough: a fresh image can carry a foreign object (another
# application's key, or a blob from a different setup) at the configured
# handle, and treating it as ours leaves the stack with no usable secret.
blob_unseals() {  # blob_unseals HANDLE: payload parses as master-key lines
  tpm2_unseal -c "$1" -p "pcr:$HYPROXY_TPM_PCRS" 2>/dev/null \
    | grep -q '^mk-[0-9][0-9]*:'
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

if [ "$REUSE_ENV" = yes ] && [ "${HYPROXY_SECRETS_BACKEND:-}" = tpm ] && [ -z "$OLD_KEY_FILE" ] \
   && blob_unseals "$HYPROXY_TPM_SEALED_BLOB"; then
  c_info "master key already sealed in the TPM at $HYPROXY_TPM_SEALED_BLOB (unseal verified; keeping it)"
else
  # A new key is about to be sealed. If the configured handle is occupied by
  # an object that is not a usable hyproxy blob, never destroy it:
  #   - a keyedhash that no longer unseals may be an older hyproxy master key
  #     whose PCR state drifted -> fail closed (docs/TPM_STEPS.md), unless
  #     HYPROXY_TPM_FORCE_RESEAL=1 explicitly discards it;
  #   - anything else is a foreign object from a different setup -> leave it
  #     intact and seal to the next free handle instead (recorded in .env).
  if handle_in_use "$HYPROXY_TPM_SEALED_BLOB" && ! blob_unseals "$HYPROXY_TPM_SEALED_BLOB"; then
    if [ "${HYPROXY_TPM_FORCE_RESEAL:-0}" = 1 ]; then
      c_warn "HYPROXY_TPM_FORCE_RESEAL=1: discarding the object at $HYPROXY_TPM_SEALED_BLOB"
      tpm2_evictcontrol -C o -c "$HYPROXY_TPM_SEALED_BLOB" >/dev/null
    elif tpm2_readpublic -c "$HYPROXY_TPM_SEALED_BLOB" 2>/dev/null | grep -q keyedhash; then
      c_die "handle $HYPROXY_TPM_SEALED_BLOB holds a sealed object that does not unseal under pcr:$HYPROXY_TPM_PCRS.
       If it is an earlier hyproxy master key, the PCR state has drifted: reseal it per
       docs/TPM_STEPS.md. To discard it and seal a NEW key (any data sealed under it
       becomes unrecoverable), re-run with HYPROXY_TPM_FORCE_RESEAL=1."
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
  if [ -n "$OLD_KEY_FILE" ]; then
    c_info "folding existing file-backend key(s) from $OLD_KEY_FILE into the blob"
    grep -v '^[[:space:]]*#' "$OLD_KEY_FILE" | grep . >> "$PLAIN" \
      || c_die "no key lines found in $OLD_KEY_FILE"
    _n=$(($(grep -c . "$PLAIN") + 1))
    while grep -q "^mk-$_n:" "$PLAIN"; do _n=$((_n + 1)); done
  fi
  printf 'mk-%s:%s\n' "$_n" "$(openssl rand -base64 32)" >> "$PLAIN"

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
# The compose master_key secret must still resolve to a file; /dev/null keeps
# it defined and empty (the TPM backend never reads it).
HYPROXY_MASTER_KEY_FILE=/dev/null
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
# Generated by install.sh on $(date -u +%FT%TZ). Production values.
HYPROXY_DOMAIN=$HYPROXY_DOMAIN
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
HYPROXY_ISSUER=$HYPROXY_ISSUER
HYPROXY_ADMIN_UI_ORIGIN=$HYPROXY_ADMIN_UI_ORIGIN
# Secrets backend lines (HYPROXY_SECRETS_BACKEND etc.) are appended below,
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

# Enforce the TPM backend in the .env whatever its origin (a reused pre-TPM
# .env still says HYPROXY_SECRETS_BACKEND=file): replace the secrets-backend
# lines with the canonical TPM block.
sed -i -e '/^HYPROXY_SECRETS_BACKEND=/d' -e '/^HYPROXY_MASTER_KEY_FILE=/d' \
       -e '/^HYPROXY_TPM_SEALED_BLOB=/d' -e '/^HYPROXY_TPM_PCRS=/d' \
       -e '/^HYPROXY_TPM_DEVICE=/d' \
       -e '/^TSS_GID=/d' -e '/^COMPOSE_FILE=/d' "$HYPROXY_INSTALL_DIR/.env"
cat >> "$HYPROXY_INSTALL_DIR/.env" <<EOF
HYPROXY_SECRETS_BACKEND=tpm
HYPROXY_MASTER_KEY_FILE=/dev/null
HYPROXY_TPM_SEALED_BLOB=$HYPROXY_TPM_SEALED_BLOB
HYPROXY_TPM_PCRS=$HYPROXY_TPM_PCRS
HYPROXY_TPM_DEVICE=/dev/tpmrm0
TSS_GID=$TSS_GID
EOF
chown hyproxy:hyproxy "$HYPROXY_INSTALL_DIR/.env"
chmod 600 "$HYPROXY_INSTALL_DIR/.env"

c_info "preparing /etc/hyproxy (lego state + cert install dirs)"
install -d -m 0755 /etc/hyproxy
# The lego state dir holds the ACME account key and issued private keys:
# owner-only, service-account owned so issuance/renewal never runs as root.
install -d -m 0700 -o hyproxy -g hyproxy /etc/hyproxy/lego
install -d -m 0755 -o hyproxy -g hyproxy /etc/hyproxy/certs

# --- 5. Bootstrap (deps, firewall, images, migrate, admin, binary) -----------
c_info "running bootstrap.sh"
c_warn "SAVE the admin one-time password printed below; it is shown only once."
SKIP_GATES=1; [ "${HYPROXY_RUN_GATES:-0}" = "1" ] && SKIP_GATES=0
# Bootstrap output is teed through tmpfs (never disk) so the admin one-time
# password can be re-printed in the final summary instead of scrolling away.
BOOT_LOG="$(mktemp /dev/shm/hyproxy-boot.XXXXXX)"
( set +e
  HYPROXY_ASSUME_YES=1 SKIP_GATES="$SKIP_GATES" \
    ADMIN_EMAIL="$ADMIN_EMAIL" ADMIN_NAME="$ADMIN_NAME" \
    bash "$HYPROXY_INSTALL_DIR/bootstrap.sh" 2>&1
  echo "$?" > "$BOOT_LOG.rc"
) | tee "$BOOT_LOG"
BOOT_RC="$(cat "$BOOT_LOG.rc" 2>/dev/null || echo 1)"
ADMIN_TEMP_PW="$(sed -n 's/^temporary password (shown once): //p' "$BOOT_LOG" | tail -n 1)"
rm -f "$BOOT_LOG" "$BOOT_LOG.rc"
[ "$BOOT_RC" = 0 ] || c_die "bootstrap.sh failed (exit $BOOT_RC; see output above)"

# From here on the service account drives docker compose. runuser does a fresh
# initgroups, so the new membership applies immediately, no re-login needed.
getent group docker >/dev/null 2>&1 || c_die "docker group not found after bootstrap"
usermod -aG docker hyproxy

# Optional guac cipher key, minted now that images exist.
if [ "$HYPROXY_ENABLE_GUAC" = yes ]; then
  c_info "minting a Guacamole cipher key"
  GKEY="$(runuser -u hyproxy -- docker compose run --rm cli gen-guac-key 2>/dev/null | tr -d '\r' | tail -n1)"
  if [ -n "$GKEY" ]; then printf 'HYPROXY_GUAC_CYPHER_KEY=%s\n' "$GKEY" >> "$HYPROXY_INSTALL_DIR/.env"
  else c_warn "could not mint a guac key; set HYPROXY_GUAC_CYPHER_KEY in .env by hand"; fi
fi

# --- 6. Render the data-plane config -----------------------------------------
# The data plane is the single LAN TLS ingress. idp and admin are proxied with
# auth disabled (they authenticate independently); application routes are
# DB-driven and hot-loaded from the control plane, so only the infra routes are
# rendered here. Static routes win on host conflict.
c_info "rendering dataplane/config.json"
set -a; . "$HYPROXY_INSTALL_DIR/.env"; set +a
case "${HYPROXY_ENABLE_GUAC:-no}" in [Yy]*|1|true) HYPROXY_ENABLE_GUAC=yes ;; *) HYPROXY_ENABLE_GUAC=no ;; esac
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

# bootstrap.sh and the render above ran as root; re-own so the service
# account can read everything it runs (including the 0600 config.json).
chown -R hyproxy:hyproxy "$HYPROXY_INSTALL_DIR"

# --- 7. TLS certificate (Let's Encrypt via DNS-01) ---------------------------
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
# Configuration comes from the environment (the hyproxy-acme systemd unit
# loads the stack's .env via EnvironmentFile; ACME_ENV_FILE, if set, names an
# env file to source instead):
#   HYPROXY_DOMAIN          base domain; cert covers *.<domain> and <domain>
#   ACME_EMAIL              registration/expiry-notice email
#   LEGO_DNS_PROVIDER       lego DNS provider code (e.g. cloudflare, route53)
#   <provider creds>        provider-specific env vars (e.g. CLOUDFLARE_DNS_API_TOKEN)
#   LEGO_PATH               lego state dir (default /etc/hyproxy/lego)
#   DP_TLS_CERT/DP_TLS_KEY  install targets (default /etc/hyproxy/certs/{fullchain,privkey}.pem)
#   ACME_STAGING=1          use the Let's Encrypt STAGING CA first (untrusted, for dry runs)

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

server_args=()
[ "${ACME_STAGING:-0}" = "1" ] && server_args=(--server https://acme-staging-v02.api.letsencrypt.org/directory)

common=(--accept-tos --email "$ACME_EMAIL" --dns "$LEGO_DNS_PROVIDER"
        --domains "*.$HYPROXY_DOMAIN" --domains "$HYPROXY_DOMAIN"
        --path "$LEGO_PATH"
        # Skip lego's local propagation self-check on the TXT challenge record:
        # assume the provider applied it and move straight to validation.
        # Let's Encrypt checks from its own resolvers regardless.
        --dns.propagation-disable-ans
        "${server_args[@]}")

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

c_info "issuing the real Let's Encrypt wildcard cert (as the hyproxy user)"
runuser -u hyproxy -- env ACME_ENV_FILE="$HYPROXY_INSTALL_DIR/.env" "$CERT_SCRIPT" \
  || c_die "ACME issuance failed (see output above)"

# --- 8. SELinux, systemd units ------------------------------------------------
c_info "installing the systemd units"

# The cert script needs no fcontext: /usr/local/sbin is bin_t by default.
if have getenforce && [ "$(getenforce)" != "Disabled" ]; then
  have semanage || dnf install -y policycoreutils-python-utils
  f="$HYPROXY_INSTALL_DIR/dataplane/bin/dataplane"
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
WorkingDirectory=$HYPROXY_INSTALL_DIR/dataplane
ExecStart=$HYPROXY_INSTALL_DIR/dataplane/bin/dataplane -config config.json
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
User=hyproxy
Group=hyproxy
EnvironmentFile=$HYPROXY_INSTALL_DIR/.env
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

# --- 9. Start the stack ------------------------------------------------------
c_info "starting the control plane (containers, as the hyproxy user)"
PROFILES="--profile app"
[ "$HYPROXY_ENABLE_GUAC" = yes ] && PROFILES="$PROFILES --profile guac"
# shellcheck disable=SC2086
runuser -u hyproxy -- docker compose $PROFILES up -d --wait

# File-backend migration epilogue: with the stack up on the TPM backend (old
# key still in the blob), re-wrap every sealed secret to the new current key,
# then destroy the on-disk key. Invariant: no unsealed master-key material on
# disk in production.
if [ -n "$OLD_KEY_FILE" ]; then
  c_info "re-wrapping all sealed secrets to the new TPM master key"
  runuser -u hyproxy -- docker compose run --rm cli rotate-master-key
  c_info "destroying the on-disk file master key ($OLD_KEY_FILE)"
  shred -u "$OLD_KEY_FILE"
fi

c_info "enabling + starting the data plane and renewal timer"
systemctl enable --now hyproxy-dataplane
systemctl enable --now hyproxy-acme.timer

# --- 10. Summary ---------------------------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
c_info "installation complete"
cat <<EOF

hyproxy is installed at $HYPROXY_INSTALL_DIR and running.

  Public ingress : :443 (data plane, systemd 'hyproxy-dataplane')
  Control plane  : idp/admin/authz containers on 127.0.0.1
  Cert renewal   : hyproxy-acme.timer (daily, runs as 'hyproxy')
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
    printf '\n     (could not capture the one-time password from the bootstrap output;\n     look for the "temporary password (shown once)" line above. Every run\n     resets the break-glass admin to a fresh temporary password.)\n'
  fi)
  3. Work through docs/production-checklist.md before internet exposure:
     WireGuard admin access, backend TLS verification, off-box logging, and
     the security review.

SECURITY NOTES:
  - $HYPROXY_INSTALL_DIR/.env (0600, hyproxy-owned) holds ALL secrets: the Postgres
    password and the DNS provider API credentials. Guard it and any backups.
  - The 'hyproxy' account is in the 'docker' group, which is root-equivalent
    on most hosts; treat a compromise of that account as a host compromise.
  - The master key is sealed in the TPM (handle in HYPROXY_TPM_SEALED_BLOB)
    under PCR policy HYPROXY_TPM_PCRS; nothing unsealed is on disk. Keep the
    one-time printout on the FIPS device only. A firmware/kernel update that
    changes the bound PCRs makes unsealing fail closed; reseal per
    docs/TPM_STEPS.md before rebooting into such an update.
EOF
