#!/usr/bin/env bash
#
# obtain-cert.sh: issue or renew the wildcard Let's Encrypt cert for the staging
# domain via ACME DNS-01 (lego) and install it where the data plane hot-reloads
# it (internal/tlsconf re-reads the files live, so no restart is needed).
#
# DNS-01 is used deliberately: it issues a browser-trusted cert for the LAN-only
# admin/idp hosts WITHOUT exposing anything to the internet (the challenge is a
# DNS TXT record). It also permits the wildcard.
#
# Usage:
#   deploy/acme/obtain-cert.sh            # issue if missing, else renew (<30d)
#   deploy/acme/obtain-cert.sh renew      # renew only
#
# Configuration (put secrets in an env file OUTSIDE the repo, default
# /etc/hyproxy/acme.env, and reference it via ACME_ENV_FILE):
#   STAGING_DOMAIN          base domain; cert covers *.<domain> and <domain>
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

: "${STAGING_DOMAIN:?set STAGING_DOMAIN}"
: "${ACME_EMAIL:?set ACME_EMAIL}"
: "${LEGO_DNS_PROVIDER:?set LEGO_DNS_PROVIDER (lego provider code, e.g. cloudflare)}"
command -v lego >/dev/null || { echo "lego not found (install from https://go-acme.github.io/lego/)" >&2; exit 1; }

LEGO_PATH="${LEGO_PATH:-/etc/hyproxy/lego}"
DP_TLS_CERT="${DP_TLS_CERT:-/etc/hyproxy/certs/fullchain.pem}"
DP_TLS_KEY="${DP_TLS_KEY:-/etc/hyproxy/certs/privkey.pem}"

server_args=()
[ "${ACME_STAGING:-0}" = "1" ] && server_args=(--server https://acme-staging-v02.api.letsencrypt.org/directory)

common=(--accept-tos --email "$ACME_EMAIL" --dns "$LEGO_DNS_PROVIDER"
        --domains "*.$STAGING_DOMAIN" --domains "$STAGING_DOMAIN"
        --path "$LEGO_PATH" "${server_args[@]}")

mode="${1:-auto}"
# lego stores the wildcard cert under a sanitized name: *. -> _.
crt="$LEGO_PATH/certificates/_.$STAGING_DOMAIN.crt"
key="$LEGO_PATH/certificates/_.$STAGING_DOMAIN.key"

# lego v5 folds get + renew into a single `run` command, and all these flags are
# subcommand-scoped, so they must follow `run` (v4 accepted them before it).
if { [ "$mode" = "auto" ] && [ ! -f "$crt" ]; }; then
  echo "==> issuing wildcard cert for *.$STAGING_DOMAIN via DNS-01 ($LEGO_DNS_PROVIDER)"
  lego run "${common[@]}"
else
  echo "==> renewing (if within 30 days) *.$STAGING_DOMAIN"
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
