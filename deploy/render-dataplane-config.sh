#!/usr/bin/env bash
#
# render-dataplane-config.sh: emit the data-plane config.json for a staging /
# prod deployment from environment variables, so the domain and cert paths live
# in one place (.env) instead of being hand-edited into JSON.
#
# The data plane is the single LAN TLS ingress. It terminates TLS with the
# Let's Encrypt wildcard cert and Host-routes to the loopback-published
# containers. idp and admin are proxied with auth disabled: the IdP and the
# admin app authenticate independently (OIDC + DPoP + step-up), so they must NOT
# sit behind the gateway forward-auth. Everything else (app backends) is
# forward-authed.
#
# The "routes" object below is INFRA ONLY (idp/admin). Application routes are
# DB-driven: create resources with a public_host in the admin UI and the data
# plane polls the control plane (/authz/routes) and hot-loads them, no restart
# and no config edit. Static routes here still work and win on host conflict.
#
# Required:
#   HYPROXY_DOMAIN     base domain; hosts are idp./admin./auth.<domain>
# Optional:
#   DP_TLS_CERT        cert path (default /etc/hyproxy/certs/fullchain.pem)
#   DP_TLS_KEY         key path  (default /etc/hyproxy/certs/privkey.pem)
#   DP_LISTEN          listen addr (default :443)
#   DP_OUT             output path (default <repo>/dataplane/config.json)
#   IDP_BACKEND/ADMIN_BACKEND/AUTHZ_BACKEND  loopback origins (sane defaults)
#   GUAC_BACKEND       tunnel origin for DB vnc/rdp/ssh routes (default guac:8600)
#   ROUTES_REFRESH_SECS  DB-route poll interval (default 10)
#   DP_UPSTREAM_INSECURE_SKIP_VERIFY  "true" to skip TLS verification on https
#                      backends (self-signed / IP-only certs). Default false.

set -euo pipefail

: "${HYPROXY_DOMAIN:?set HYPROXY_DOMAIN (e.g. staging.example.com)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DP_TLS_CERT="${DP_TLS_CERT:-/etc/hyproxy/certs/fullchain.pem}"
DP_TLS_KEY="${DP_TLS_KEY:-/etc/hyproxy/certs/privkey.pem}"
DP_LISTEN="${DP_LISTEN:-:443}"
DP_OUT="${DP_OUT:-$ROOT/dataplane/config.json}"
IDP_BACKEND="${IDP_BACKEND:-http://127.0.0.1:8300}"
ADMIN_BACKEND="${ADMIN_BACKEND:-http://127.0.0.1:8400}"
AUTHZ_BACKEND="${AUTHZ_BACKEND:-http://127.0.0.1:8500}"
GUAC_BACKEND="${GUAC_BACKEND:-http://127.0.0.1:8600}"
ROUTES_REFRESH_SECS="${ROUTES_REFRESH_SECS:-10}"
case "${DP_UPSTREAM_INSECURE_SKIP_VERIFY:-false}" in
  true|1|yes) UPSTREAM_INSECURE=true ;;
  *) UPSTREAM_INSECURE=false ;;
esac

cat > "$DP_OUT" <<JSON
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
JSON

echo "wrote $DP_OUT (ingress $DP_LISTEN, hosts: idp/admin/auth.$HYPROXY_DOMAIN)"
