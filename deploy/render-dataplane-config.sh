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
# Required:
#   STAGING_DOMAIN     base domain; hosts are idp./admin./auth.<domain>
# Optional:
#   DP_TLS_CERT        cert path (default /etc/hyproxy/certs/fullchain.pem)
#   DP_TLS_KEY         key path  (default /etc/hyproxy/certs/privkey.pem)
#   DP_LISTEN          listen addr (default :443)
#   DP_OUT             output path (default <repo>/dataplane/config.json)
#   IDP_BACKEND/ADMIN_BACKEND/AUTHZ_BACKEND  loopback origins (sane defaults)
#
# App backends are deployment-specific; add them to the "routes" object after
# rendering (each an object like {"backend":"http://127.0.0.1:9101"}), or extend
# APP_ROUTES_JSON below.

set -euo pipefail

: "${STAGING_DOMAIN:?set STAGING_DOMAIN (e.g. staging.example.com)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DP_TLS_CERT="${DP_TLS_CERT:-/etc/hyproxy/certs/fullchain.pem}"
DP_TLS_KEY="${DP_TLS_KEY:-/etc/hyproxy/certs/privkey.pem}"
DP_LISTEN="${DP_LISTEN:-:443}"
DP_OUT="${DP_OUT:-$ROOT/dataplane/config.json}"
IDP_BACKEND="${IDP_BACKEND:-http://127.0.0.1:8300}"
ADMIN_BACKEND="${ADMIN_BACKEND:-http://127.0.0.1:8400}"
AUTHZ_BACKEND="${AUTHZ_BACKEND:-http://127.0.0.1:8500}"

# Extra app routes as a JSON fragment (host -> route object), comma-LEADING so it
# appends cleanly after the admin route. Default: none.
APP_ROUTES_JSON="${APP_ROUTES_JSON:-}"

cat > "$DP_OUT" <<JSON
{
  "listen": "$DP_LISTEN",
  "tls_cert": "$DP_TLS_CERT",
  "tls_key": "$DP_TLS_KEY",
  "authz_url": "$AUTHZ_BACKEND",
  "auth_host": "auth.$STAGING_DOMAIN",
  "auth_backend": "$AUTHZ_BACKEND",
  "gateway_cookie_name": "__Secure-gw",
  "routes": {
    "idp.$STAGING_DOMAIN": { "backend": "$IDP_BACKEND", "auth": false },
    "admin.$STAGING_DOMAIN": { "backend": "$ADMIN_BACKEND", "auth": false }$APP_ROUTES_JSON
  }
}
JSON

echo "wrote $DP_OUT (ingress $DP_LISTEN, hosts: idp/admin/auth.$STAGING_DOMAIN)"
