# LAN-only staging environment

A staging deployment on a single VM (**Rocky Linux only** for now), reachable
only from the LAN, with browser-trusted **Let's Encrypt** TLS. `bootstrap-prod.sh`
installs any missing host toolchain (Docker, the Go toolchain, make, uv, lego)
and opens the public port in `firewalld`, so a bare Rocky VM is enough to start.
It reuses the production topology (`docs/deployment.md`): the containerized
control plane behind the baremetal Go data plane as the single TLS ingress. The
one deliberate difference from prod is that the **admin UI is reachable from the
LAN** (still never from the internet), fronted through the data plane on a
no-forward-auth route while the admin app keeps enforcing OIDC + DPoP + step-up.

## Why this shape

- WebAuthn's RP ID and origin derive from `HYPROXY_ISSUER`
  (`server/src/hyproxy/security/webauthn.py`); WebAuthn forbids a bare IP and
  demands a trusted cert in a secure context. A real hostname + a Let's Encrypt
  cert make passkey enrollment, the SPA's background token `fetch()`, and
  secure-context all work with **no client-side CA import**.
- **DNS-01** issues a valid cert for the LAN-only hosts without exposing port
  80/443 to the internet: the ACME challenge is a DNS TXT record.

## Hostnames

All under one base domain `HYPROXY_DOMAIN` (wildcard cert `*.HYPROXY_DOMAIN`):

| Host                    | Serves                         | Data-plane route |
|-------------------------|--------------------------------|------------------|
| `idp.HYPROXY_DOMAIN`    | OIDC IdP (issuer)              | `auth:false` -> `127.0.0.1:8300` |
| `admin.HYPROXY_DOMAIN`  | Admin API + served SPA        | `auth:false` -> `127.0.0.1:8400` |
| `auth.HYPROXY_DOMAIN`   | Gateway / guac broker         | auth_host -> `127.0.0.1:8500` |
| `<app>.HYPROXY_DOMAIN`  | Protected app backends        | forward-authed |

Point these at the VM's **LAN IP** via your LAN DNS (split-horizon) or each
client's `/etc/hosts`. DNS-01 makes the cert valid regardless of the A record.

## One-time setup

1. **Config files.** From the repo root:
   ```sh
   cp .env.staging.example .env            # then edit: HYPROXY_DOMAIN, HYPROXY_ISSUER,
                                           # HYPROXY_ADMIN_UI_ORIGIN, POSTGRES_PASSWORD
   ```
   Create the DNS-provider secret file (root-owned, 0600). For GoDaddy:
   ```sh
   sudo install -d -m 0700 /etc/hyproxy
   sudo tee /etc/hyproxy/acme.env >/dev/null <<'EOF'
   HYPROXY_DOMAIN=friskiemar.com
   ACME_EMAIL=you@friskiemar.com
   LEGO_DNS_PROVIDER=godaddy
   GODADDY_API_KEY=<key from https://developer.godaddy.com/keys>
   GODADDY_API_SECRET=<secret>
   DP_TLS_GROUP=hyproxy
   EOF
   sudo chmod 600 /etc/hyproxy/acme.env
   ```

   > **GoDaddy API access caveat.** GoDaddy restricts its Domains API to accounts
   > that meet a threshold (historically 10+ domains or an eligible plan). A
   > smaller account often gets `403 ACCESS_DENIED` from lego's `godaddy`
   > provider. If that happens, either delegate just the ACME challenge by adding
   > a `CNAME` for `_acme-challenge.<host>.friskiemar.com` to a provider whose API
   > works (e.g. acme-dns or Cloudflare) and point lego there, or run a one-off
   > manual challenge (`lego --dns manual ... run`) placing the TXT record by
   > hand. Both keep the domain on GoDaddy.

2. **Issue the cert** (use the ACME staging CA once to dry-run, then real):
   ```sh
   sudo ACME_STAGING=1 deploy/acme/obtain-cert.sh   # untrusted, proves the DNS-01 flow
   sudo deploy/acme/obtain-cert.sh                  # real Let's Encrypt cert
   sudo cp deploy/acme/hyproxy-acme.{service,timer} /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now hyproxy-acme.timer
   ```
   Certs install to `DP_TLS_CERT` / `DP_TLS_KEY` (default `/etc/hyproxy/certs/`).

3. **Render the data-plane config** (reads `.env`):
   ```sh
   set -a && . ./.env && set +a
   deploy/render-dataplane-config.sh        # writes dataplane/config.json
   ```
   Add any app backends to the `routes` object afterwards (or via `APP_ROUTES_JSON`).

4. **Bootstrap** (builds images with the issuer baked into the SPA, migrates,
   creates the first admin + the admin-ui client):
   ```sh
   set -a && . ./.env && set +a
   ADMIN_EMAIL=admin@friskiemar.com ADMIN_NAME="Staging Admin" \
   ADMIN_UI_REDIRECT="$HYPROXY_ADMIN_UI_ORIGIN/callback" \
   ./bootstrap-prod.sh
   ```

## Every start

```sh
./start-prod.sh          # compose control plane + baremetal data plane (foreground)
```
For persistence, install the data-plane unit instead of the foreground script:
```sh
sudo useradd --system --user-group hyproxy 2>/dev/null || true
sudo cp deploy/systemd/hyproxy-dataplane.service /etc/systemd/system/
# edit WorkingDirectory/paths to your deploy location, then:
sudo systemctl daemon-reload && sudo systemctl enable --now hyproxy-dataplane
```

## First login

From a LAN browser:

1. `https://idp.HYPROXY_DOMAIN/auth/login` — sign in as the admin with the
   one-time password printed by `bootstrap-prod.sh`.
2. Enroll **two** passkeys at `/auth/enroll/webauthn` (admin tier requires two).
3. Use the admin UI at `https://admin.HYPROXY_DOMAIN`.

## Verify

- `curl https://idp.HYPROXY_DOMAIN/.well-known/openid-configuration` → 200,
  valid LE chain, `issuer == https://idp.HYPROXY_DOMAIN`.
- Unknown Host → `421 Misdirected Request` from the data plane.
- Admin UI loads, OIDC login (PKCE + DPoP) completes, a mutation triggers the
  WebAuthn step-up redirect.
- `docker compose -f docker-compose.yml --profile app ps` healthy;
  `systemctl status hyproxy-acme.timer` active; force a dry renewal with
  `sudo lego ... renew --days 90` and confirm the data plane serves the new cert
  without a restart (hot-reload).

## Differences from production (`docs/production.md`)

- LAN-only; nothing internet-facing, no DDNS, no public 443.
- Admin plane fronted through the (LAN-bound) data plane for convenience; in
  prod it stays loopback + WireGuard only.
- File secrets backend (master key on disk). Migrate to TPM before exposure.
- guac bridges and off-box log shipping are available but not enabled here.
