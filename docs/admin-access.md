# Management-Plane Access and Break-Glass Runbook

The admin API (port 8400) and the admin UI are management-plane services.
The management endpoints are never internet-facing. This document describes
the only supported ways in, and the recovery paths when normal access is
impossible.

One deliberate exception: the same app also serves the standard-user portal
(`/api/v1/portal` plus the SPA) on a second, internet-facing host configured
via `HYPROXY_PORTAL_ORIGIN` and a non-`lan_only` data-plane route (see
`dataplane/config.example.json`, `apps.example.com`). Portal endpoints
authenticate with the same DPoP-bound tokens but skip the LAN check; every
management endpoint keeps `require_admin` (LAN CIDR check + admin tier), so
the split origin does not widen management-plane exposure. Portal review
actions (approving or denying standard users' download requests) require an
admin-tier login but, unlike management mutations, no WebAuthn step-up,
because the step-up flow returns to a fixed origin per request and the action
set is narrow. The portal's qBittorrent integration is configured with
`HYPROXY_QBIT_URL` and `HYPROXY_QBIT_SAVEPATH_ALPHA`/`_BRAVO`; the qBittorrent
WebUI must IP-whitelist the hyproxy host (no credentials are sent).

Enabling the portal origin also requires registering the second redirect URI
on the SPA's OAuth client (`hyproxy create-client` upserts and REPLACES the
URI list, so pass both `--redirect-uri` values).
The WireGuard tunnel and break-glass hardware are set up manually by the
operator; nothing in this repository automates them by design.

## Network paths to the management plane

1. LAN: the admin API binds to loopback on the control-plane host
   (`make run-admin` binds 127.0.0.1:8400). Reach it from the LAN via SSH port
   forwarding or run it bound to a LAN-only interface behind the host firewall.
2. Out-of-band WireGuard: a WireGuard peer config terminating ON THE HOST
   (not behind the reverse proxy) so the admin path works even when the data
   plane or IdP is down. This is the primary remote-admin path.

Requirements for the WireGuard path:

- The WireGuard endpoint must not depend on the reverse proxy, the IdP, or
  DNS names served by the DDNS updater. Use the raw WAN IP plus a static
  fallback note in the offline runbook, or a secondary DNS name updated
  independently.
- Restrict the peer allowed-IPs to the management addresses and port 8400
  (plus SSH if desired). The tunnel is an admin path, not a general VPN.
- Keep a copy of the WireGuard client config on the FIPS device (see below).

## Authentication on the management plane

Reaching port 8400 over the network is necessary but not sufficient. Every
admin API request requires:

- a DPoP-bound access token from the IdP for an admin-tier user
  (password + WebAuthn login), and
- for any mutation, a WebAuthn step-up assertion no older than 5 minutes.

The admin UI (served by the admin app from `ui/dist`) authenticates the same
way: it is an OIDC public client with a browser-held non-extractable DPoP key,
so reaching it still requires the network path above plus an admin-tier login,
and mutations still trigger the WebAuthn step-up. Run the admin app with
`HYPROXY_ADMIN_UI_ORIGIN` set to the UI origin (loopback in dev) to enable the
IdP CORS allowance and the step-up return target; leave it empty to serve the
API alone. The UI adds no new network exposure: it lives entirely on the
management plane.

## Break-glass credential

- Each admin enrolls at least two non-break-glass passkeys (primary +
  backup, enforced by the admin API) plus one break-glass credential: a
  WebAuthn credential on a FIPS-validated hardware key, enrolled during
  provisioning with the "break-glass" flag, then stored offline in a safe.
- Server-side it is verify-only and cryptographically indistinguishable from
  any other credential; its use additionally emits the high-severity
  `login.break_glass.used` audit event. Treat any such event that you did not
  cause as an active incident.
- There are NO email, SMS, or security-question reset paths anywhere in the
  codebase, deliberately. Softer recovery would become the real attack
  surface.

## Recovery scenarios

- Standard user lost TOTP device: they use a one-time recovery code at
  `/auth/recovery`, which forces re-enrollment of a new authenticator, or an
  admin calls `POST /api/v1/users/{id}/reset-totp` (step-up required), which
  drops the secret and unused codes and revokes their sessions.
- Admin lost primary passkey: sign in with the backup passkey, enroll a
  replacement, delete the lost credential (the API refuses to drop an active
  admin below two strong passkeys, so enroll first, then delete).
- Admin lost ALL day-to-day passkeys: retrieve the break-glass key from the
  safe, sign in (expect the audit alarm), enroll fresh passkeys, return the
  break-glass key to the safe. If the break-glass key is also gone, recovery
  is via the host itself over WireGuard/console: `bootstrap-admin` a new
  admin account and disable the compromised one.
- IdP down entirely: WireGuard to the host, fix the service. The admin path
  never depends on the IdP being healthy.

## Offline kit (on/with the FIPS device)

- The break-glass hardware key (PIN-protected).
- WireGuard client config for the out-of-band tunnel.
- The secrets-broker recovery key (Phase 5; see spec section 8a).
- A printed copy of this runbook.
