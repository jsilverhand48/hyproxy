# hyproxy rollout: remaining phases (3 to 5)

This file is the working instruction set for the phases still to build. Phases 1
(control plane + self-built OIDC IdP) and 2 (policy engine + ext-authz + Go data
plane) are complete and covered by `docs/security-notes.md`. Each phase below is
written so it can be picked up cold: goal, the seams already left for it, an
ordered milestone list with a verifiable exit check per milestone, and the
security invariants that must hold. Spec references are to the v4 MVP spec.

Global constraints that apply to every phase (do not relax):

- No hand-rolled crypto. Vetted primitives only (joserfc, argon2-cffi, pyotp,
  py_webauthn, WebCrypto in the browser, Go stdlib crypto).
- The management plane (admin API + admin UI) is never internet-facing. It binds
  loopback and is reached over LAN/WireGuard only (`docs/admin-access.md`).
- `/authz/check` and the admin API have no client-facing exposure; segment them.
- Fail closed everywhere: an unreachable control plane refuses the request.
- Quality gates stay green: ruff, mypy --strict, bandit, pip-audit for Python;
  gofmt, go vet, fuzzers for Go; `npm run lint` + typecheck + build for the UI.

---

## Phase 3: React admin UI + audit / policy-change viewers (IN PROGRESS)

Goal (spec section 10): a React admin UI for users, roles, resources, and
policies, plus audit and policy-change viewers, kept off the internet. Spec
section 9 fixes the UI stack as React.

### Auth model (the load-bearing decision)

The admin API is a DPoP-bound resource server that runs the same
`sessions.check_request` contract as every other resource consumer (JWT + DPoP
proof + session liveness + source-IP binding), and requires a fresh WebAuthn
step-up for mutations. The UI therefore cannot be a naive fetch client with a
bearer token. It is a first-class OIDC public client:

- The SPA is registered as its own `oauth_clients` row (`admin-ui`), public
  client, `require_dpop = true`, redirect_uri on the admin origin.
- The browser generates a NON-EXTRACTABLE P-256 DPoP key via WebCrypto and
  persists it in IndexedDB (reuse `idp/web/static/js/dpop.js` verbatim; it
  already survives the redirect dance). It runs authorization code + PKCE (S256)
  against the IdP, exchanges the code at the IdP token endpoint WITH a DPoP
  proof, and then calls the admin API with `Authorization: DPoP <access>` plus a
  fresh per-request proof.
- The SPA build is served BY the admin FastAPI app, so admin origin == admin API
  origin and every `/api/v1/*` call is same-origin (no CORS on the API surface).
- The only cross-origin browser call is the token exchange (and optional
  userinfo) to the IdP origin. Add a NARROW CORS allowance on the IdP scoped to
  the configured admin-ui origin, methods `POST` (token) / `GET` (jwks,
  userinfo), allowed request headers `authorization, dpop, content-type`. Never
  wildcard; never allow credentials (the flow is bearer/DPoP, not cookie).
- Step-up: `step_up_verified_at` lives on the IdP session that the access
  token's `sid` claim points to. The SameSite=Lax IdP session cookie is NOT sent
  on cross-origin fetch, so step-up cannot be an XHR from the SPA. Instead, on a
  403 `stepup_required` the SPA does a TOP-LEVEL navigation to an IdP step-up
  page (`/auth/stepup?return_to=<spa-url>`); the Lax cookie rides the top-level
  request, the page runs the WebAuthn assertion (reuse `webauthn.js`), sets
  `step_up_verified_at`, and 302s back to a validated `return_to`. The SPA then
  retries the mutation. `return_to` MUST be validated against the registered
  admin-ui redirect origin (open-redirect defense identical to the gateway's).

### Milestones

M1. Viewer API (backend, fully testable now). Add read-only, admin-tier,
    paginated endpoints under the admin API:
    - `GET /api/v1/audit/access` over `audit_log` (data-plane decisions):
      filters `user_id`, `resource_id`, `decision`, `since`, `until`; keyset
      pagination on `(ts, id)` desc; hard page-size cap (<=200).
    - `GET /api/v1/audit/auth` over `auth_events`: filters `user_id`,
      `event_type`, `success`, `since`, `until`; same pagination.
    - `GET /api/v1/policy-changes` over `policy_changes`: filters `actor_id`,
      `entity_type`, `entity_id`; returns actor email joined, before/after JSON.
    All three are reads: guard with `AdminDep` (not `StepUpDep`). Add `*Out`
    schemas and a shared `Page[T]` envelope (`items`, `next_cursor`). Never leak
    secrets: these tables are already whitelist-detail by construction, but the
    schema must still project explicit fields, not the ORM row.
    EXIT: integration tests seed rows and assert filter + pagination + tier gate
    (standard-tier token 403); `make check` green.

M2. IdP support for the SPA client.
    - `create-client` a public `admin-ui` client (document exact command).
    - Add the narrow CORS middleware on the IdP (config-driven allowed origin
      `HYPROXY_ADMIN_UI_ORIGIN`, empty by default = disabled).
    - Add `GET /auth/stepup` HTML page + `return_to` validation helper shared
      with the gateway's return-URL check.
    EXIT: a scripted browserless test drives authorize -> token (DPoP) ->
    admin API call end-to-end against the admin-ui client; CORS preflight unit
    test; `return_to` open-redirect negatives.

M3. SPA scaffold. Vite + React + TypeScript under `ui/`. Node 26 / npm 11 are
    present (pnpm/bun are not). Strict TS, ESLint, no runtime state library
    beyond React Query (or hand-rolled fetch hooks) to keep the bundle small and
    the CSP tight (no eval). Vendor `dpop.js` / `webauthn.js` from the IdP as ES
    modules (single source of truth: copy in a build step, do not fork).
    EXIT: `npm run build` produces a hashed-asset bundle; `npm run lint` clean.

M4. SPA auth core. `auth.ts`: PKCE + DPoP authorization code flow, token store
    (access in memory, refresh via rotation, DPoP key in IndexedDB), silent
    refresh, and the step-up redirect dance. `api.ts`: a fetch wrapper that
    attaches `Authorization: DPoP` + a fresh proof per call, transparently
    handles 401 (re-auth) and 403 stepup_required (step-up redirect + retry).
    EXIT: manual login in a browser reaches an authenticated shell; token
    refresh and a mutation-triggered step-up both work.

M5. SPA views. Tables + forms for users, roles, user-role assignment,
    resources, policies (full CRUD wired to the existing endpoints), and
    read-only viewers for access audit, auth events, and policy changes (filter
    controls + keyset "load more"). Mutations surface the step-up flow. Client
    validation mirrors the Pydantic schemas but the server remains authoritative.
    EXIT: every admin API endpoint is reachable from the UI; error/empty/loading
    states handled.

M6. Serve + appsec + docs. Mount the built SPA from the admin app with an SPA
    fallback route; apply a strict CSP (`default-src 'none'`, `script-src
    'self'`, `connect-src 'self' <idp-origin>`, `frame-ancestors 'none'`,
    `base-uri 'none'`) plus nosniff / Referrer-Policy / X-Frame-Options; the
    admin app stays loopback-bound. Makefile targets `ui-install`, `ui-build`,
    `ui-dev`, `run-admin` serving the build. Update `README.md`,
    `docs/admin-access.md`, `docs/security-notes.md` (new "Phase 3" section:
    admin-ui client, CORS scope, step-up redirect, CSP, connect-src to IdP).
    EXIT: `make ui-build && make run-admin`, log in over loopback, exercise CRUD
    + a step-up mutation + the viewers in a real browser.

### Phase 3 security invariants

- The admin UI holds NO long-lived secret the API trusts; every call is DPoP
  bound to a browser key that never leaves the device.
- The admin API keeps enforcing tier from the frozen session value and step-up
  freshness server-side; the UI's checks are UX only.
- CORS on the IdP is a single explicit origin, no wildcard, no credentials.
- `return_to` / redirect targets are allowlist-validated (open-redirect safe).
- No inline scripts; CSP has no `unsafe-inline` / `unsafe-eval`.

---

## Phase 4: Guacamole browser bridges (RDP / VNC / SSH) — MOSTLY BUILT

Goal (spec section 10): browser-only access to non-HTTP resources (RDP, VNC,
SSH) via Apache Guacamole, fronted by the same identity-aware proxy so the same
login, policy, DPoP session, and audit path apply. The `resources.protocol`
enum already admits `tcp/vnc/rdp/ssh`; Phase 4 makes those resources reachable.

Architecture (decided): guacamole-lite (Node) tunnel. The browser (guacamole-
common-js) opens a WebSocket to the Go data plane, which forward-auths + single-
use-consumes the grant and reverse-proxies the WebSocket to the loopback Node
`tunnel/` service, which decrypts the broker token and speaks guacd.

Status as of this writing (all tested unless noted):
- M1 connection model + sealing + admin CRUD: DONE. `resource_connections`
  (sealed secrets, write-only), migration, `PUT/GET/DELETE
  /api/v1/resources/{id}/connection`.
- M2 broker: DONE. `hyproxy/guac/{token,connections,broker}.py`, guacamole-lite
  AES-256-CBC token codec, policy-checked mint, `guac_grants` (short-lived,
  single-use, IP + owner bound), audit. Endpoints `POST /guac/token` and
  internal `POST /guac/consume` in the authz service.
- M3 data-plane wiring: DONE. `"guac_tunnel": true` routes, `ConsumeGuac` client,
  WebSocket proxy, fail-closed; auth host exposes `/guac/token` only (consume is
  internal). Go tests cover allow/deny/503/missing-token and the allowlist.
- M4a Node tunnel service (`tunnel/`, guacamole-lite): DONE (builds, boots,
  serves healthz). guacd itself is a native daemon, absent on the dev machine.
- M4b in-browser client (2026-07-16): DONE. SPA connect view
  (`ui/src/views/Connect.tsx` at `/connect/:resourceId`, guacamole-common-js)
  mints at `POST /guac/token` (CORS on the authz app for the SPA origins;
  connect-src widened to the auth host + `wss://*.<domain>`) and opens
  `wss://<public_host>/?token=...`; portal links guac resources to the connect
  view; admin Resources view gained a Connection editor over
  `/resources/{id}/connection`. Tunnel allows client display params
  (width/height/dpi/audio/image/timezone) only. Deployed to prod with the
  guacd + tunnel compose profile.
- REMAINING: the guacd network-segmentation runbook and tunnel-creation rate
  limiting.

### Seams already in place

- `resources` rows carry protocol + host + ports; policies already gate roles
  against resources with port/path/time conditions.
- The data plane has a pluggable listener seam (spec section 12) and Host
  routing; a Guacamole tunnel endpoint is another routed backend, not a redesign.
- `sessions.check_request` / `/authz/check` already produce an authorization
  decision + identity headers per request; the tunnel broker reuses it.

### Milestones

M1. Connection model. Add a `resource_connections` table (or extend
    `resources`) holding per-resource Guacamole connection parameters
    (protocol-specific: hostname, port, and a reference to credentials sealed via
    the SecretsBackend, never plaintext). Admin API CRUD + UI form (extends
    Phase 3). Credentials are AES-256-GCM enveloped like TOTP secrets; the UI
    write-only-masks them.

M2. Broker service. A control-plane component that, given an authenticated +
    policy-allowed user and a target resource, mints a short-lived, single-use
    Guacamole tunnel authorization (guacamole-lite / guacd token) with the
    resolved connection params. It NEVER exposes raw connection credentials to
    the browser; the browser gets an opaque tunnel token only. Every brokered
    session writes an `audit_log` row (user, resource, decision, source_ip).

M3. guacd + tunnel. Stand up guacd (containerless-dev: document the process;
    prod: a segmented host) and a WebSocket tunnel endpoint fronted by the data
    plane on the single public port (a new route + listener path). The tunnel is
    forward-authed on connect AND the session is re-checked (liveness / IP
    binding) so revoking the IdP session tears down the live tunnel.

M4. Browser client. Guacamole's web client (guacamole-common-js) embedded in the
    Phase 3 UI as a resource "connect" view. It authenticates the same way
    (DPoP session), opens the WebSocket tunnel, and renders the remote display.
    Clipboard / file-transfer / audio gating is policy-driven and off by default.

M5. Hardening + docs. Idle/absolute TTLs also tear down tunnels; per-protocol
    input sanitation; rate-limit tunnel creation; security-notes section on the
    guacd trust boundary and credential sealing. Fuzz any new host/target parser.

### Phase 4 security invariants

- Remote-resource credentials are sealed by the SecretsBackend and never reach
  the browser; the browser only ever holds an opaque, short-lived tunnel token.
- Tunnel authorization is a policy decision at connect time AND re-validated for
  liveness so IdP-session revocation kills active tunnels.
- guacd is on a segmented network path reachable only from the broker.
- No new client-controlled dial target (SSRF invariant holds: targets come from
  `resources`, never from request input).

---

## Phase 5: Internet exposure hardening (DDNS, ACME, TPM broker, off-box logs, final security review) — CORES BUILT

Goal (spec section 10 / 11): everything required before the single public port
faces the internet. Nothing here changes application behavior; it replaces
dev-only stand-ins with production-grade infrastructure behind the seams already
built, then runs the dedicated security review.

Status (software cores built + tested; infra is deployment, see
`docs/production.md`):
- M1 TPM broker: `TpmSecretsBackend` adapter (unseal isolated, unit-tested) +
  `HYPROXY_SECRETS_BACKEND` selector + master-key rotation (`core/reencrypt.py`,
  `rotate-master-key`, integration-tested). The `tpm2_unseal` wiring is a
  documented deployment hook (needs a TPM, absent here).
- M2 ACME DNS-01: seam only (data-plane cert hot-reload already exists). Use a
  vetted client (lego/certbot); do not hand-roll ACME. Documented.
- M3 DDNS: decision core (`ops/ddns.py`, unit-tested); provider adapter is
  deployment. Documented.
- M4 off-box logging: shipper (`audit/shipping.py`, `ship-logs`, cursor table)
  + severity classification, tested. Syslog/OTLP forwarder + SIEM alerts are
  deployment. Documented.
- M5 production posture + final review: `docs/production.md` checklist; the
  review itself is a process to run before exposure.

### Seams already in place

- `SecretsBackend` protocol (`core/secrets.py`): `FileSecretsBackend` is the
  dev stand-in; the TPM broker is a drop-in implementation, no call-site changes.
- Data-plane TLS `GetCertificate` hot-reload seam (`internal/tlsconf`): the ACME
  slot. Certs swap without a restart.
- All audit tables (`auth_events`, `audit_log`, `policy_changes`) already exist
  and are written transactionally; off-box shipping is a consumer, not a schema
  change.

### Milestones

M1. TPM secrets broker. Implement `TpmSecretsBackend` satisfying the protocol:
    the master key is sealed to the TPM (PCR policy), unsealed at process start
    into memory only. Config selects the backend; `FileSecretsBackend` stays for
    dev. Verify: a re-encrypt/rotate path so existing ciphertext (TOTP secrets,
    signing keys) migrates from the file master key to the TPM-sealed key.
    EXIT: on a TPM host, all envelope decrypts succeed with the file backend
    disabled; key material never touches disk unsealed.

M2. ACME DNS-01. A control-plane cert manager obtains and renews Let's Encrypt
    certificates via DNS-01 (works behind CGNAT and for wildcard app subdomains),
    writing the cert/key so the data plane's `GetCertificate` picks them up
    live. DNS provider credentials are sealed via the SecretsBackend. Renewal is
    scheduled with a safety margin; failures alert (see M4).
    EXIT: issue + a forced renewal rotate the live cert with zero downtime;
    staging directory first, then production.

M3. DDNS. A dynamic-DNS updater keeps the public A/AAAA (or CNAME target) current
    for the home IP; runs on a timer, is idempotent, and backs off on provider
    errors. Coordinates with ACME DNS-01 on the same provider credentials.
    EXIT: simulated IP change propagates within the TTL; no update storm.

M4. Off-box logging + alerting. Ship `auth_events`, `audit_log`, and
    `policy_changes` to an external collector (syslog/OTLP to a host the proxy
    cannot delete from), append-only, with alerts on high-severity events
    (`login.break_glass.used`, `oidc.refresh.reuse_detected`, throttle spikes,
    ACME/DDNS failures). Clock/NTP monitoring (TOTP + token expiry depend on it).
    EXIT: a break-glass login and a forced refresh-reuse both alert off-box.

M5. Production posture + final security review. Enforce backend TLS verification
    (no insecure skip-verify) with an internal CA pin; verify the IdP backchannel
    uses a verified endpoint (retire `idp_verify_tls=false`); network
    segmentation for admin API, `/authz/check`, guacd; then run the dedicated
    security review against `docs/security-notes.md`, close findings, and only
    then expose the public port.
    EXIT: review sign-off; bandit + pip-audit + go vet + fuzz corpora clean;
    every dev-only accepted risk in security-notes has a production resolution.

### Phase 5 security invariants

- The master key is TPM-sealed in production; no unsealed key material on disk.
- Certificates rotate live via the existing hot-reload seam; private keys are
  sealed at rest.
- Audit is append-only off-box; the proxy host cannot tamper with shipped logs.
- Backend connections verify TLS against a pinned internal CA before any https
  backend is enabled.
- The public port is exposed only after the security review signs off.
