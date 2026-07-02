# Phase 1 Security Notes (input to the dedicated security review)

Running record of the security-relevant decisions, invariants, and accepted
risks in the Phase 1 codebase (control plane + self-built OIDC IdP). Spec
references are to the v4 MVP specification.

## Cryptography and storage

- All JOSE operations via joserfc; argon2id via argon2-cffi; TOTP via pyotp;
  WebAuthn via py_webauthn. No hand-rolled primitives anywhere.
- Passwords and recovery codes: argon2id (verify-only, low entropy).
- Auth codes, refresh tokens, session cookie secrets: SHA-256 of full-entropy
  random values; plaintext never stored (`core/crypto.py`).
- TOTP secrets and OIDC signing private keys: AES-256-GCM under a master key
  from the SecretsBackend protocol, table name as AAD, ciphertext stored with
  the encrypting key id (`core/secrets.py`, `core/crypto.py`). The Phase 5
  TPM broker replaces FileSecretsBackend behind the same protocol.
- Signing keys: ES256/P-256, publish-overlap-retire lifecycle with a partial
  unique index enforcing exactly one active key (`core/keys.py`).

## OIDC / OAuth invariants (enforced + tested)

- authorize validation order: client_id, then byte-exact redirect_uri, both
  failing to a LOCAL page; only then redirect-based errors. state (16..512)
  and nonce required; PKCE S256 only, `plain` rejected.
- Auth codes: 60s TTL, single-use via conditional UPDATE; replay of a
  consumed code revokes the issuing session and emits
  `oidc.code.replay_detected`.
- PKCE: S256 constant-time compare; verifier charset/length per RFC 7636.
- DPoP (RFC 9449): ES256-only allowlist; embedded JWK must be a public P-256
  key with no private members and no kid/x5c trust shortcuts; htm/htu
  normalization per RFC; iat window 300s past / 30s future; ath binding on
  resource calls; RFC 7638 jkt binding; per-jkt jti replay cache in Postgres.
- Sessions pin their DPoP key at first token exchange (immutable after);
  refresh proofs must match the family's jkt.
- Refresh rotation: single-use tokens, family-tracked; reuse revokes the
  family AND the session; family expiry capped at the session's 6h absolute
  bound.
- Every resource-side consumer runs `sessions.check_request`: JWT signature
  (active+retiring kids), iss/exp, DPoP proof + ath + jkt, then a session
  liveness lookup (revoked/stale/absolute/idle/IP-binding). Revocation is
  therefore immediate despite JWTs.
- Revocation endpoint requires a proof with the token's bound key, so leaked
  token strings cannot be used for third-party revocation DoS; unknown tokens
  still return 200 (no validity oracle).

## Authentication tiers and login flow

- `users.auth_tier` is first-class and drives the second factor at login
  time; no request parameter can select the method; admins are never offered
  TOTP (enrollment endpoints reject admin-tier users).
- Login flow is a server-side state machine (login_flows) bound to source IP
  and a `__Host-` cookie, with per-flow rotating CSRF tokens (hash stored).
- Unknown-user password attempts burn a dummy argon2 verify (timing).
- WebAuthn bootstrap enrollment during login is allowed only while the user
  has no credential predating the flow; otherwise a password-only attacker
  could enroll their own authenticator.
- Step-up: sensitive admin actions need a WebAuthn assertion within the last
  5 minutes regardless of session age.
- Recovery codes: ~50 bits, shown once, argon2id-hashed, batch-invalidated;
  use forces TOTP re-enrollment before login completes. No email/SMS paths.

## Session hardening

- Source-IP binding: IP change marks the session stale and everything
  (cookie, access token via check_request, refresh) fails until full re-auth.
- Layered TTLs: access 10 min; refresh family absolute 6h; idle 30 min
  (enforced at cookie use, resource calls, and refresh); step-up 5 min.
- Progressive delays, never lockout: account scope 3 free failures then
  2^n capped 60s; IP scope 10 free then capped 30s; checks run before
  credential evaluation to bound argon2 spend.

## Web appsec

- CSP `default-src 'none'` with explicit self allowances, no inline scripts;
  nosniff; Referrer-Policy no-referrer; X-Frame-Options DENY; HSTS;
  Cache-Control no-store on the auth surface (JWKS keeps its max-age).
- Cookies: `__Host-` prefix, Secure, HttpOnly, SameSite=Lax.
- JSON endpoints (WebAuthn/step-up) rely on SameSite + JSON content type;
  cross-origin HTML forms cannot produce these requests.

## Audit

- auth_events written in the same transaction as the state change they
  describe; detail is whitelisted-keys-only and never carries secrets
  (enforced by tests). Admin mutations write policy_changes with actor and
  before/after. Off-box shipping is Phase 5.

## Accepted residual risks (spec-acknowledged)

- TOTP tier is phishable via AITM relay; a relayed login yields the attacker
  a DPoP-bound session on their device. Accepted for standard users at this
  user count; admins are WebAuthn-only (origin-bound, phishing-resistant).
- Roaming users re-authenticate on public-IP change (deliberate tradeoff).
- Dev-only FileSecretsBackend keeps the master key on disk (chmod 600);
  replaced by the TPM broker in Phase 5 before internet exposure.
- The `sub` claim uses users.external_id; deleting a user cascades their
  sessions/tokens immediately.

## Items for the reviewer to probe

- login_flows lifecycle: expiry, IP binding, stage transitions, CSRF rotation.
- check_request htu handling on the admin API (uses the request URL; the
  admin plane is never behind a proxy by policy).
- Throttle race behavior under concurrent failures (row-locked upsert).
- GC coverage: dpop_jti_seen and retiring keys via `hyproxy.cli gc`
  (cron it); login_flows and expired auth_codes rely on natural expiry checks
  but rows should also be GC'd eventually (cosmetic, not security).

## Not in Phase 1 (tracked for later phases)

- Off-box log shipping and alerting (Phase 5).
- TPM-backed secrets broker (Phase 5).
- NTP monitoring (deployment concern; TOTP and token expiry depend on it).

# Phase 2 Security Notes (data plane + policy engine)

## Policy engine (`hyproxy.policy.engine`)

- Pure functions over dataclasses; no ORM. Decision order: among applicable
  rules (enabled, matching resource, role held, port/path/time conditions
  satisfied) an explicit deny always wins; absent an applicable allow, default
  deny. Verified by Hypothesis properties: deny never overridden, allow
  requires an applicable allow and no deny, default-deny holds for unmatched
  requests, and disabled rules never change the outcome.
- Path matching is segment-aware (`/web` matches `/web` and `/web/x`, not
  `/webby`). Time windows are UTC, support midnight crossing, and fail closed
  on malformed input.

## ext-authz decision point (`/authz/check`)

- The single authorization decision point for the data plane; transport
  agnostic (spec section 2/5). Internal-only: never expose /authz/check to
  clients (the data plane only proxies the auth host's /gateway/* paths to
  this service, nothing else).
- Resolves the routing key (Host) to a registered, enabled resource
  `public_host`; unknown hosts are denied without touching any backend.
- No live gateway session -> `auth_required` with a redirect to the gateway
  login (open-redirect-safe: the return URL host must itself be a registered
  resource; only https is accepted).
- Every decision writes an `audit_log` row (user, resource, port, decision,
  reason, source_ip) in the same transaction.
- Identity headers returned to the data plane: X-Forwarded-User (email),
  X-Auth-User-Id (external_id), X-Auth-Roles (comma-joined role names).

## Gateway RP (the data plane's OIDC client)

- Server-side DPoP key derived deterministically from the master key via HKDF
  (stable jkt across restarts, nothing on disk). This is the one RP whose DPoP
  key is server-side; browser RPs keep theirs in WebCrypto.
- /gateway/start parks a single-use, IP-bound, 10-min state (PKCE verifier +
  nonce + validated return URL) and redirects to the IdP authorize endpoint.
- /gateway/callback exchanges the code with a DPoP proof, verifies the access
  and ID tokens against the shared signing keys, checks the ID-token nonce,
  and links a gateway session to the underlying IdP session. Liveness,
  revocation, source-IP binding, idle and 6h absolute bounds are all inherited
  from the IdP session on every /authz/check, so revoking the IdP session
  immediately cuts data-plane access (covered by the cross-plane E2E).
- Gateway cookie is `__Secure-` prefixed, Secure/HttpOnly/SameSite=Lax; its
  Domain must be the parent of all app subdomains so it is presented to every
  resource (dev/E2E use `.home.test`). `__Host-` is not usable here precisely
  because a Domain is required.

## Go data plane

- Single public port, TLS termination (1.2 floor, 1.3 preferred) with a
  GetCertificate hot-reload seam (the ACME slot for Phase 5). Pluggable
  listener interface (spec section 12) so a future raw-L4 transport is a new
  listener, not a redesign.
- Host normalization (lowercase, strip port/trailing dot, DNS-label
  validation, IPv6 literals rejected since IPv6 is disabled at the edge) is
  the sole attacker-controlled parser and is fuzzed (FuzzNormalizeHost);
  unknown/hostile hosts get 421 with an empty body (reveal nothing, route
  nowhere).
- SSRF invariant: backends come only from the static config route table keyed
  by normalized Host; the dial target is never derived from client input
  (request target, path, or headers). Tested.
- Identity-header hygiene: X-Forwarded-User / X-Auth-User-Id / X-Auth-Roles
  are stripped from every inbound request unconditionally before anything
  else, then set only from the authz allow response. X-Forwarded-* is rebuilt
  by the proxy (no inbound spoof passthrough). The gateway cookie is removed
  from the upstream Cookie header so backends never see gateway credentials.
- Fail closed: if the control plane is unreachable, the request is refused
  (503), never proxied.
- auth_required is a 302 to the gateway only for safe (GET/HEAD) navigations;
  other methods get 401 so non-idempotent requests are not silently bounced.

## Phase 2 accepted risks / reviewer items (continued below with Phase 3)

- The data plane trusts the network path to the authz service (loopback or a
  private segment); /authz/check has no auth of its own by design and must
  never be reachable from clients. Enforce with network segmentation
  (spec section 11) plus the auth-host path allowlist already in the proxy.
- The gateway backchannel to the IdP uses `idp_verify_tls=false` only for the
  dev self-signed cert; production must verify (internal CA) or use a verified
  endpoint.
- Backend re-encryption/verification (spec section 11: no insecure skip
  verify) is a deployment concern for https backends; the proxy dials whatever
  scheme the route specifies. Pin/trust internal CA before enabling https
  backends.
- gc now also clears expired gateway_login_states.

# Phase 3 Security Notes (admin UI + audit/policy viewers)

## Admin UI auth (browser-held DPoP, no server-trusted UI secret)

- The React admin UI is an OIDC public client (`admin-ui`), not a bearer-token
  app. It generates a NON-EXTRACTABLE P-256 DPoP key in WebCrypto (IndexedDB,
  survives reloads), runs authorization code + PKCE (S256), exchanges the code
  at the IdP token endpoint with a DPoP proof, and calls the admin API with
  `Authorization: DPoP <token>` plus a fresh proof per request. Every admin API
  call therefore runs the same `check_request` contract as any resource
  consumer (JWT + DPoP + session liveness + source-IP binding); a stolen token
  is useless without the browser key.
- The access token lives in memory only (never localStorage/sessionStorage);
  only the OIDC flow's PKCE verifier/state/nonce sit in sessionStorage for the
  duration of the redirect. On reload the app silently re-runs authorize, which
  the live IdP session cookie completes without a fresh login.

## Same-origin API, single-origin CORS

- The built SPA is served BY the admin app, so `/api/v1/*` is same-origin and
  needs no CORS. The only cross-origin browser call is the token exchange to
  the IdP; the IdP adds a CORS allowance for EXACTLY one configured origin
  (`HYPROXY_ADMIN_UI_ORIGIN`), methods GET/POST/OPTIONS, request headers
  `authorization, dpop, content-type`, and `allow_credentials=False` (the flow
  is bearer/DPoP, never cookie). Empty origin disables CORS entirely.

## Step-up over a validated top-level redirect

- `step_up_verified_at` lives on the IdP session the access token's `sid` points
  to. The SameSite=Lax IdP session cookie is not sent on the SPA's cross-origin
  fetches, so step-up cannot be an XHR. On `403 stepup_required` the SPA does a
  top-level navigation to `GET /auth/stepup?return_to=<current-url>`; the Lax
  cookie rides the top-level request, the page runs a WebAuthn assertion and
  sets `step_up_verified_at`, then 302s back. `return_to` is validated to equal
  the configured admin-UI origin exactly (`valid_stepup_return`): scheme + host
  + port must match, userinfo/scheme smuggling rejected, and an unset admin-UI
  origin accepts nothing. The page also requires a live admin-tier session
  cookie before rendering.

## Viewer endpoints (read-only, admin-tier, projected)

- `/api/v1/audit/access`, `/audit/auth`, `/policy-changes` are admin-tier reads
  (AdminDep, no step-up). They project explicit `*Out` fields, never the ORM
  row, and keyset-paginate on the monotonic BigInteger id (stable under
  concurrent inserts) with a hard page-size cap (<=200). These tables were
  already whitelist-detail by construction (Phase 1/2); the viewers add no new
  secret exposure.

## Web appsec

- The admin app sets a strict CSP: `default-src 'none'`, `script-src 'self'`,
  `style-src 'self'`, `connect-src 'self' <idp-origin>`, `form-action 'self'`,
  `frame-ancestors 'none'`, `base-uri 'none'`. No `unsafe-inline`/`unsafe-eval`;
  the SPA ships hashed self-hosted assets only. nosniff / Referrer-Policy
  no-referrer / X-Frame-Options DENY are set. `connect-src` admits the IdP
  origin solely for the token exchange (authorize/step-up are top-level
  navigations, not connect-src).
- The step-up page and its glue use an external script (`/static/js/stepup.js`)
  under the IdP's existing strict CSP; no inline scripts.

## Phase 3 accepted risks / reviewer items

- The admin app remains loopback/management-plane only (docs/admin-access.md);
  the SPA being same-origin does not change that. HSTS is intentionally NOT set
  on the admin app because dev serves it over http on loopback; production
  behind the WireGuard/TLS front should add it.
- The DPoP browser key is bound to the browser profile (IndexedDB). Clearing
  site data forces a fresh key and re-login; this is expected, not a defect.
- Reviewer items: `valid_stepup_return` origin comparison (port + scheme),
  the CORS allowlist being a single origin with no credentials, and that the
  SPA fallback route never shadows `/api/*` (unknown API paths must 404 as API,
  not return HTML).

# Phase 4 Security Notes (Guacamole browser bridges)

## Connection secrets are sealed and never reach the browser

- Per-resource Guacamole connection parameters live in `resource_connections`.
  Secret parameters (password, private-key, passphrase) are AES-256-GCM sealed
  under the master key with the table name as AAD, exactly like TOTP secrets;
  only the parameter NAMES are stored in cleartext (`secret_keys`). The admin
  API is write-only for secrets: reads return `secret_keys` + `has_secret`,
  never values, and the policy_changes log records names only.
- The broker unseals secrets ONLY at mint time, folds them into the connection
  settings, and encrypts the whole thing into a single guacamole-lite token.
  The browser only ever holds that opaque token; it never sees raw credentials.

## Tunnel tokens are policy-gated, short-lived, single-use, and IP-bound

- `POST /guac/token` (browser-facing via the auth host) requires a live gateway
  session, runs the SAME policy decision path as the data-plane ext-authz check
  (`authz.decision.evaluate_access`, one decision core), and only then mints a
  token. Every decision writes an audit_log row in the same transaction.
- Each mint records a `guac_grants` row: token hash, user, resource, source_ip,
  and an expiry (`HYPROXY_GUAC_GRANT_TTL`, default 60s). The token itself is a
  bearer credential to the remote resource, so the grant bounds its use.
- `POST /guac/consume` is called by the data plane when it forward-auths the
  tunnel WebSocket connect. It re-resolves a LIVE gateway session (so revoking
  the IdP session tears the tunnel down), then atomically consumes the grant:
  valid, unexpired, unconsumed, IP-matched, and owner-matched. It returns allow
  exactly once per token. Expired/consumed grants are GC'd (`hyproxy.cli gc`).

## Trust boundaries and the data plane

- `/guac/consume` is INTERNAL: the data plane's auth-host allowlist exposes only
  `/guac/token` to clients; `/guac/consume` (and `/authz/check`) stay internal.
  Verified by a Go test.
- Guacamole tunnel routes (`"guac_tunnel": true`) are authorized by grant
  consumption, not the per-request policy check (policy was already evaluated at
  mint). The Go handler fails closed (503) if the control plane is unreachable,
  401 on a missing token, 403 on a denied/spent grant. ReverseProxy carries the
  WebSocket upgrade to the loopback Node tunnel; the gateway cookie is stripped
  from the upstream like every other backend.
- The Node guacamole-lite tunnel (`tunnel/`) binds loopback and trusts its
  network path (like the authz service). It decrypts the token with the shared
  cypher key and connects to guacd. guacd must sit on a segmented path reachable
  only from the tunnel.

## Phase 4 accepted risks / reviewer items

- The cypher key is a shared symmetric secret between the broker and the Node
  tunnel (config, not TPM-sealed yet). Rotating it invalidates in-flight tokens
  (acceptable given the 60s TTL). Phase 5 can seal it via the SecretsBackend.
- Source-IP binding on tunnel connect relies on the data plane forwarding the
  real browser IP to `/guac/consume` (body `source_ip`); the same trusted-proxy
  assumption already applies to the gateway path.
- NOT yet built (remaining Phase 4 integration, needs a live guacd, which the
  dev machine lacks): the in-browser guacamole-common-js client page and the
  guacd deployment/segmentation runbook, plus tunnel-creation rate limiting.
  Everything up to and including the data-plane WebSocket authorization is
  implemented and tested; the guacd hop and browser renderer are the remaining
  live-only pieces. See `ROLLOUT.md` Phase 4 for the exact status.

# Phase 5 Security Notes (internet-exposure hardening)

Full runbook in `docs/production.md`. Security-relevant points:

## Master key: TPM sealing + rotation

- The `SecretsBackend` protocol gains a `TpmSecretsBackend` selected by
  `HYPROXY_SECRETS_BACKEND=tpm`. Master keys are unsealed from the TPM into
  memory only; the TPM call is isolated behind an injected `unseal` callable so
  the adapter is unit-tested without hardware, and the real `tpm2_unseal` wiring
  is a documented deployment hook (`core/secrets.tpm_unseal`, currently a clear
  `NotImplementedError`). Invariant: no unsealed key material on disk in prod.
- Master-key rotation (`core/reencrypt.py`, `rotate-master-key`) re-wraps every
  sealed blob (signing keys, TOTP secrets, connection secrets) to the current
  key, decrypt-then-encrypt with the same table-name AAD, in one transaction.
  This is the zero-downtime file->TPM migration path. Integration-tested:
  plaintext preserved, idempotent, null secrets skipped.

## Off-box audit shipping

- `audit/shipping.py` streams the three audit tables past a per-stream
  `log_ship_cursors` high-water mark, projecting EXPLICIT fields (never the ORM
  row) and flagging high-severity events. The tables are whitelist-detail by
  construction (Phase 1/2), so shipped records carry no secrets.
- The cursor advances only after the sink accepts a batch (at-least-once; a
  failed forwarder re-ships). Concurrency caveat (reviewer item): advancing by
  max id can skip a row that commits out of id order; a strict pipeline ships
  with a time-lag window.
- High-severity set alerts off-box: break-glass login, OIDC code replay, refresh
  reuse, session stale-IP, step-up failure, admin TOTP reset, data-plane deny.

## DDNS

- The decision core (`ops/ddns.py`) is idempotent and backoff-limited, with the
  provider API and public-IP lookup behind interfaces (no provider secrets in
  repo). Unit-tested for changed/unchanged/backoff/no-ip.

## Production posture (must hold before exposure)

- Backend TLS verification enforced (no insecure skip-verify), internal CA
  pinned; the dev-only `idp_verify_tls=false` retired.
- Segmentation: admin API, `/authz/check`, `/guac/consume`, the guac tunnel, and
  guacd are internal; only the public port and out-of-band WireGuard face any
  network. ACME (a vetted client, not hand-rolled) feeds the cert hot-reload
  seam; DNS provider creds are sealed.
- The dedicated security review runs against this document; every dev-only
  accepted risk must have a production resolution before the port opens.
