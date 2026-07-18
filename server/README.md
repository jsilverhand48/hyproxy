# Control plane (Python)

The `hyproxy` package ships three FastAPI applications and a management CLI
from one codebase and one container image:

| App | ASGI target | Port | Role |
|---|---|---|---|
| IdP | `hyproxy.idp.app:app` | 8300 | Self-built OIDC identity provider + login/MFA web pages |
| Admin | `hyproxy.admin.app:app` | 8400 | Management API, standard-user portal API, and the built React SPA |
| Authz | `hyproxy.authz.app:app` | 8500 | Policy decision point, data plane gateway (OIDC RP), Guacamole broker endpoints |

Everything is async SQLAlchemy 2.0 over asyncpg/Postgres, Python >= 3.13.
There are no console scripts in `pyproject.toml`: the services are uvicorn
ASGI targets, the CLI is `python -m hyproxy.cli`, migrations are plain
`alembic`. Package root: `src/hyproxy/`.

Sections below: [Core](#core), [DB](#db), [Guac](#guac), [IdP](#idp),
[Security](#security), [Authz](#authz), [Admin](#admin), then scripts,
packaging, and Docker notes. Environment variables are documented centrally
in the [root README](../README.md#environment-env-parameters).

---

## Core

`src/hyproxy/core/`, plus `config.py`, `logs.py`, `cli.py`.

### Settings (`config.py`)

Pydantic-settings `Settings` with env prefix `HYPROXY_`, loaded from the
environment or `server/.env`. Unknown keys are ignored (`extra="ignore"`),
which is why stale `.env` entries are harmless but also why typos fail
silently. `get_settings()` is `lru_cache`d, as are the secrets backend and DB
engine; they are process-lifetime singletons.

One subtle validator: the DB URL's `host=` query parameter is rewritten to an
absolute path, because asyncpg only treats `host=` as a unix-socket directory
when it is absolute.

### Secrets backend (`core/secrets.py`)

The TPM is the only secrets backend. `get_secrets_backend()` calls
`tpm_unseal()`, which shells out to
`tpm2_unseal -c $HYPROXY_TPM_SEALED_BLOB -p pcr:$HYPROXY_TPM_PCRS`. The
unsealed payload is `key_id:base64key` lines; the **last** non-comment line is
the current key. Any failure (missing handle, missing tool, empty output)
aborts startup.

Fingerprint pinning: `_verify_fingerprint()` compares
`sha256(current_key)[:16]` against `HYPROXY_MASTER_KEY_FP` and aborts on
mismatch. This converts "someone resealed a different key" from a runtime
`InvalidTag` on every decrypt into an immediate, obvious startup failure.
An empty setting skips the check.

### Envelope crypto (`core/crypto.py`)

AES-256-GCM with a 12-byte random nonce and **AAD = the table name**, so a
ciphertext lifted from one table cannot be decrypted in the context of
another. `encrypt_blob()` returns `(key_id, nonce||ciphertext)`; every sealed
column stores its own `key_id`, so rows encrypted under an old master key keep
decrypting until `rotate-master-key` re-wraps them. Also here: token
generation, hashing helpers, and `constant_time_equals`.

### Signing keys (`core/keys.py`)

OIDC signing keys are P-256 (ES256), private PEM sealed with AAD
`"signing_keys"`. Lifecycle: `pending` (published in JWKS, not signing yet,
so caches warm up) -> `active` (exactly one, enforced by a partial unique
index) -> `retiring` (still verifies old tokens) -> `retired`. A 15-minute
buffer keeps retiring keys verifiable past the last token lifetime.
`rotate-signing-key` creates a pending key; `--activate` promotes it and
demotes the old active key to retiring. The JWKS publishes
pending + active + retiring.

### Master key rotation (`core/reencrypt.py`)

`rotate_to_current()` re-encrypts the three sealed tables (`signing_keys`,
`user_totp`, `resource_connections`) under the current master key in one
transaction. Idempotent; exposed as CLI `rotate-master-key`.

### Other core modules

- `core/netutil.py`: client IP resolution, honoring
  `HYPROXY_TRUST_FORWARDED_FOR` (leftmost `X-Forwarded-For` when true).
- `core/time.py`: `Clock` protocol with `SystemClock`/`FixedClock` so time is
  injectable everywhere.
- `logs.py`: unified JSON logging (details in the
  [root README](../README.md#logging-and-log-shipping)).

### CLI (`cli.py`)

Click group, invoked as `python -m hyproxy.cli` (dev) or
`docker compose run --rm cli` (prod). Commands: `bootstrap-keys`,
`rotate-signing-key [--activate]`, `bootstrap-admin --email --name`,
`create-client --client-id --name --redirect-uri...`,
`bootstrap-gateway-client`, `rotate-master-key`, `gen-guac-key`,
`ship-logs [--batch-size N] [--to-file]`, and `gc` (expired DPoP jtis,
gateway login states, guac grants, login flows; retires old signing keys).
Full table in the [root README](../README.md#hyproxy-cli).

---

## DB

`src/hyproxy/db/` and `alembic/`.

### Engine and sessions (`db/engine.py`)

Singleton async engine + sessionmaker. `db_session()` is an async context
manager giving one transaction per unit of work; `get_db()` is the FastAPI
dependency form. `expire_on_commit=False`: ORM objects stay usable after
commit, but since async sessions cannot lazy-load, anything needing
server-generated values after insert must `refresh()` explicitly. Pool sizing
(`HYPROXY_DB_POOL_SIZE`/`_MAX_OVERFLOW`) is applied only for Postgres URLs.

### Postgres specifics

The schema leans on Postgres: `UUID`, `CITEXT` (case-insensitive emails and
hostnames), `INET`, `JSONB`, arrays, partial unique indexes, and
`gen_random_uuid()`. The `pgcrypto` and `citext` extensions must exist
**before** migrating; the initial migration does not create them. In dev,
`scripts/devdb.py` creates both; in production the compose Postgres image is
initialized accordingly.

### Migrations

`alembic.ini` at the server root; `alembic/env.py` runs migrations through the
async engine (`run_sync`), using the same `HYPROXY_DB_URL` as the app. Twelve
linear revisions from the initial schema through guac connection rework. New
revisions: `make db-revision m="message"` (autogenerate against
`Base.metadata`), then `make db-migrate`.

### Model catalog (`db/models.py`)

- **Identity:** `User` (stable `external_id` used as the OIDC `sub`, CITEXT
  email, `auth_tier` of `standard`/`admin` as a first-class attribute never
  derived from roles, `is_protected` marking the break-glass admin that
  cannot be deleted/disabled/demoted), `Role`, `UserRole`.
- **Resources and policy:** `Resource` (protocol enum http/https/tcp/vnc/rdp/
  ssh, unique CITEXT `public_host`, `ports` array), `Policy` (role x
  resource allow/deny with optional port list, path prefixes, and
  `conditions_json` time windows), `ResourceConnection` (guacd parameters;
  secret parameters sealed, cleartext column holds secret **names** only).
- **Sessions and OAuth:** `Session` (hashed cookie secret, bound source IP,
  frozen `auth_tier`, `amr`, DPoP `jkt`, absolute expiry, step-up timestamp,
  `stale`/`revoked_at`), `OAuthClient` (public clients, DPoP required by
  default, exact-match redirect URIs), `AuthCode` (PK is the code hash, S256
  enforced by a CHECK), `RefreshToken` (hash, `family_id`, `parent_id`,
  bound `dpop_jkt`), `DpopJtiSeen` (replay cache, PK `(jkt, jti)`),
  `SigningKey`.
- **MFA:** `UserTotp` (sealed secret), `WebAuthnCredential` (COSE key, sign
  count, `break_glass` flag), `RecoveryCode` (argon2id hashes, batch id).
- **Flows and gateway:** `LoginFlow` (stage machine + parked OIDC request +
  `completed_session_id`; completed rows are retained on purpose, see IdP),
  `GatewaySession`, `GatewayLoginState`, `GuacGrant` (PK is the token hash,
  IP-bound, single-use).
- **Audit:** `AuthEvent`, `AuditLog` (every data plane decision),
  `PolicyChange`, `LogShipCursor` (shipping high-water marks),
  `AuthThrottle` (login rate limiting state).

---

## Guac

`src/hyproxy/guac/` (broker, sealing, token codec) plus the browser-facing
endpoints in `authz/guac.py`. End-to-end flow and the Node side are described
in [tunnel/README.md](../tunnel/README.md).

### Model

VNC/RDP/SSH resources have no `public_host` route of their own. Sessions ride
a fixed `/guac/tunnel` path on the portal host (a data plane route flag), and
everything sensitive travels inside an encrypted token the browser cannot
read.

### Mint (`guac/broker.py`)

`issue_tunnel` resolves the resource and its `ResourceConnection`, runs the
same policy evaluation as any HTTP request (`authz.decision.evaluate_access`
against the connection port), writes an `AuditLog` row **in the same
transaction**, then builds the guacamole-lite payload: non-secret parameters,
secrets **decrypted only at this moment**, plus target host/port. The result
is encrypted into a token and a `GuacGrant` row is persisted holding only
`sha256(token)`, the requester's IP, and a `HYPROXY_GUAC_GRANT_TTL` (60s)
expiry.

### Consume

`consume_grant` is a single conditional UPDATE requiring unconsumed +
unexpired + matching IP (+ owning user); it returns true exactly once, which
makes grants single-use under concurrency without locks. The data plane calls
`POST /guac/consume` when the tunnel WebSocket connects; the endpoint also
requires a live gateway session, so revoking a user's session tears down
tunnel access.

### Token format (`guac/token.py`)

Mirrors guacamole-lite's default codec: JSON -> PKCS7 -> **AES-256-CBC**
(random IV) under the shared base64 32-byte `HYPROXY_GUAC_CYPHER_KEY` ->
`base64(JSON({iv, value}))`. Note this is CBC on the wire and completely
separate from the AES-GCM master-key envelope used at rest. The key must be
byte-identical to the tunnel's `GUAC_CYPHER_KEY`.

### Confusion points

- Connection secrets are write-only through the admin API: responses list
  secret **names**, never values.
- `guac_disabled` (no cypher key configured) surfaces as 503 from
  `/guac/token`; a policy deny is 403. Different failure classes on purpose.

---

## IdP

`src/hyproxy/idp/`: app factory + security headers (`app.py`), session
lifecycle (`sessions.py`), the login flow machine (`flows.py`), the OIDC
protocol surface (`oidc/`), and the HTML login/MFA/enrollment pages
(`web/`).

### Protocol surface

Authorization code + refresh token grants only. All clients are public, PKCE
S256 is mandatory, and DPoP is mandatory (tokens are `token_type: DPoP`).
Discovery at `/.well-known/openid-configuration`, JWKS at `/oidc/jwks`,
endpoints `/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/oidc/revoke`,
`/oidc/logout`.

### Authorize (`oidc/authorize.py`)

The validation **order is load-bearing**: an unknown/disabled `client_id` or a
`redirect_uri` not byte-exactly registered produces a local error page and
never a redirect (otherwise the IdP becomes an open redirector); only after
those two checks do errors flow back to the client via redirect. `state` is
required, `nonce` is required, `code_challenge_method` must be S256. With no
live session, the validated request is parked in a `LoginFlow` behind a
`__Host-login_flow` cookie and the browser goes to `/auth/login`; with a live
session, a 60-second single-use code is issued immediately.

### Token endpoint (`oidc/token.py`)

- Auth code grant: DPoP proof verified first; the code is consumed by a
  conditional UPDATE. A consumed code presented again is treated as theft:
  the whole refresh family **and the issuing session** are revoked and a
  high-severity event is emitted. `redirect_uri` byte-exact, PKCE verified
  constant-time, access token bound to the proof's `jkt`.
- Refresh grant: single-use rotation (parent marked used, child issued).
  Reuse of a used token revokes the family and session. The `dpop_jkt` must
  match the family's binding; expiry is capped at the session's absolute
  expiry.
- The token endpoint checks session liveness with `enforce_ip=False`: the
  caller is the client's backchannel, not the browser, so its IP legitimately
  differs.

### Tokens (`oidc/tokens.py`)

ES256 JWTs. Access tokens (`typ: at+jwt`) carry `sid`, `scope`, `auth_tier`,
`amr`, and `cnf.jkt`. ID tokens carry `nonce`, `auth_time`, `amr`, `sid`, and
`acr` in the form `tier:<tier>` (the SPA reads this to decide admin vs portal
mode). Verification accepts only active + retiring key ids.

### DPoP (`oidc/dpop.py`)

RFC 9449 as a pure-function core with a strict 8-step order: alg allowlist of
exactly `ES256`; the embedded JWK is rejected if it carries private-key or
trust-shortcut members (`d`, `x5c`, `kid`, ...); `htm`/`htu` matching with
normalized URIs; `iat` freshness window; `ath` (access token hash) when a
token is presented; `jkt` thumbprint match against the token binding; and jti
replay via `INSERT ... ON CONFLICT DO NOTHING` on `(jkt, jti)`
(`oidc/replay.py`).

### Sessions (`idp/sessions.py`)

Cookie `__Host-idp_sid` is `{session_id}.{secret}` with only the secret's
SHA-256 stored. `check_liveness` rejects revoked/stale sessions, enforces the
6-hour absolute bound and 30-minute idle timeout (idle trip revokes), and
binds to source IP: a mismatch marks the session `stale` and forces full
re-auth. `touch()` writes `last_seen_at` at most once per
`session_touch_interval`. `check_request` is the shared resource-server
contract (verify JWT -> verify DPoP proof against it -> session liveness ->
active user); userinfo, the admin API, and the authz service all use it.

### Login flow and MFA

Stage machine: password -> second factor -> done. The second factor is chosen
strictly by `user.auth_tier`: admins use WebAuthn only (no TOTP fallback
anywhere), standard users use TOTP.

- **TOTP** (`security/totp.py` + `web/routes.py`): pyotp with a one-step
  window; the secret is sealed at rest. Enrollment renders the QR as inline
  SVG because the CSP allows `img-src 'self'` with no `data:` URIs.
  Confirming enrollment completes the login and shows recovery codes once.
- **WebAuthn** (`security/webauthn.py` + `web/webauthn_routes.py`):
  RP ID/origin derived from the issuer URL. Bootstrap enrollment during login
  is allowed only when the user has no credential predating the flow, so an
  attacker with just the password cannot register their own authenticator.
  Credentials can be flagged `break_glass`; logging in with one emits a
  high-severity event.
- **Recovery codes** (`security/recovery.py`): 10 per batch, argon2id-hashed,
  shown once; a new batch invalidates prior unused ones. Using a recovery
  code assumes the authenticator is lost: the TOTP secret is deleted and
  re-enrollment is forced.
- **Step-up**: admin mutations require a fresh WebAuthn assertion on the live
  session within `stepup_max_age` (300s). Step-up is a top-level navigation
  (so the SameSite=Lax IdP cookie is sent), and the post-step-up return URL
  is restricted to configured SPA origins.

Intricacies that will otherwise confuse you:

- **Completed login flows are retained, not deleted.** A duplicate or late
  second-factor submit replays the same outcome: the flow is pinned to
  `completed_session_id`, the session cookie is re-minted, and the OIDC
  continuation is re-emitted. The flow cookie is deliberately left in place
  on success; clearing it made repeat submits dead-end instead of continuing
  to the resource. Row-level `FOR UPDATE` serializes concurrent submits.
- **IP binding is split.** The pre-auth authorize -> login handoff is not
  IP-bound (it holds only public parameters). After the password step the
  flow is pinned to the client IP, but second-factor submits pass
  `enforce_ip=False` because the browser-to-IdP hop's forwarded IP
  fluctuates; binding there rests on the single-use flow cookie + CSRF +
  short TTL. The data plane resource path, by contrast, is strictly
  IP-bound.

### Security headers and CSP (`idp/app.py`)

Strict same-origin CSP (`default-src 'none'`, `script-src 'self'`, no
`data:`), `frame-ancestors 'none'`, HSTS, no-referrer, `no-store` on all auth
and OIDC responses. The known trap: browsers enforce CSP `form-action`
across the **entire redirect chain** of a form submission, so when
`HYPROXY_GATEWAY_COOKIE_DOMAIN` is set the CSP must widen `form-action` to
that domain's subdomains, or the post-login cross-subdomain redirect is
silently cancelled and login appears to do nothing. CORS allows only the
admin UI and portal origins, without credentials (the API auth is
bearer/DPoP, never cookies).

---

## Security

`src/hyproxy/security/`: the shared primitives.

- **Passwords** (`passwords.py`): argon2id (argon2-cffi defaults).
  `dummy_verify()` burns the same argon2 cost for unknown or disabled
  accounts so response timing does not reveal account existence.
- **PKCE** (`pkce.py`): S256 only, RFC 7636 charset/length validation,
  constant-time comparison.
- **Rate limiting** (`ratelimit.py`): progressive delay backed by the
  `auth_throttle` table, in two scopes (per-account and per-IP), exponential
  up to small caps (60s account / 30s IP), no hard lockout. Checked
  **before** password verification so an attacker cannot burn argon2 CPU.
  Success resets the account scope; the IP scope decays on its own.
- **At-rest inventory:** cookie secrets, auth codes, refresh tokens, CSRF
  tokens, and guac grants are stored as SHA-256; recovery codes as argon2id;
  TOTP secrets, signing keys, and connection secrets as AES-256-GCM under the
  TPM master key. Nothing replayable sits in the database.
- **Audit hygiene** (`audit/events.py`): `emit()` writes events inside the
  caller's transaction and enforces a whitelist of allowed `detail` keys with
  short-scalar limits, so audit rows can never accidentally carry tokens or
  secrets.

---

## Authz

`src/hyproxy/authz/` plus the pure policy core in `policy/engine.py`. This
service is internal-only: the data plane calls it directly and proxies only
the auth host's `/gateway/*` and `/guac/token` paths to it. API docs
endpoints are disabled.

### /authz/check (`check.py`)

Request: `{host, method, uri, source_ip, backend_port, gateway_cookie}`.
Resolution order: unknown host -> deny; no live gateway session ->
`auth_required` with a redirect into `/gateway/start`; inactive user ->
deny; a standard-tier user on the admin console host -> bounced (tier gate);
otherwise the policy engine decides. **Every branch writes an `AuditLog` row
in the same transaction**, which is what the admin "Access audit" viewer
shows. Allow responses carry the identity headers the data plane injects.

### Decision cache hint (`decision.py`)

An allow that provably holds for every path and time on this
(user, resource, port) - no path restrictions, no time windows - returns
`cache_scope: "host"` with `HYPROXY_AUTHZ_CACHE_TTL` (20s), letting the data
plane skip per-request checks for hot streaming traffic. Denies and
constrained allows are never cacheable. `_host_stable` fails closed on any
condition key it does not recognize, so adding a new policy condition type
cannot silently over-cache.

### Policy engine (`policy/engine.py`)

Pure functions over frozen dataclasses; no I/O. Among applicable rules
(enabled, resource match, role held, port match, path prefix match, time
window match): explicit deny wins, else an applicable allow, else default
deny. Time windows are day + HH:MM in UTC and support crossing midnight;
malformed windows fail closed.

### Gateway RP (`gateway.py`)

The browser-facing OIDC relying party the data plane fronts:

- `/gateway/start?rd=`: the return URL is validated against registered
  resource hosts and configured SPA origins (open-redirect guard), then a
  single-use, IP-bound `GatewayLoginState` (state, PKCE verifier, nonce) is
  parked and the browser is sent to `/oidc/authorize`.
- `/gateway/callback`: validates and single-use-deletes the state (including
  IP match), exchanges the code over the internal backchannel using the
  gateway's server-side DPoP proof, verifies both tokens and the nonce, then
  creates a `GatewaySession` linked to the IdP `Session` so liveness,
  revocation, and the 6-hour bound are inherited. Sets `__Secure-gw`
  (`{id}.{secret}`, HttpOnly, SameSite=Lax).
- `resolve_gateway_session`: IP-binds against the gateway session's own
  origin but checks the linked IdP session with `enforce_ip=False` (the two
  hops legitimately see different IPs).
- The gateway's DPoP keypair is derived from the master key via HKDF (salt
  `hyproxy-gateway-dpop`), so its thumbprint is stable across restarts and
  nothing is written to disk.

### /authz/routes (`routes.py`)

Polled by the data plane. Emits backends only from server-side resource rows
(the SSRF invariant): http/https resources become `{protocol}://{host}:{port}`
targets keyed by `public_host`; vnc/rdp/ssh resources are never emitted (they
ride the portal tunnel path); tcp is skipped in v1.

---

## Admin

`src/hyproxy/admin/`: the management API, the portal API, and the static SPA.

### App (`app.py`)

Serves `/api/v1/*`, mounts the built SPA (from `HYPROXY_ADMIN_UI_DIST`,
falling back to `../ui/dist`) with an index.html fallback for client-side
routing. Its CSP is computed from settings; notably `connect-src` must
include the IdP origin (token exchange), the auth host (guac token minting),
and the `wss://` tunnel origin(s). Lifespan owns the qBittorrent HTTP client.

### Auth dependencies (`deps.py`)

The admin API is a resource server for the IdP's DPoP-bound access tokens,
running the same `sessions.check_request` contract as userinfo:

| Dependency | Requires | Used by |
|---|---|---|
| `require_admin` | LAN client + valid token + frozen session tier `admin` | Management endpoints |
| `require_user` | Any authenticated user | Portal endpoints |
| `require_portal_admin` | Admin tier, no LAN restriction | Portal review actions (internet-facing) |
| `require_recent_stepup` | WebAuthn step-up within `stepup_max_age` | Every mutation |
| `require_lan_client` | Source IP in `HYPROXY_ADMIN_LAN_CIDRS` (empty disables, dev only) | Defense in depth behind the data plane `lan_only` flag |

The `_expected_htu` workaround matters when debugging DPoP failures: behind
the proxy, uvicorn honors `X-Forwarded-Proto` but not `X-Forwarded-Host`, so
the expected proof URI is rebuilt from configured origins keyed by the
`X-Forwarded-Host` allowlist rather than trusted from `request.url`.

### Routes (`routes/`)

- `users.py`: user CRUD, credential and session management. Invariants:
  promoting to admin requires at least two non-break-glass passkeys already
  enrolled, and an active admin must keep two; the `is_protected` bootstrap
  admin cannot be disabled, demoted, or deleted; you cannot delete yourself.
  Disable/delete/reset revokes the user's sessions and refresh families.
- `resources.py` / `connections.py`: resource CRUD with `public_host`
  normalization and collision checks (the auth host is reserved); guac
  connections nest under resources with write-only sealed secrets; guac
  resources cannot carry a `public_host`.
- `policies.py`, `roles.py`, `user_roles.py`: CRUD, step-up gated, recorded
  in `policy_changes` via `changes.py`.
- `viewers.py`: read-only, admin-tier keyset-paginated views over
  `audit_log`, `auth_events`, and `policy_changes` (stable pagination under
  concurrent inserts; no step-up needed to read).
- `portal.py` (`/api/v1/portal`, also served on the portal host): the user's
  allowed resources (presentation only; enforcement stays in authz),
  self-service password change (revokes other sessions), and the download
  request queue. Downloads accept **magnet links only** (BitTorrent v1
  infohash regex), specifically so qBittorrent's URL field cannot be turned
  into SSRF. Standard users queue requests; admins approve/deny (with
  `FOR UPDATE` against double-approval) or submit directly. `qbit.py` posts
  to qBittorrent with no credentials, relying on its IP whitelist; save paths
  come from `HYPROXY_QBIT_SAVEPATH_SHOWS`/`_MOVIES` (empty disables the
  target).
- `ui_logs.py` (`/api/v1/ui-logs`): unauthenticated **by design** so the SPA
  can report errors even when auth is broken. Guarded by strict payload caps
  and an in-memory fixed-window rate limiter (per-IP and global),
  deliberately not the DB-backed throttle so log spam cannot become database
  load. Entries land in `ui.log`.

---

## Dev scripts

- `scripts/devdb.py`: user-space dev Postgres (no Docker/root). Subcommands
  `start` (default), `stop`, `status`, `url`; creates `hyproxy` and
  `hyproxy_test` databases with `pgcrypto` + `citext`, prints the URLs to
  export.
- `scripts/gen_dev_certs.py`: self-signed dev TLS cert for the IdP (secure
  context for cookies/WebAuthn) into `.dev/certs/`. `DEV_CERT_EXTRA` adds
  extra SAN hosts/IPs (comma-separated).

## Packaging and Docker

`pyproject.toml`: hatchling build, Python >= 3.13. Key runtime deps: FastAPI,
uvicorn, SQLAlchemy 2 + asyncpg, alembic, joserfc (JWT/JWK), argon2-cffi,
pyotp + segno, webauthn, pydantic-settings, click, httpx (the OIDC
backchannel). Dev group adds pytest (+asyncio, hypothesis), ruff, mypy strict,
bandit, pip-audit. No `[project.scripts]`; see the table at the top for how
each entry point is invoked.

`server/Dockerfile` is documented in the
[root README](../README.md#docker): two stages (SPA build, then a uv-based
Python runtime with `tpm2-tools`), non-root uid 10001, no CMD (compose
supplies per-service commands).

## Running locally

```sh
make db-up          # user-space Postgres (scripts/devdb.py)
export HYPROXY_DB_URL=...   # printed by db-up
make db-migrate
make gen-certs
make bootstrap-admin args="--email you@example.com --name You"
make run-idp        # :8300 (TLS, dev certs)
make run-admin      # :8400
make run-authz      # :8500
```

Tests: `make test`, `make test-integration`, `make test-e2e`; quality gates:
`make check` and `make audit`.
