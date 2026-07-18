# hyproxy

An identity-aware reverse proxy stack for self-hosted services. A single Go
binary (the data plane) is the only internet-facing process: it terminates TLS
on one public port, routes by hostname to an allowlist of backends, and
forward-auths every request against a self-built Python control plane that
provides an OIDC identity provider, a policy engine, an admin console, a user
portal, and an in-browser remote desktop bridge (Apache Guacamole).

- Target OS: Rocky Linux (RHEL family). The data plane runs baremetal; the
  control plane, Postgres, and the optional Guacamole bridge run in Docker
  Compose, all published on `127.0.0.1` only.
- The master encryption key is sealed in the machine's TPM 2.0. There is no
  on-disk key file; an unseal failure aborts startup (fail closed).
- All user-facing auth is phishing-resistant by construction: OIDC
  authorization code + PKCE (S256) with mandatory DPoP-bound tokens, WebAuthn
  for admins, TOTP for standard users.

## Architecture

```
                          internet
                             |
                     :443  (TLS, HTTP/1.1)
              +--------------------------------+
              |        data plane (Go)         |  baremetal, sole ingress
              |  host routing / bot filter /   |
              |  forward-auth / header hygiene |
              +--------------------------------+
                 |            |            |
      /authz/check (per     static +      DB-driven app routes
       request, fails       DB routes     (polled from /authz/routes)
       closed)                 |
                 v             v
   +--------------------------------------------------+
   |            control plane (Python, Docker)        |
   |                                                  |
   |  idp   :8300  OIDC IdP + login pages             |
   |  admin :8400  admin API + portal API + SPA       |
   |  authz :8500  policy decisions + gateway RP      |
   |                    |                             |
   |               Postgres 17                        |
   +--------------------------------------------------+
                 |
        optional guac profile (Docker)
                 |
   tunnel :8600 (guacamole-lite, Node)  ->  guacd :4822  ->  VNC/RDP/SSH targets
```

Request flows worth understanding before reading any code:

1. **Proxied app request.** Browser hits `https://app.example.com`. The data
   plane normalizes the Host header, looks up the route, extracts the gateway
   cookie, and POSTs `/authz/check` to the authz service. On `allow` it strips
   any client-supplied identity headers, injects `X-Forwarded-User`,
   `X-Auth-User-Id`, and `X-Auth-Roles` from the decision, and proxies to the
   backend. `auth_required` becomes a 302 to the login flow; anything else is
   denied. A transport error to authz is a 503, never a pass-through.

2. **Login.** The authz service doubles as an OIDC relying party ("gateway")
   for the data plane: `/gateway/start` parks state and redirects to the IdP's
   `/oidc/authorize`; the user authenticates (password, then TOTP or WebAuthn
   by tier); `/gateway/callback` exchanges the code over an internal
   backchannel using a server-side DPoP proof and sets the `__Secure-gw`
   cookie. The gateway session is linked to the IdP session, so revoking one
   kills the other.

3. **Remote desktop.** The SPA asks the auth host for a short-lived encrypted
   Guacamole token (`/guac/token`), then opens
   `wss://apps.example.com/guac/tunnel?token=...`. The data plane single-use
   consumes the grant via `/guac/consume` (IP-bound, live-session-bound) and
   reverse-proxies the WebSocket to the Node tunnel, which decrypts the token
   and speaks the Guacamole protocol to `guacd`.

## Repository layout

| Path | What it is | Docs |
|---|---|---|
| `dataplane/` | Go edge proxy: TLS, host routing, forward-auth, bot filter, streaming tuning | [dataplane/README.md](dataplane/README.md) |
| `server/` | Python control plane: IdP, authz, admin/portal, CLI, migrations | [server/README.md](server/README.md) |
| `ui/` | React SPA: admin console and user portal (one app, tier-gated) | [ui/README.md](ui/README.md) |
| `tunnel/` | Node guacamole-lite WebSocket tunnel to guacd | [tunnel/README.md](tunnel/README.md) |
| `tests/` | Test suite (unit / integration / e2e) | |
| `docs/` | Theme asset inventory, TODO tracker | |
| `install.sh`, `build.sh`, `start.sh`, `stop.sh` | Lifecycle scripts (see below) | |
| `Makefile`, `docker-compose.yml` | Dev targets and the containerized control plane | |

## Getting started

- **Production install (bare Rocky Linux host):** `sudo ./install.sh`. One
  command: seals a fresh master key in the TPM, writes `.env`, installs the
  toolchain, builds everything, issues a Let's Encrypt wildcard cert, installs
  systemd units, and starts the stack.
- **Run an installed stack:** `systemctl start hyproxy` (which runs
  `start.sh`), or `./start.sh` directly for a foreground run.
- **Stop everything:** `./stop.sh` (idempotent; also the unit's `ExecStop`).
- **Rebuild after changes:** `./build.sh --clean`, then `./start.sh`.
- **Local development (no root, no containers):** `make db-up`, `make
  db-migrate`, `make gen-certs`, then `make run-idp` / `run-admin` /
  `run-authz` and `make ui-dev`. See [server/README.md](server/README.md).

## Scripts, options, and flags

### install.sh

One-command Rocky Linux installer. Idempotent: if a complete `.env` already
exists it is reused verbatim and prompts are skipped. Must run as root.

Prompts (first run only): domain, admin email/name, lego DNS provider and
credentials, Postgres password (or auto-generate), enable Guacamole y/n.

Environment overrides:

| Variable | Default | Effect |
|---|---|---|
| `HYPROXY_REPO_URL` | the upstream repo | Repo to clone |
| `HYPROXY_REPO_BRANCH` | `master` | Branch to check out |
| `HYPROXY_INSTALL_DIR` | `/opt/hyproxy` | Install location |
| `HYPROXY_RUN_GATES` | `0` | `1` runs `make audit` and `make dp-test` during install |
| `HYPROXY_TPM_FORCE_RESEAL` | `0` | Discard the existing sealed blob and reseal a new key |
| `HYPROXY_TPM_SEALED_BLOB` | `0x81010001` | Persistent TPM handle for the sealed master key |
| `HYPROXY_TPM_PCRS` | `sha256:0,2,4,7` | PCR policy the key is sealed under |

What it installs beyond the repo itself:

- `/usr/local/sbin/hyproxy-obtain-cert.sh`: lego DNS-01 wildcard issue/renew,
  pinned to the domain's authoritative nameservers; installs
  `fullchain.pem`/`privkey.pem` into `/etc/hyproxy/certs` (the data plane
  hot-reloads them).
- Systemd units (written only if absent, so operator edits survive re-runs):
  - `hyproxy.service`: whole-stack supervisor (`ExecStart=start.sh`,
    `ExecStop=stop.sh`, runs as the `hyproxy` service account with
    `CAP_NET_BIND_SERVICE`).
  - `hyproxy-acme.service` + `hyproxy-acme.timer`: daily cert renewal.
  - `hyproxy-ship-logs.service` + `hyproxy-ship-logs.timer`: audit log
    shipping every 5 minutes (`docker compose run --rm cli ship-logs --to-file`).
- BBR congestion control (`/etc/sysctl.d/99-hyproxy-net.conf` and a
  modules-load drop-in). This matters for streaming throughput on lossy WAN
  paths.
- SELinux file contexts for the install dir, firewalld opening for the data
  plane port only.

The freshly generated master key is printed exactly once for offline backup,
then shredded from the tmpfs scratch space. Store it; the TPM copy is the only
other one.

### build.sh

Builds the stack from source, smoke-tests it, then tears everything down. It
leaves nothing running; use `start.sh` afterwards.

| Flag / variable | Default | Effect |
|---|---|---|
| `--clean` | off | Rebuild the image with `--no-cache` and the Go binary from scratch |
| `-h`, `--help` | | Print usage |
| `RENDER_CONFIG` | `0` | Re-render `dataplane/config.json` from `.env` even if present |
| `SKIP_DATAPLANE` | `0` | Build and verify containers only, skip the Go binary |
| `HYPROXY_INSTALL_DIR` | `/opt/hyproxy` | Path baked into `hyproxy.service` if it writes one |

Incremental: content hashes under `.build/` skip the image or binary build when
inputs have not changed. Requires a populated `.env` (`TSS_GID`,
`HYPROXY_TPM_SEALED_BLOB`, an https `HYPROXY_ISSUER`).

**Gotcha:** the exit trap is a superset of `stop.sh`. Running `build.sh` on a
live box stops the data plane, the compose project, the systemd units, and any
dev processes. This is intentional (a clean-slate smoke test) but surprises
people.

### start.sh

Runs the full stack in the foreground: compose services plus the baremetal
data plane. Ctrl-C stops both. No flags; knobs are environment variables:

| Variable | Default | Effect |
|---|---|---|
| `REBUILD` | `0` | `docker compose build` before starting |
| `SKIP_TIMER` | `0` | Skip enabling/checking `hyproxy-acme.timer` |
| `DP_LISTEN` | `:443` | Data plane listen address |

It fails closed before touching anything: checks the data plane binary,
`config.json`, the TPM device, and the TLS cert/key paths referenced by the
config. It also runs migrations and `bootstrap-gateway-client` on every start,
both idempotent.

### stop.sh

No flags. Idempotent teardown: kills the data plane and any uvicorn dev
processes, stops the systemd units, then `docker compose -p hyproxy down
--remove-orphans`. TERM first, SIGKILL after a short grace.

### server/scripts/devdb.py

User-space dev Postgres (no Docker, no root): downloads embedded Postgres 17
binaries, initializes a cluster under `server/.dev/pgdata`, serves it over a
unix socket, and creates the `hyproxy` and `hyproxy_test` databases with the
`pgcrypto` and `citext` extensions. Positional subcommands (default `start`):

| Subcommand | Effect |
|---|---|
| `start` | Download/init/start, print `HYPROXY_DB_URL` and `HYPROXY_TEST_DB_URL` |
| `stop` | `pg_ctl stop -m fast` |
| `status` | Cluster status |
| `url` | Print the SQLAlchemy URL |

### server/scripts/gen_dev_certs.py

Generates a self-signed dev TLS cert for the IdP (cookies and WebAuthn need a
secure context) into `server/.dev/certs/`. No flags; the `DEV_CERT_EXTRA`
environment variable adds comma-separated extra SAN hosts or IPs.

### hyproxy CLI

The management CLI (`python -m hyproxy.cli` inside the server env, or
`docker compose run --rm cli <command>` in production, or the `make` wrappers):

| Command | Flags | Effect |
|---|---|---|
| `bootstrap-keys` | | Ensure an active OIDC signing key exists (first run) |
| `rotate-signing-key` | `--activate` | Create a pending signing key, or promote the pending one |
| `bootstrap-admin` | `--email`, `--name` | Create/reset the protected break-glass admin with a one-time password |
| `create-client` | `--client-id`, `--name`, `--redirect-uri` (repeatable) | Register/update an OIDC client (e.g. `admin-ui`) |
| `bootstrap-gateway-client` | | Register the data plane's gateway OIDC client |
| `rotate-master-key` | | Re-encrypt all sealed blobs under the current master key |
| `gen-guac-key` | | Print a fresh base64 32-byte Guacamole cypher key |
| `ship-logs` | `--batch-size` (500), `--to-file` | Ship new audit rows to stdout or `audit.log` (see Logging) |
| `gc` | | Purge expired DPoP jtis, login states, guac grants, login flows; retire old signing keys |

## Makefile targets

Run from the repo root. `uv` drives all Python invocations.

| Group | Targets |
|---|---|
| Dev database | `db-up`, `db-down` (user-space Postgres via `devdb.py`); `up`, `down` (compose Postgres) |
| Schema | `db-migrate` (alembic upgrade head), `db-revision m="msg"` (autogenerate) |
| Keys / bootstrap | `gen-certs`, `rotate-key`, `bootstrap-admin`, `create-client`, `create-admin-ui-client`, `gc` |
| Run (dev) | `run-idp` (:8300 with dev TLS), `run-admin` (:8400), `run-authz` (:8500) |
| Admin UI | `ui-install`, `ui-build`, `ui-dev` |
| Guacamole | `gen-guac-key`, `tunnel-install`, `tunnel-run` |
| Prod hardening | `rotate-master-key`, `ship-logs args="..."` |
| Data plane | `dp-build`, `dp-test` (gofmt + vet + tests), `dp-fuzz` (host normalizer, 30s), `dp-run` |
| Quality | `lint`, `fmt`, `typecheck`, `test`, `test-integration`, `test-e2e`, `check`, `audit` (bandit + pip-audit) |

## Docker

### Images

- **`server/Dockerfile`** (build context = repo root), two stages:
  1. `ui` stage (`node:22-alpine`): `npm ci && npm run build` of the SPA. The
     Vite variables `VITE_IDP_ISSUER`, `VITE_ADMIN_UI_CLIENT_ID`,
     `VITE_PORTAL_HOST`, and `VITE_AUTH_ORIGIN` are build args baked into the
     bundle; changing them requires an image rebuild.
  2. `runtime` stage (`ghcr.io/astral-sh/uv:python3.13-bookworm-slim`):
     installs `tpm2-tools` (the secrets backend shells out to `tpm2_unseal`),
     `uv sync --frozen --no-dev`, copies `src/`, `alembic/`, and the built SPA
     to `/app/ui/dist` (`HYPROXY_ADMIN_UI_DIST` points there). Runs as
     non-root uid 10001. Exposes 8300/8400/8500. **No CMD**: compose supplies
     each service's command, so one image backs idp, admin, authz, migrations,
     and the CLI.
- **`tunnel/Dockerfile`**: `node:22-alpine`, production-only `npm ci`, copies
  just `server.js` and `logger.js`, runs as the `node` user, `CMD node
  server.js`, port 8600.
- There is deliberately **no `ui/Dockerfile`** (the SPA is compiled inside the
  server image) and **no `dataplane/Dockerfile`** (the Go binary runs
  baremetal so it can bind :443 with plain capabilities and keep streaming off
  the Docker network path; built on the target host via `make dp-build`).

### docker-compose.yml

Project name `hyproxy`, one bridge network, one volume (`pgdata`). All ports
publish on `127.0.0.1` only; the data plane is the only public listener. YAML
anchors share the server build, the common `HYPROXY_*` environment, TPM device
passthrough (`HYPROXY_TPM_DEVICE` plus `group_add: TSS_GID`), and healthcheck
defaults.

| Service | Profile | Image / command | Port (localhost) |
|---|---|---|---|
| `postgres` | default | `postgres:17-alpine` | 5433 -> 5432 |
| `migrate` | `tools` | server image, `alembic upgrade head` | |
| `cli` | `tools` | server image, entrypoint `python -m hyproxy.cli` | |
| `idp` | `app` | `uvicorn hyproxy.idp.app:app --port 8300` | 8300 |
| `admin` | `app` | `uvicorn hyproxy.admin.app:app --port 8400` | 8400 |
| `authz` | `app` | `uvicorn hyproxy.authz.app:app --port 8500 --workers 2` | 8500 |
| `guacd` | `guac` | `guacamole/guacd:1.5.5` | internal only |
| `tunnel` | `guac` | built from `tunnel/` | 8600 |

Notes:

- The `guac` profile is only started when `HYPROXY_GUAC_CYPHER_KEY` is set
  (the scripts add `--profile guac` conditionally).
- authz runs 2 uvicorn workers because `/authz/check` gates every proxied
  request; a single event loop queues concurrent media-segment checks.
- `HYPROXY_LOG_DIR` (when set) bind-mounts into every service at
  `/var/log/hyproxy`; empty disables file logging entirely.
- **Stale reference:** `postgres` mounts `./deploy/initdb` into
  `/docker-entrypoint-initdb.d`, but the `deploy/` directory was removed from
  the repo. Compose silently creates an empty directory, which is harmless,
  but the mount (and a Dockerfile comment mentioning
  `deploy/docker-compose.tpm.yml`) are leftovers.

## Configuration

Everything an operator can change, from most to least commonly touched:

1. **`.env` at the repo/install root.** The single source of truth for
   secrets and topology. Consumed by compose (variable substitution),
   `install.sh`, `build.sh`, and `start.sh`; the Python app reads the same
   `HYPROXY_*` names from its environment. See the table below.
2. **The admin console / API (DB-driven, no restarts).** Users, roles,
   resources (public hostnames and backends), Guacamole connections, and
   access policies live in Postgres and are managed over the admin API. The
   data plane polls `/authz/routes` (default every 10s) and hot-swaps its
   route table, so adding an application requires no config file edits and no
   restarts.
3. **`dataplane/config.json`.** Rendered from `.env` by `build.sh`/
   `install.sh` but hand-editable; holds the static infra config the DB cannot
   (listen address, TLS paths, the auth/idp/admin routes, bot filter, LAN
   rules, logging). Full field reference in
   [dataplane/README.md](dataplane/README.md).
4. **The hyproxy CLI** for key rotation, client registration, and shipping
   (see above).
5. **TLS**: `hyproxy-obtain-cert.sh` + the acme timer manage the wildcard
   cert; provider credentials live in `.env`; the data plane hot-reloads the
   files on change, no restarts.
6. **Systemd units**: written only if absent, so local edits persist across
   re-installs.

### Environment (.env) parameters

Required (compose interpolation or script guards fail without them):

| Variable | Notes |
|---|---|
| `POSTGRES_PASSWORD` | Containerized Postgres password; `HYPROXY_DB_URL` is derived from it, do not set that here |
| `HYPROXY_ISSUER` | Public IdP origin, must be https in production; also baked into the SPA and used as the WebAuthn RP ID source |
| `HYPROXY_ADMIN_UI_ORIGIN` | Admin SPA origin; the sole IdP CORS allowance and the only step-up return target |
| `HYPROXY_DOMAIN` | Apex domain; drives the auth host and cookie domain defaults (written by install.sh, required by start.sh) |
| `HYPROXY_TPM_SEALED_BLOB` | Persistent TPM handle of the sealed master key |
| `TSS_GID` | gid of the host `tss` group, so compose can pass the TPM device into containers |

Required at install time only (not application config): `ADMIN_EMAIL`,
`ADMIN_NAME`, `ACME_EMAIL`, `LEGO_DNS_PROVIDER` plus the provider's credential
variables, and optionally `ADMIN_UI_REDIRECT` (defaults to
`<HYPROXY_ADMIN_UI_ORIGIN>/callback`).

Optional, with defaults (all read by the control plane unless noted):

| Variable | Default | Controls |
|---|---|---|
| `HYPROXY_TPM_PCRS` | `sha256:0,2,4,7` | PCR selection; must match sealing time |
| `HYPROXY_TPM_DEVICE` | `/dev/tpmrm0` | TPM device passed into containers |
| `HYPROXY_MASTER_KEY_FP` | empty | Pinned fingerprint of the master key; startup fails closed on mismatch. Empty skips the check |
| `HYPROXY_GUAC_CYPHER_KEY` | empty | Base64 32-byte Guacamole token key; empty disables guac entirely |
| `HYPROXY_GUAC_GRANT_TTL` | `60` | Seconds a minted tunnel token stays valid (single-use regardless) |
| `HYPROXY_AUTH_HOST` | `auth.<domain>` | Public hostname for the gateway endpoints |
| `HYPROXY_EXTERNAL_SCHEME` | `https` | Scheme used in gateway redirects |
| `HYPROXY_GATEWAY_COOKIE_NAME` | `__Secure-gw` | Gateway session cookie name |
| `HYPROXY_GATEWAY_COOKIE_DOMAIN` | empty | Empty = host-only cookie; set a parent domain to share across subdomains (also widens the IdP CSP `form-action`) |
| `HYPROXY_GATEWAY_STATE_TTL` | `600` | Gateway login state lifetime |
| `HYPROXY_GATEWAY_CLIENT_ID` | `gateway` | OIDC client id of the data plane gateway |
| `HYPROXY_IDP_INTERNAL_URL` | empty | authz -> IdP backchannel base; defaults to the issuer |
| `HYPROXY_IDP_VERIFY_TLS` | `true` | TLS verification on the backchannel; keep true in production |
| `HYPROXY_TRUST_FORWARDED_FOR` | `false` | Take client IP from the leftmost `X-Forwarded-For`; must be consistent across all services or IP-bound sessions break |
| `HYPROXY_ADMIN_LAN_CIDRS` | empty | CIDRs allowed to call the admin API; empty disables the check (dev only) |
| `HYPROXY_PORTAL_ORIGIN` | empty | Internet-facing portal origin (CORS, DPoP htu, step-up target) |
| `HYPROXY_ADMIN_UI_DIST` | empty | Built SPA directory; the image sets `/app/ui/dist` |
| `HYPROXY_DB_POOL_SIZE` / `HYPROXY_DB_MAX_OVERFLOW` | `10` / `10` | SQLAlchemy pool sizing |
| `HYPROXY_ACCESS_TTL` | `600` | Access token lifetime (s) |
| `HYPROXY_REFRESH_ABS_TTL` | `21600` | Absolute session/refresh bound (6h) |
| `HYPROXY_IDLE_TTL` | `1800` | Session idle timeout (revokes on trip) |
| `HYPROXY_STEPUP_MAX_AGE` | `300` | Freshness window for WebAuthn step-up on admin mutations |
| `HYPROXY_AUTH_CODE_TTL` | `60` | Authorization code lifetime |
| `HYPROXY_LOGIN_FLOW_TTL` | `600` | Login flow lifetime |
| `HYPROXY_DPOP_IAT_WINDOW` / `HYPROXY_DPOP_IAT_FUTURE_SKEW` | `300` / `30` | DPoP proof freshness window |
| `HYPROXY_SESSION_TOUCH_INTERVAL` | `60` | Throttle on last-seen session writes |
| `HYPROXY_JWKS_CACHE_MAX_AGE` | `300` | JWKS Cache-Control max-age |
| `HYPROXY_SIGNING_ALG` | `ES256` | JWT signing algorithm |
| `HYPROXY_AUTHZ_CACHE_TTL` | `20` | Data plane allow-decision cache hint (s); `0` disables |
| `HYPROXY_THROTTLE_WINDOW` | `900` | Login throttle window |
| `HYPROXY_THROTTLE_ACCOUNT_FREE_FAILURES` / `..._MAX_DELAY` | `3` / `60` | Per-account progressive delay |
| `HYPROXY_THROTTLE_IP_FREE_FAILURES` / `..._MAX_DELAY` | `10` / `30` | Per-IP progressive delay |
| `HYPROXY_QBIT_URL` | dev default | qBittorrent Web API base for portal downloads |
| `HYPROXY_QBIT_SAVEPATH_SHOWS` / `..._MOVIES` | empty | Save paths per download target; empty disables that target |
| `HYPROXY_LOG_DIR` | empty | Central log directory; empty = stderr only |
| `HYPROXY_LOG_LEVEL` | `INFO` | Control plane log level |
| `HYPROXY_LOG_MAX_BYTES` | `52428800` | Rotation threshold (50 MB) |
| `HYPROXY_LOG_BACKUP_COUNT` | `2` | Archives kept per log file |
| `VITE_ADMIN_UI_CLIENT_ID` | `admin-ui` | SPA build arg: OIDC client id |
| `VITE_PORTAL_HOST` | empty | SPA build arg: portal hostname (switches the SPA to portal-only sections on that host) |
| `VITE_AUTH_ORIGIN` | derived | SPA build arg: origin that mints guac tokens |
| `DP_LISTEN` | `:443` | Data plane listen address (start.sh) |
| `DP_LOG_LEVEL` | `info` | Data plane log level, rendered into config.json |
| `DP_TLS_CERT` / `DP_TLS_KEY` | `/etc/hyproxy/certs/...` | Cert/key paths rendered into config.json |
| `DP_TLS_GROUP` | `hyproxy` | Group ownership of the private key |
| `DP_UPSTREAM_INSECURE_SKIP_VERIFY` | `false` | Renders `upstream_insecure_skip_verify` (see Security Implications) |
| `IDP_BACKEND` / `ADMIN_BACKEND` / `AUTHZ_BACKEND` / `GUAC_BACKEND` | `http://127.0.0.1:83/84/85/8600` | Backend origins rendered into config.json |
| `ROUTES_REFRESH_SECS` | `10` | Data plane DB route poll interval |
| `ACME_EMAIL`, `LEGO_DNS_PROVIDER`, `LEGO_PATH` | | Cert issuance (obtain-cert script) |
| `HYPROXY_GID` | | Host group joined by the tunnel container so it can write the shared log dir |

One dead key to know about: some existing `.env` files contain
`HYPROXY_MASTER_KEY_FILE`. No code reads it (the settings loader ignores
unknown keys); the TPM is the only secrets backend. It can be deleted.

## Logging and log shipping

Two distinct mechanisms: runtime service logs (files/stderr) and an off-box
audit shipper (database tables to a SIEM-friendly stream).

### Runtime logs

Every component emits the same JSON-lines scheme: `ts` (ISO-8601 UTC),
lowercase `level`, `service`, `logger`, `msg`, plus flattened extras. One file
per service under `HYPROXY_LOG_DIR` (production: `/var/log/hyproxy`, a setgid
dir writable by uid 10001 and the `hyproxy` group so containers and the
baremetal data plane share it). Empty `HYPROXY_LOG_DIR` = stderr only (the dev
default). Size-based rotation at `HYPROXY_LOG_MAX_BYTES` (50 MB), keeping
`HYPROXY_LOG_BACKUP_COUNT` (2) archives.

| Component | Files | Notes |
|---|---|---|
| Control plane (idp/admin/authz/cli) | `idp.log`, `admin.log`, `authz.log`, `cli.log` + stderr | `server/src/hyproxy/logs.py`. The rotating handler is multi-process safe (inode watch + flock) for the 2-worker authz. uvicorn access lines are split into Splunk CIM Web fields (`src`, `src_port`, `http_method`, `url`, `uri_path`, `uri_query`, `status`) instead of one packed string |
| Data plane (Go) | `dataplane.log` (+ stderr), `dataplane-access.log` (file only) | The per-request access log never goes to stderr so streaming volume cannot drown journald. Fields: `http_method`, `site`, `uri_path`, `uri_query`, `status`, `response_time`, `bytes_out`, `src`, `http_user_agent`. Knobs live in `config.json` (`log_dir`, `log_level`, `log_max_bytes`, `log_backup_count`) |
| Tunnel (Node) | `tunnel.log` + stdout/stderr | `tunnel/logger.js`; env `LOG_DIR`, `LOG_MAX_BYTES`, `LOG_LEVEL` |
| Browser SPA | `ui.log` | The SPA batches uncaught errors to `POST /api/v1/ui-logs` (unauthenticated by design, aggressively rate limited); the admin app writes them to `ui.log` |

### Audit shipping (ship-logs)

Security events are first-class database rows, not log lines: `auth_events`
(logins, MFA, OIDC anomalies), `audit_log` (every data plane access decision),
and `policy_changes` (admin mutations). The shipper
(`server/src/hyproxy/audit/shipping.py`, run via the CLI `ship-logs` command)
streams each table past a per-stream high-water cursor (`log_ship_cursors`
table) and only advances the cursor after the sink accepts the batch, giving
at-least-once delivery.

- **Sinks:** JSON lines to stdout (default; pipe into any syslog/OTLP
  forwarder), or `--to-file` appending to `<log_dir>/audit.log` with the same
  rotation scheme.
- **Format:** projected to Splunk CIM (Authentication/Change models): `src`,
  `user`, `app`, `action`, `signature`, `dest_port`, `object_category`,
  `object_id`, `severity`. A fixed high-severity set (break-glass credential
  used, auth code replay, refresh token reuse, stale-IP session, step-up
  failure, admin TOTP reset) is marked `severity: high` for SIEM alerting.
- **Scheduling:** in production `hyproxy-ship-logs.timer` runs
  `docker compose run --rm cli ship-logs --to-file` every 5 minutes. Ad hoc:
  `make ship-logs args="--batch-size 1000"`.
- **Changing it:** the shipper is deliberately a seam, not an integration.
  To ship off-box, point the timer's command at your forwarder (drop
  `--to-file` and pipe stdout), or tail `audit.log` with the collector of
  your choice. Alert on `severity:"high"`. Note the at-least-once caveat: ids
  are assigned before commit, so a row committing late with a smaller id than
  an already-shipped one can be skipped; a strict pipeline should ship with a
  small time-lag window.

## Security Implications

Things an operator or reviewer should know; each is deliberate, but several
have failure modes worth understanding.

**Key management**

- The master key exists in exactly two places: sealed in the TPM and the
  one-time plaintext printed during install. PCR drift (firmware or kernel
  update) makes the unseal fail and the whole control plane refuses to start.
  Reseal before rebooting into new firmware, or keep the printed backup.
- `HYPROXY_MASTER_KEY_FP` pins the expected key fingerprint. Without it, a
  resealed-but-different key would pass startup and then fail on every
  decrypt with AES-GCM `InvalidTag` (this outage has happened). Set it.
- Two different AES modes are in play: AES-256-GCM (with per-table AAD) for
  everything sealed at rest, and guacamole-lite's AES-256-CBC for the on-wire
  Guacamole token. They use unrelated keys; do not conflate them.
- The gateway's DPoP keypair is derived from the master key via HKDF, so it
  never touches disk but also rotates with the master key.

**Trust boundaries**

- The data plane strips `X-Forwarded-User`, `X-Auth-User-Id`, and
  `X-Auth-Roles` from every inbound request before injecting the authz
  service's values. Backends trust those headers entirely; removing that
  stripping is a full authentication bypass. The gateway cookie is likewise
  removed before proxying so backends never see gateway credentials.
- SSRF invariant: the proxy only ever dials backends from its own config file
  or from server-side DB rows. Nothing a client sends can name a dial target.
  Unknown hosts get a bare 421.
- `HYPROXY_TRUST_FORWARDED_FOR` must be consistent across every service.
  Sessions are bound to source IP; if one service derives the client IP
  differently than another, users get bounced into re-auth loops. Related:
  reaching the admin plane over a different network path (LAN) than the IdP
  (WAN) breaks IP-bound sessions by design.
- `HYPROXY_ADMIN_LAN_CIDRS` empty disables the admin API's network check.
  That is a dev convenience; production relies on it plus the data plane's
  `lan_only` route flag as two independent layers.

**Deliberate exposures**

- `POST /api/v1/ui-logs` is unauthenticated by design (the SPA must report
  errors even when auth is broken). It is capped by strict payload limits and
  in-memory per-IP/global rate buckets, intentionally not the DB-backed
  throttle, so log spam cannot become database load.
- The portal's download feature posts to qBittorrent with no credentials; it
  relies on qBittorrent's IP whitelist trusting the hyproxy host. The input
  is restricted by a magnet-only regex (BitTorrent v1 infohash) precisely so
  the URL field cannot be used for SSRF from qBittorrent's side.
- The Guacamole cypher key is a bearer secret for remote desktop targets.
  Mitigations: tokens live ~60 seconds, are single-use (consumed by a
  conditional UPDATE), are bound to the requesting IP, and require a live
  gateway session, so revoking the session tears down tunnel access.

**Host posture**

- The `hyproxy` service account is in the `docker` group, which is
  root-equivalent on the host. The account exists to avoid running the stack
  as root, but treat it as privileged.
- `hyproxy.service` grants `CAP_NET_BIND_SERVICE` so the data plane can bind
  :443 without root.
- `upstream_insecure_skip_verify` in the data plane config disables upstream
  TLS verification (for self-signed or IP-only backends such as media
  servers). It does not relax public TLS or the backend allowlist, but any
  backend using it gets no transport authentication on the internal hop.
- `dataplane/bin/` contains prebuilt, unstripped binaries checked into the
  repo. Installs build from source on the host (`make dp-build`); do not run
  the committed artifacts in production without rebuilding.

**Known sharp edges**

- Session cookies, auth codes, refresh tokens, CSRF tokens, and guac grants
  are stored only as SHA-256 hashes; recovery codes as argon2id. A database
  leak does not yield replayable credentials, but the audit `detail` column
  is additionally key-whitelisted so events can never carry secrets.
- The IdP's CSP `form-action` must include the gateway cookie domain when it
  is set to a parent domain; browsers enforce `form-action` across the whole
  redirect chain, and a too-narrow value silently cancels the post-login
  redirect (the login appears to succeed and nothing happens).
- Replay is treated as compromise: reuse of an auth code or refresh token
  revokes the entire token family and the issuing session, and emits a
  high-severity event.
