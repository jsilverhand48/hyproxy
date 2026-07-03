# hyproxy

Identity-aware reverse proxy for a home lab (spec v4).

Phase 1 (control plane + IdP): Postgres data model, FastAPI admin CRUD API,
and a self-built OIDC provider with authorization code + PKCE, DPoP
sender-constrained tokens (RFC 9449), tiered MFA (TOTP for standard users,
WebAuthn/passkeys for admins), recovery codes, progressive-delay rate
limiting, signing-key rotation, and transactional auth auditing.

Phase 2 (data plane + policy): a transport-agnostic policy engine and
ext-authz decision point, a browser auth gateway (the data plane's OIDC
relying party), and a Go data plane that terminates TLS on a single public
port, routes by Host to allowlisted backends only, forward-auths every
request against the control plane, and injects identity headers after
stripping any client-supplied copies.

Phase 3 (admin UI): a React management-plane UI for users, roles, resources,
and policies, plus read-only audit and policy-change viewers. It is an OIDC
public client of the IdP using authorization code + PKCE + DPoP (a browser-held
non-extractable key), served same-origin by the admin app, with a WebAuthn
step-up redirect for mutations. Kept off the internet like the rest of the
management plane.

Phase 4 (Guacamole browser bridges): browser-only access to RDP/VNC/SSH
resources. Per-resource connection secrets are AES-256-GCM sealed; a broker
policy-checks and mints short-lived, single-use, IP-bound guacamole-lite tokens
(the browser never sees raw credentials); the Go data plane forward-auths and
consumes the grant on the tunnel WebSocket connect and reverse-proxies it to an
internal `tunnel/` (guacamole-lite) service that speaks guacd. The in-browser
client and guacd deployment are the remaining live-only pieces (see `ROLLOUT.md`).

Phase 5 (internet-exposure hardening): the software cores are built and tested,
the infrastructure is deployment. A TPM secrets backend (unseal isolated behind
a hook) plus zero-downtime master-key rotation (`rotate-master-key`); an off-box
audit shipper with severity classification (`ship-logs`); a DDNS decision core;
and a production-posture checklist. ACME DNS-01 uses a vetted client (lego/
certbot) feeding the data plane's existing cert hot-reload seam. See
`docs/production.md`.

See `ROLLOUT.md` for the phase-by-phase instructions.

## Layout

- `server/` Python package (`hyproxy`): IdP app (:8300), admin API (:8400,
  management plane only), authz service (:8500, internal: policy decision
  point + gateway RP), the policy engine, SQLAlchemy models, migrations,
  tests.
- `dataplane/` Go module: single-port TLS ingress, Host routing, forward-auth,
  reverse proxy. Pluggable listener seam (spec section 12) for a future
  raw-L4 transport.
- `ui/` React admin UI (Vite + TypeScript). Built to `ui/dist` and served by
  the admin app; see `ui/README.md`.
- `tunnel/` internal guacamole-lite service (Node): decrypts broker tokens and
  bridges the WebSocket to guacd. Never internet-facing; see `tunnel/README.md`.
- `docs/admin-access.md` management-plane access + break-glass runbook.
- `docs/security-notes.md` security posture; input to the security review.

## Request path (Phase 2)

```
browser --TLS--> data plane (:443) --Host routing--> forward-auth (/authz/check)
   |                                                       |
   |  unauthenticated: 302 to auth host /gateway/start     |  allow + identity headers
   v                                                       v
gateway RP (OIDC code+PKCE, DPoP) --> IdP login       allowlisted backend
```

## Scripts

Three top-level orchestration scripts wrap the `make` targets end to end:

- `./start-dev.sh` starts the whole stack for local development: database, migrations,
  dev keys/certs, admin UI, Go data plane, then IdP + admin + authz + data plane
  together. Ctrl-C stops all of them. Toggles: `SKIP_UI=1`, `FORCE_UI=1`,
  `WITH_TUNNEL=1`.
- `./bootstrap-prod.sh` performs the one-time first-run production setup: it
  builds the container images (the UI is compiled inside the server image), runs
  migrations, signing keys, the first admin, and OIDC clients inside containers,
  builds the baremetal data-plane binary, runs the gates, and then STOPS short
  of opening the public port. It is fail-closed and never self-signs certs. Run
  it once per deployment.
- `./start-prod.sh` starts the stack in production following the hybrid model:
  it hard-requires Docker (aborts if absent), fail-closes on any missing
  dependency, artifact, or config value, brings up the containerized Postgres +
  control plane (idp/admin/authz) + guac bridge, then starts the baremetal Go
  data plane (the single public ingress) in the foreground. It builds nothing.

Production runs as a **hybrid**: the Go data plane is the only baremetal piece
(the public TLS edge); everything else is containerized in `docker-compose.yml`
and published on loopback only. See `docs/deployment.md` for the full topology.

Production first run: `cp .env.example .env` and fill it in, author
`dataplane/config.json`, run `./bootstrap-prod.sh`, complete the
`docs/production.md` section 5 checklist, then `./start-prod.sh`. See
`docs/TODO.md` for open work and known gaps.

## Dev quickstart

Requires [uv](https://docs.astral.sh/uv/). Docker is optional: with Docker,
`make up` runs Postgres via compose; without it, `make up` falls back to a
user-space PostgreSQL 17 (downloaded to `server/.dev/`, managed over a unix
socket, no root needed).

```sh
make up          # start Postgres (compose, or user-space fallback)
make gen-keys    # dev master key file (server/.dev/master.keys)
make db-migrate  # alembic upgrade head
make check       # ruff + mypy --strict + unit tests
make test-integration
make test-e2e    # full login -> code -> DPoP -> refresh -> revocation flows

make gen-certs         # self-signed dev TLS (WebAuthn needs a secure context)
make bootstrap-admin args='--email you@example.com --name "You"'
make run-idp           # https://idp.localhost:8300
make run-admin         # http://127.0.0.1:8400 (loopback only)
make run-authz         # http://127.0.0.1:8500 (internal only)

make dp-test           # Go: gofmt + vet + unit tests
make dp-fuzz           # fuzz the Host/routing parser
make dp-run            # build and run the data plane (dataplane/config.example.json)

make ui-install        # npm install (Node 20+; dev machine has Node 26)
make ui-build          # build the SPA to ui/dist (served by the admin app)
make create-admin-ui-client args='--redirect-uri http://127.0.0.1:8400/callback'
HYPROXY_ADMIN_UI_ORIGIN=http://127.0.0.1:8400 make run-admin  # serve API + UI
```

Copy `.env.example` to `server/.env` and adjust `HYPROXY_DB_URL` (the
fallback DB URL is printed by `make db-up`). The cross-plane E2E
(`make test-e2e`) compiles the Go binary and runs it in front of live IdP and
authz services, so it needs the Go toolchain and dev certs present.

## Notable make targets

`rotate-key` / `rotate-key args='--activate'` (signing-key
publish-overlap-retire), `create-client` (register an OIDC relying party),
`gc` (expired DPoP jtis, gateway login states, retired keys), `audit`
(bandit + pip-audit), `dp-build` (compile the data plane).
