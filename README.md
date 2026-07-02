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

Later phases add the React admin UI, Guacamole browser bridges, and the
TPM-backed secrets broker. `ui/` is a placeholder for the UI.

## Layout

- `server/` Python package (`hyproxy`): IdP app (:8300), admin API (:8400,
  management plane only), authz service (:8500, internal: policy decision
  point + gateway RP), the policy engine, SQLAlchemy models, migrations,
  tests.
- `dataplane/` Go module: single-port TLS ingress, Host routing, forward-auth,
  reverse proxy. Pluggable listener seam (spec section 12) for a future
  raw-L4 transport.
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
