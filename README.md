# hyproxy

Identity-aware reverse proxy for a home lab. Phase 1 implements the control
plane and a self-built OIDC identity provider (spec v4): Postgres data model,
FastAPI admin CRUD API, and an IdP with authorization code + PKCE, DPoP
sender-constrained tokens (RFC 9449), tiered MFA (TOTP for standard users,
WebAuthn/passkeys for admins), recovery codes, progressive-delay rate
limiting, signing-key rotation, and transactional auth auditing.

Later phases add the Go data plane (single public port 443 with SNI/Host
routing), the React admin UI, Guacamole browser bridges, and the TPM-backed
secrets broker. `dataplane/` and `ui/` are placeholders for those.

## Layout

- `server/` Python package (`hyproxy`): IdP app (:8300) + admin API (:8400,
  management plane only), SQLAlchemy models, alembic migrations, tests.
- `docs/admin-access.md` management-plane access + break-glass runbook.
- `docs/security-notes.md` security posture; input to the Phase 1 review.

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
```

Copy `.env.example` to `server/.env` and adjust `hyproxy_DB_URL` (the
fallback DB URL is printed by `make db-up`).

## Notable make targets

`rotate-key` / `rotate-key args='--activate'` (signing-key
publish-overlap-retire), `create-client` (register an OIDC relying party),
`gc` (expired DPoP jtis + retired keys), `audit` (bandit + pip-audit).
