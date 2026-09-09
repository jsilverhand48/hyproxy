# Tech stack

Four languages, four independent toolchains. No monorepo tool; the root
`Makefile` is the only thing that ties them together.

## Python control plane (`server/`)

- Python **>= 3.13**, package `hyproxy` under `server/src/hyproxy` (src
  layout, hatchling build). Package manager: **uv** (`uv run`, `uv sync
  --frozen`); every Makefile target is `cd server && uv run ...`.
- FastAPI + uvicorn (3 ASGI apps + 1 bridge app from one codebase/image),
  async SQLAlchemy 2.0 + asyncpg, alembic, pydantic-settings.
- Crypto/auth: joserfc (JWT/JWK), argon2-cffi, pyotp + segno, `webauthn`,
  cryptography. httpx is a **runtime** dep (OIDC backchannel), not test-only.
- Dev group: pytest (+ pytest-asyncio, hypothesis, soft-webauthn), ruff, mypy
  **strict**, bandit, pip-audit.
- Pins that exist for a reason: `pyopenssl>=26` (CVE floor) forces
  `[tool.uv] override-dependencies = ["cryptography>=46"]` because test-only
  fido2 caps cryptography<45. Do not "fix" that override away.
- Postgres **17** and the schema depends on it: UUID, CITEXT, INET, JSONB,
  arrays, partial unique indexes, `gen_random_uuid()`. `pgcrypto` and `citext`
  must exist *before* the first migration (it does not create them).

## Go data plane (`dataplane/`)

- Plain `go build`, module in `dataplane/`. Deliberately near-zero
  dependencies: the only direct module dep is `oschwald/maxminddb-golang` for
  GeoIP. Log rotation, listener, and config loading are hand-rolled to keep it
  that way; prefer stdlib over adding a dep.
- Runs **baremetal**, never in Docker (needs `CAP_NET_BIND_SERVICE` for :443
  and keeps streaming off the container network path). There is no
  `dataplane/Dockerfile` on purpose.
- HTTP/1.1 only, upstream too (WebSockets need it; h2 flow control throttles
  high-bitrate media).

## React SPA (`ui/`)

- React 19 + TypeScript ~5.7 + Vite 6, npm. eslint + `tsc --noEmit` via
  `npm run lint`. Built output `ui/dist` is served by the admin FastAPI app.
- Deliberately **no react-router and no data-fetching library** (small bundle,
  strict CSP). Only runtime deps besides React: `guacamole-common-js`.
- No `ui/Dockerfile`: the SPA is compiled in the server image's first stage,
  so `VITE_*` values are baked at image build time.

## Node tunnel (`tunnel/`)

- Node 22, single runtime dependency `guacamole-lite`. No test framework;
  `npm run check` is `node --check server.js`.

## Containers

`docker-compose.yml`, project name `hyproxy`, everything published on
`127.0.0.1` only. One server image backs idp/admin/authz/migrate/cli/rtspbridge
(no CMD; compose supplies each command). Profiles: `app`, `tools`, `guac`
(needs `HYPROXY_GUAC_CYPHER_KEY`), `rtsp` (needs `HYPROXY_RTSP_CYPHER_KEY`).
Full service/port table in the root README.
