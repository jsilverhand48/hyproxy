# hyproxy: core

Identity-aware reverse proxy stack for self-hosted services. Repo dir is
`reverse_proxy`, but every artifact (package, env prefix, service account,
install dir) is named **hyproxy**. Target host OS: Rocky Linux.

## Documentation is the primary source of truth

This repo is unusually well documented, and the READMEs are maintained as part
of every change (see `mem:conventions`). **Read the relevant README before
exploring code**; they carry architecture, request flows, config references,
and the reasoning behind non-obvious invariants:

- `README.md` (root): architecture diagram, 4 request flows, all lifecycle
  scripts and their flags, full `.env` variable reference, logging/audit
  shipping, security implications.
- `dataplane/README.md`, `server/README.md`, `ui/README.md`,
  `tunnel/README.md`: per-module deep dives.

Stale doc references to know: `docs/TODO.md` predates several shipped features
(claims TPM unsealing and ACME are unimplemented; both are done) and points at
`ROLLOUT.md`, `docs/production.md`, `docs/deployment.md`, none of which exist.
`docs/` holds only `THEME-ASSETS.md` and `TODO.md`. `deploy/` was deleted; only
`install.sh`'s embedded scripts are canonical. `docker-compose.yml` still
bind-mounts `./deploy/initdb` (harmless leftover).

## Source map

| Path | Module | Memory |
|---|---|---|
| `dataplane/` | Go edge proxy, the only internet-facing process | `mem:dataplane/core` |
| `server/` | Python control plane: IdP, authz, admin/portal, RTSP bridge, CLI, migrations | `mem:server/core` |
| `ui/` | React SPA: admin console + user portal in one app | `mem:ui/core` |
| `tunnel/` | Node guacamole-lite WebSocket tunnel to guacd | `mem:tunnel/core` |
| `tests/` | pytest suite: `unit/`, `integration/`, `e2e/`, `rp/` (test relying party) |  |
| `install.sh` `build.sh` `start.sh` `stop.sh` | Lifecycle scripts, root README documents every flag | `mem:suggested_commands` |

## Project-wide invariants

- **SSRF invariant**: the proxy only ever dials backends named by its own
  config file or by server-side DB rows. Nothing a client sends can name a dial
  target. Unknown hosts get 421.
- **Fail closed everywhere**: authz transport error -> 503 (never
  pass-through); TPM unseal failure -> startup abort; malformed policy
  condition or time window -> deny; unrecognized authz cache condition -> not
  cacheable.
- **Header stripping is authentication**: the data plane strips inbound
  `X-Forwarded-User`, `X-Auth-User-Id`, `X-Auth-Roles` and the gateway cookie
  before injecting authz's values. Removing that stripping is a full auth
  bypass; backends trust those headers absolutely.
- **No plaintext secret at rest**: cookie secrets / auth codes / refresh
  tokens / CSRF tokens / grants are SHA-256; recovery codes argon2id; TOTP
  secrets, signing keys, connection secrets AES-256-GCM under the TPM master
  key. RTSP camera credentials are never stored at all.
- **Master key lives only in the TPM** (plus the one-time plaintext printed at
  install). There is no file backend and no `HYPROXY_SECRETS_BACKEND` flag.
- **One `.env` at the repo/install root** is the single source of truth for
  secrets and topology; unknown keys are silently ignored, so typos fail
  silently.
- **Applications are DB-driven, not config-driven**: adding a resource via the
  admin API makes the route live within `routes_refresh_secs` with no restart.
  `dataplane/config.json` holds only static infra routes and host-level config.
- `HYPROXY_TRUST_FORWARDED_FOR` must be identical across all services;
  sessions are source-IP bound, so divergent client-IP derivation causes
  re-auth loops.

Related: `mem:tech_stack`, `mem:suggested_commands`, `mem:conventions`,
`mem:task_completion`.
