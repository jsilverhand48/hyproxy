# Deployment topology (hybrid: baremetal + containers)

hyproxy runs as a hybrid: the security-critical public edge stays on baremetal,
and every other module runs in a container. This is the deliberate split the
project was designed around; this document is the containerization reference.

## What runs where, and why

### Baremetal (the host, not in compose)

- **Go data plane** (`dataplane/`). It is the single public TLS ingress. It
  stays on the host because it:
  - owns the one public port and the host network stack (and the future
    raw-L4 listener seam, spec section 12);
  - reads the ACME-issued `tls_cert` / `tls_key` files directly and hot-reloads
    them in place (`internal/tlsconf`), so certificate renewal is a file write
    with no restart;
  - is the trust boundary that forward-auths every request, so it is kept as
    close to the metal and as simple to reason about as possible.
  It reverse-proxies by Host to the containerized services over their
  loopback-published ports (`127.0.0.1:8300/8400/8500/8600`).

- **Hardware root of trust (TPM).** In the production secrets posture the master
  key is sealed to the host TPM and unsealed into memory only
  (`HYPROXY_SECRETS_BACKEND=tpm`). The TPM is host hardware; see "Secrets" below
  for how the containers get the key.

### Containerized (`docker-compose.yml`)

| Service   | Image                     | Profile | Published (loopback) | Purpose |
|-----------|---------------------------|---------|----------------------|---------|
| postgres  | `postgres:17-alpine`      | default | `127.0.0.1:5433`     | data store |
| migrate   | `hyproxy-server:local`    | tools   | -                    | one-shot `alembic upgrade head` |
| cli       | `hyproxy-server:local`    | tools   | -                    | one-shot `hyproxy.cli` (keys, admin, clients, ship-logs) |
| idp       | `hyproxy-server:local`    | app     | `127.0.0.1:8300`     | OIDC provider |
| admin     | `hyproxy-server:local`    | app     | `127.0.0.1:8400`     | admin API + served SPA |
| authz     | `hyproxy-server:local`    | app     | `127.0.0.1:8500`     | policy decision point + gateway RP |
| guacd     | `guacamole/guacd:1.5.5`   | guac    | internal only        | Guacamole protocol daemon |
| tunnel    | `hyproxy-tunnel:local`    | guac    | `127.0.0.1:8600`     | guacamole-lite WebSocket bridge |

The three Python services share one image (`server/Dockerfile`), differing only
by their compose `command`. The React UI is compiled in a build stage of that
image and baked in at `/app/ui/dist` (`HYPROXY_ADMIN_UI_DIST`), so the admin
service serves it same-origin. `guacd` is never published; only `tunnel` reaches
it, on the internal bridge network.

Everything is published on `127.0.0.1` only. Nothing in compose is
internet-facing; the sole public listener is the baremetal data plane.

## Profiles

Compose profiles keep dev and prod out of each other's way:

- **default** (`docker compose up`): Postgres only. This is what `make up` uses
  for local development.
- **tools** (`docker compose run --rm migrate|cli ...`): one-shot migration and
  management containers.
- **app** (`docker compose --profile app up -d`): the control plane.
- **guac** (add `--profile guac`): guacd + tunnel, enabled only when
  `HYPROXY_GUAC_CYPHER_KEY` is set.

## Configuration

Compose reads the **repo-root `.env`** for variable substitution. Copy
`.env.example` to `.env` and set at least:

```
POSTGRES_PASSWORD=<strong password>
HYPROXY_ISSUER=https://idp.example.com
HYPROXY_ADMIN_UI_ORIGIN=https://admin.example.com
HYPROXY_SECRETS_BACKEND=file            # or tpm
HYPROXY_MASTER_KEY_FILE=/path/to/master.keys
# HYPROXY_GUAC_CYPHER_KEY=<base64 key>  # enables the guac profile
```

Container environment variables take precedence over any baked config, so the
DB host is pinned to the compose service name (`postgres:5432`) regardless of
what a stray `.env` file inside the image might say.

## Secrets

The `master_key` compose secret is mounted read-only into the control plane at
`/run/secrets/master_key`; its source file is
`${HYPROXY_MASTER_KEY_FILE:-./server/.dev/master.keys}` on the host.

- **file backend** (bridge / non-TPM hosts): the source is a plaintext key file.
  Keep it off the repo and restrict its permissions. This is a documented
  accepted risk to be retired before internet exposure.
- **tpm backend** (production): the key is sealed to the host TPM. A container
  cannot reach the TPM by default. Two supported options:
  1. Pass the TPM device into the control-plane services
     (`devices: ["/dev/tpmrm0:/dev/tpmrm0"]`) and install `tpm2-tools` in the
     server image, then wire `core/secrets.tpm_unseal` to `tpm2_unseal`; or
  2. Run the control plane on baremetal (where the TPM lives) and keep only
     Postgres and the guac bridge in containers.
  Pick per your threat model; option 2 keeps unsealed material entirely off the
  container runtime.

## Lifecycle

First run (once per deployment):

```sh
cp .env.example .env         # fill in production values
./bootstrap-prod.sh          # builds images, migrates, creates the admin, builds the data plane
```

Every start:

```sh
./start-prod.sh              # brings up the containers, then the baremetal data plane
```

Under the hood `start-prod.sh` does:

```sh
docker compose up -d --wait postgres
docker compose run --rm migrate
docker compose --profile app [--profile guac] up -d --wait
# then, on the host:
./dataplane/bin/dataplane -config dataplane/config.json
```

Useful operational commands:

```sh
docker compose --profile app logs -f            # tail control-plane logs
docker compose run --rm cli ship-logs           # off-box audit export (cron this)
docker compose run --rm cli gen-guac-key        # mint a guac cypher key
docker compose --profile app --profile guac down
```

## Production hardening still required

Containerization does not by itself make the stack internet-ready. The data
plane binary is built on the host but is not yet supervised; add a systemd unit
for it (and consider units that wrap the compose lifecycle) so it restarts on
failure. Then complete the `docs/production.md` section 5 checklist (TPM
migration, backend TLS verification, network segmentation, off-box logging, and
the security review) before opening the public port. Open items are tracked in
`docs/TODO.md`.
