# Updating and redeploying

How to take a code change from a working tree to a running deployment. Read
alongside `docs/production.md` (prod runbook), `docs/staging.md` (LAN staging),
and `docs/deployment.md` (topology). Supported platform: Rocky Linux only.

## Mental model

The stack is a hybrid (`docs/deployment.md`):

- **Control plane** (Python: idp / admin / authz, plus Postgres and the optional
  guac bridge) runs in containers from `docker-compose.yml`, published on
  `127.0.0.1` only. The image `hyproxy-server:local` is built from
  `server/Dockerfile`; the admin SPA in `ui/` is compiled inside that image.
- **Data plane** (Go, `dataplane/`) is a baremetal binary: the single public TLS
  ingress on `:443`. It is supervised by `deploy/systemd/hyproxy-dataplane.service`
  and reverse-proxies to the loopback-published control plane.

What git tracks vs. what each host generates:

| In git | Generated on the host (never committed) |
|--------|-----------------------------------------|
| Source, `docker-compose.yml`, scripts, `dataplane/config.example.json` | `dataplane/bin/dataplane` (built by `make dp-build`) |
| Migrations (`server/alembic/`) | `dataplane/config.json` (rendered from `.env`) |
| `.env.example` and friends | container images, Postgres volume, secrets, ACME certs |

Because the binary and `config.json` are gitignored, a fresh checkout has neither:
they are rebuilt / re-rendered per host during bootstrap or redeploy.

## Update lifecycle (author to deploy)

1. **Develop** on a branch. Keep changes behind the existing seams.
2. **Run the gates locally** before landing:
   - Python + UI: `make check` (lint, typecheck, tests) and `make audit`
     (bandit, pip-audit).
   - Data plane: `make dp-test` (gofmt, vet, tests); `make dp-fuzz` for parser
     changes.
3. **Land the change** in git (commit + push to the canonical remote).
4. **Bring the deploy host to the target commit** (`git -C <repo> pull`, or fetch
   and reset to the reviewed commit). Certs, secrets, `.env`, the rendered
   `config.json`, and the built binary are untracked, so a pull never disturbs
   them.
5. **Apply the redeploy steps for what changed** (matrix below).
6. **Verify** (smoke tests below).

## What to redeploy, by change type

Run these from the repo root on the deploy host, after loading `.env`
(`set -a && . ./.env && set +a`).

### Control-plane Python (`server/src/hyproxy/**`, idp / admin / authz)
Rebuild the image and recreate the containers:
```sh
docker compose --profile app build
docker compose --profile app up -d --wait   # recreates only changed services
```

### Admin SPA (`ui/**`)
The SPA is compiled into the server image with `VITE_IDP_ISSUER` /
`VITE_ADMIN_UI_CLIENT_ID` baked in, so it needs the same rebuild path. Ensure
`HYPROXY_ISSUER` is set (compose forwards it as the build arg) or the SPA points
at the wrong issuer:
```sh
docker compose --profile app build          # recompiles ui/ inside the image
docker compose --profile app up -d --wait   # 'admin' serves the new bundle
```

### Data-plane Go (`dataplane/**`)
Rebuild, redeploy the binary to the systemd location, restart. See the gotcha
section: the unit runs from a system path, not the repo.
```sh
make dp-build
sudo install -m 0755 dataplane/bin/dataplane /opt/hyproxy/dataplane/bin/dataplane
sudo restorecon /opt/hyproxy/dataplane/bin/dataplane   # SELinux (fcontext already set)
sudo systemctl restart hyproxy-dataplane
```

### Routes / data-plane config (add or change app backends)
The data plane loads `config.json` once at startup and only hot-reloads the TLS
cert/key files, so a route or backend change needs a restart:
```sh
deploy/render-dataplane-config.sh            # or hand-edit; add APP_ROUTES_JSON
sudo install -m 0644 dataplane/config.json /opt/hyproxy/dataplane/config.json
sudo systemctl restart hyproxy-dataplane
```

### Python dependencies (`server/pyproject.toml`, `server/uv.lock`)
Edit `pyproject.toml`, regenerate the lock (`cd server && uv lock`), commit both,
then rebuild the image (the Dockerfile runs `uv sync --frozen`). A lock that does
not match `pyproject.toml` fails the build fast.

### Host toolchain / `bootstrap-prod.sh`
`bootstrap-prod.sh` is idempotent and installs only what is missing, so re-running
it after a toolchain or firewall change is safe. It will not restart running
services.

### Database migrations (`server/alembic/`)
Migrations run in a one-shot container and MUST be applied before starting
control-plane code that expects the new schema. Order the deploy as build ->
migrate -> up:
```sh
docker compose --profile app build
docker compose run --rm migrate             # alembic upgrade head
docker compose --profile app up -d --wait
```
Write migrations to be backward compatible (expand, then contract in a later
release) so the old and new code can overlap during the rollout.

### Environment / `.env`
Which change needs what:
- `HYPROXY_ISSUER` or `HYPROXY_ADMIN_UI_ORIGIN`: rebuild the image (baked into the
  SPA), re-render `config.json` (host names derive from it), restart both planes.
- `POSTGRES_PASSWORD`: see the drift gotcha below. Do not assume editing `.env`
  changes the database password.
- `DP_LISTEN` / cert paths: re-render `config.json`, restart the data plane, and
  reopen the firewall port if it changed (`bootstrap-prod.sh` handles the port).

### TLS certificates
Renewal is automated by `hyproxy-acme.timer` and hot-reloaded by the data plane,
so no restart and no code deploy is involved. To force a check:
`sudo systemctl start hyproxy-acme.service`.

## Standard redeploy (most changes)

```sh
cd <repo> && git pull
set -a && . ./.env && set +a

docker compose --profile app build          # if server/ ui/ or deps changed
docker compose run --rm migrate             # if a migration was added
docker compose --profile app up -d --wait

make dp-build && \
  sudo install -m 0755 dataplane/bin/dataplane /opt/hyproxy/dataplane/bin/dataplane && \
  sudo restorecon /opt/hyproxy/dataplane/bin/dataplane && \
  sudo systemctl restart hyproxy-dataplane   # only if dataplane/ or config changed
```

Downtime: recreating a control-plane container is a brief blip on that host (the
others keep serving); restarting the data plane drops in-flight connections for a
moment. There is no built-in blue/green.

## The data-plane redeploy gotcha

The systemd unit runs the binary and `config.json` from a system path
(`/opt/hyproxy/dataplane`, the unit's `WorkingDirectory`), NOT from the repo. Two
reasons: SELinux (enforcing on Rocky) refuses to exec a binary that carries a
home-dir or tmp type, and the deploy should not depend on the checkout location.
So every data-plane or route change has an explicit copy-into-`/opt` step, and the
binary must keep its `bin_t` label:

```sh
sudo semanage fcontext -a -t bin_t '/opt/hyproxy/dataplane/bin/dataplane'  # once
sudo restorecon /opt/hyproxy/dataplane/bin/dataplane                        # after each copy
```

`make dp-build` alone changes nothing that is running until the binary is copied
to `/opt` and the unit restarted.

## Rollback

- **Code:** check out the previous commit and re-run the matching redeploy steps
  (rebuild image + `up -d` for the control plane; rebuild + copy + restart for the
  data plane). Keep the previous data-plane binary (for example
  `dataplane/bin/dataplane.prev`) so a data-plane rollback is just a copy plus
  `systemctl restart`.
- **Images** are tagged only `hyproxy-server:local` (overwritten each build), so
  there is no image history to roll back to. For real rollback capability, tag
  builds by git sha and push to a registry; then `up -d` can pin an older tag.
- **Migrations:** prefer forward fixes. `alembic downgrade` exists but is only
  safe for reversible migrations and can lose data. This is why migrations should
  be expand-then-contract.

## Verify after any redeploy

```sh
docker compose --profile app ps                 # all services healthy
systemctl status hyproxy-dataplane --no-pager    # active (running)
# through the public ingress (map the host to the VM if DNS does not):
curl --resolve idp.<domain>:443:127.0.0.1 https://idp.<domain>/.well-known/openid-configuration
curl --resolve nope.<domain>:443:127.0.0.1 -o /dev/null -w '%{http_code}\n' https://nope.<domain>/   # expect 421
```
A green run: control-plane containers healthy, the data plane active, idp
discovery returns the expected `issuer`, and an unknown Host returns 421.

## Recurring gotchas

- **SPA issuer is build-time.** Changing `HYPROXY_ISSUER` requires an image
  rebuild, not just a container restart; the old issuer is otherwise compiled into
  the served bundle.
- **Postgres password drift.** `POSTGRES_PASSWORD` is set only when the data
  volume is first initialized. Editing `.env` later does not change the stored
  role password (local socket auth hides this; app containers fail on TCP auth).
  Realign with `ALTER USER hyproxy WITH PASSWORD ...`, do not just recreate the
  container.
- **Untracked artifacts after a pull.** A fresh checkout has no
  `dataplane/bin/dataplane` and no `dataplane/config.json`; run `make dp-build`
  and `deploy/render-dataplane-config.sh` (or `bootstrap-prod.sh`, which does
  both) before `start-prod.sh`, which fails closed if either is missing.
- **Data plane hot-reloads certs only.** Route, backend, and listen changes need a
  restart; cert file changes do not.
