# Commands

Run `make` targets from the **repo root**; `uv` drives all Python invocations
(`cd server && uv run ...`). Full target list in the root README.

## Hard constraints from CLAUDE.md

- Do **not** run or start the project, and do not configure the system to run
  it. Do not commit. Do not read test files.
- Debugging happens on the remote host: `ssh hyproxy`, then `cd /opt/hyproxy`.
  Changes are made on the remote host, rebuilt with `./build.sh --clean`,
  stopped with `./stop.sh`.
- The dev machine has no Docker/podman, no root, and no guacd, so compose,
  the data plane on :443, and the end-to-end remote-desktop path cannot run
  locally. Use `make db-up` (user-space Postgres via `server/scripts/devdb.py`)
  instead of `make up`.

## Tests

Always: `pytest <path>::<test> -q --tb=short -p no:cacheprovider`, from
`server/` under `uv run`. Only the tests relevant to the change, never the full
suite unless explicitly asked. Redirect verbose runs:
`pytest <args> > /tmp/pytest.log 2>&1; tail -n 30 /tmp/pytest.log`.
The mk-2 / key-rotation e2e tests are order-dependent and flaky: ignore
failures there and do not investigate them.

Markers (`server/pyproject.toml`): `integration` needs a real Postgres, `e2e`
runs full flows through the test RP in `tests/rp/`. `asyncio_mode = "auto"`,
session-scoped loops.

| Target | Runs |
|---|---|
| `make test` | `pytest -m "not integration and not e2e" -q` |
| `make test-integration` / `make test-e2e` | the marked subsets |
| `make dp-test` | `gofmt -l . && go vet ./... && go test ./...` in `dataplane/` |
| `make dp-fuzz` | 30s fuzz of `FuzzNormalizeHost` (the only attacker-controlled parser) |

## Quality

`make lint` (ruff check + ruff format --check), `make fmt`, `make typecheck`
(mypy strict), `make check` (= lint + typecheck + test), `make audit` (bandit +
pip-audit). UI: `npm run lint` in `ui/` (eslint + `tsc --noEmit`).

## Schema

`make db-revision m="message"` (autogenerate against `Base.metadata`) then
`make db-migrate` (`alembic upgrade head`). `alembic.ini` lives at
`server/`, and `alembic/env.py` uses the app's `HYPROXY_DB_URL`.

## Management CLI

`python -m hyproxy.cli <cmd>` (dev, via uv) or
`docker compose run --rm cli <cmd>` (prod). No console scripts exist. Makefile
wrappers: `rotate-key`, `bootstrap-admin`, `create-client`,
`create-admin-ui-client`, `gc`, `gen-guac-key`, `gen-rtsp-key`,
`rotate-master-key`, `ship-logs args="..."`. Full command/flag table in the
root README.

## Lifecycle scripts (production host only)

`sudo ./install.sh` (one-command Rocky install), `./start.sh` (foreground full
stack; systemd `hyproxy.service` runs it), `./stop.sh` (idempotent teardown),
`./build.sh [--clean]`.

**`build.sh` is not just a build**: its exit trap is a superset of `stop.sh`, so
running it on a live box stops the data plane, the compose project, the systemd
units, and dev processes. Run `./start.sh` afterwards.
