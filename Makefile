SHELL := /bin/bash
SERVER := server
UV := cd $(SERVER) && uv run

UI := ui
TUNNEL := tunnel

.PHONY: up down db-up db-down db-migrate db-revision gen-keys run-idp run-admin \
        bootstrap-admin create-client create-admin-ui-client rotate-key gc lint fmt typecheck \
        test test-integration test-e2e check audit ui-install ui-build ui-dev \
        gen-guac-key tunnel-install tunnel-run

## --- Dev database ---------------------------------------------------------
# Preferred: Docker Compose. Fallback (no Docker): pgserver via scripts/devdb.py.
up:
	@if command -v docker >/dev/null 2>&1; then \
		docker compose up -d --wait; \
	else \
		echo "docker not found; using pgserver fallback"; \
		$(MAKE) db-up; \
	fi

down:
	@if command -v docker >/dev/null 2>&1; then \
		docker compose down; \
	else \
		$(MAKE) db-down; \
	fi

db-up:
	$(UV) python scripts/devdb.py start

db-down:
	$(UV) python scripts/devdb.py stop

## --- Database schema ------------------------------------------------------
db-migrate:
	$(UV) alembic upgrade head

db-revision:
	$(UV) alembic revision --autogenerate -m "$(m)"

## --- Keys and bootstrap ---------------------------------------------------
gen-keys:
	$(UV) python -m hyproxy.cli gen-keys

gen-certs:
	$(UV) python scripts/gen_dev_certs.py

rotate-key:
	$(UV) python -m hyproxy.cli rotate-signing-key $(args)

bootstrap-admin:
	$(UV) python -m hyproxy.cli bootstrap-admin $(args)

create-client:
	$(UV) python -m hyproxy.cli create-client $(args)

gc:
	$(UV) python -m hyproxy.cli gc

## --- Run ------------------------------------------------------------------
run-idp:
	$(UV) uvicorn hyproxy.idp.app:app --host 127.0.0.1 --port 8300 \
		--ssl-keyfile .dev/certs/idp.localhost-key.pem \
		--ssl-certfile .dev/certs/idp.localhost.pem

run-admin:
	$(UV) uvicorn hyproxy.admin.app:app --host 127.0.0.1 --port 8400

run-authz:
	$(UV) uvicorn hyproxy.authz.app:app --host 127.0.0.1 --port 8500

## --- Admin UI (React) -------------------------------------------------------
# The SPA is served by the admin app from ui/dist. Register its OIDC client and
# run the admin app with HYPROXY_ADMIN_UI_ORIGIN set (enables the IdP CORS
# allowance and the step-up return target). Example:
#   make create-admin-ui-client args='--redirect-uri http://127.0.0.1:8400/callback'
#   HYPROXY_ADMIN_UI_ORIGIN=http://127.0.0.1:8400 make run-admin
create-admin-ui-client:
	$(UV) python -m hyproxy.cli create-client --client-id admin-ui --name "Admin UI" $(args)

ui-install:
	cd $(UI) && npm install

ui-build:
	cd $(UI) && npm run build

ui-dev:
	cd $(UI) && npm run dev

## --- Guacamole tunnel (Phase 4) ---------------------------------------------
# Generate the shared AES-256-CBC key, set it as HYPROXY_GUAC_CYPHER_KEY on the
# control plane AND pass the SAME value to the tunnel as GUAC_CYPHER_KEY. guacd
# is a separate native daemon (Apache Guacamole); point GUACD_HOST/PORT at it.
gen-guac-key:
	$(UV) python -m hyproxy.cli gen-guac-key

tunnel-install:
	cd $(TUNNEL) && npm install

tunnel-run:
	cd $(TUNNEL) && npm start

## --- Data plane (Go) --------------------------------------------------------
dp-build:
	cd dataplane && go build -o bin/dataplane ./cmd/dataplane

dp-test:
	cd dataplane && gofmt -l . && go vet ./... && go test ./...

dp-fuzz:
	cd dataplane && go test ./internal/routing -fuzz=FuzzNormalizeHost -fuzztime=30s

dp-run: dp-build
	cd dataplane && ./bin/dataplane -config config.example.json

## --- Quality --------------------------------------------------------------
lint:
	$(UV) ruff check src tests scripts
	$(UV) ruff format --check src tests scripts

fmt:
	$(UV) ruff format src tests scripts
	$(UV) ruff check --fix src tests scripts

typecheck:
	$(UV) mypy

test:
	$(UV) pytest -m "not integration and not e2e" -q

test-integration:
	$(UV) pytest -m integration -q

test-e2e:
	$(UV) pytest -m e2e -q

check: lint typecheck test

audit:
	$(UV) bandit -q -r src -c pyproject.toml || $(UV) bandit -q -r src
	$(UV) pip-audit
