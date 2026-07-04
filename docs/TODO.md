# hyproxy TODO

Forward-looking work: what is next, what is missing, and what was left rough and
needs attention. Grouped by theme; each item notes where it lives and why it
matters. `ROLLOUT.md` is the phase plan and `docs/production.md` is the
deployment runbook; this file tracks the gaps between "built and tested in-repo"
and "actually deployable and operated."

## Deployment integrations still open (from docs/production.md)

These are the seams the phases deliberately left. The cores are tested in-repo;
the integration is not wired.

- [ ] TPM secrets backend. `core/secrets.tpm_unseal` raises `NotImplementedError`
      as an explicit hook (`server/src/hyproxy/core/secrets.py:88`). Seal a
      master key to the TPM under a PCR policy and wire `unseal` to `tpm2_unseal`.
      Until then production runs on the `file` backend, which keeps unsealed
      key material on disk. This is the top pre-exposure blocker.
- [ ] ACME DNS-01 certificate issuance and renewal. No client is wired. Add a
      vetted client (lego/certbot with a DNS-01 plugin) writing to the data
      plane's `tls_cert` / `tls_key` paths (the hot-reload seam picks them up)
      and a renewal timer that alerts on failure. `start-prod.sh` fail-closes if
      the cert files are absent, so this is required before first prod start.
- [ ] DDNS provider. `ops/ddns.py` ships only the decision core plus a
      `DnsProvider` Protocol (`server/src/hyproxy/ops/ddns.py:15`). Implement a
      concrete provider for the real DNS host, feed it a public-IP source, and
      run `update_if_needed` on a timer. Share credentials with ACME DNS-01.
- [ ] Off-box log shipping. `ship-logs` emits JSON lines with severity flags but
      nothing consumes them. Cron it, pipe to a syslog/OTLP forwarder writing to
      an append-only collector the proxy host cannot delete from, and add a SIEM
      alert on `severity:"high"` (especially `login.break_glass.used` and
      `oidc.refresh.reuse_detected`).

## Production packaging and process management

The hybrid model is implemented (`docs/deployment.md`): the control plane, guac
bridge, and Postgres are containerized in `docker-compose.yml` with health
checks and `restart` policies; the Go data plane runs on baremetal. The gaps
below are what remains.

- [x] Application containerization. Done: `server/Dockerfile` (bakes the built
      UI), `tunnel/Dockerfile`, and a profiled `docker-compose.yml` (tools / app
      / guac) run every app module as a container. The compose file uses env
      substitution from the repo-root `.env`.
- [ ] Baremetal data-plane supervision. The data plane is still started in the
      foreground by `start-prod.sh` with no restart-on-crash. Add a systemd unit
      for it (and optionally units that wrap the compose lifecycle), then retire
      the foreground supervisor.
- [ ] TPM secrets in containers. The control-plane containers mount the master
      key as a file secret. For the TPM backend, either pass `/dev/tpmrm0` into
      those services and add `tpm2-tools` to the server image, or run the control
      plane on baremetal. Decide and wire it (`docs/deployment.md` "Secrets").
- [ ] Production database secrets. `POSTGRES_PASSWORD` defaults to `devonly` and
      `deploy/initdb` is a dev seed. Set a real password (Docker/OS secret, not
      committed) and review the init SQL before prod. Alternatively point
      `HYPROXY_DB_URL` at a managed instance and drop the compose Postgres.
- [ ] Readiness gating between tiers. `start-prod.sh` waits on compose health
      checks for the containers, but the baremetal data plane starts immediately
      after; a slow control-plane start can surface as transient 502s. Poll the
      IdP/authz loopback ports before starting the data plane.
- [ ] Pin and track the `guacamole/guacd` image (currently `1.5.5`) and the
      `node`/`python`/`postgres` base images; add them to whatever CVE/update
      process the Python and Go dependencies already use.

## Security posture before opening the public port (docs/production.md section 5)

- [ ] Migrate off the `file` secrets backend to TPM; destroy any on-disk master
      key afterward.
- [ ] Enforce backend TLS verification (no insecure skip-verify); pin/trust the
      internal CA before enabling any https backend.
- [ ] Retire the dev-only `idp_verify_tls=false` authz->IdP backchannel setting.
- [ ] Network segmentation: keep the admin API, `/authz/check`, `/authz/routes`,
      `/guac/consume`, the guac tunnel, and guacd internal; only the single public
      port and the out-of-band WireGuard admin path face any network. `/authz/routes`
      returns backend origins for the DB-driven route table and must never be
      client-reachable (it is served by the internal authz service, like `/authz/check`).
- [ ] Run the dedicated security review against `docs/security-notes.md` and
      close every dev-only accepted risk.

## Phase 4 (Guacamole) live-only pieces

- [ ] guacd deployment. `guacd` is a native Apache Guacamole daemon that is not
      part of this repo. Stand it up (internal only) and point
      `GUACD_HOST`/`GUACD_PORT` at it.
- [ ] In-browser Guacamole client. The `guacamole-common-js` front end that
      opens the tunnel WebSocket is the remaining browser piece (see
      `tunnel/README.md`). Wire it into the admin/portal UI.
- [ ] End-to-end guac smoke test against a real guacd (the in-repo tests cover
      token mint/consume and the tunnel decrypt, not a live RDP/VNC/SSH session).

## Engineering hygiene

- [ ] CI. There is no `.github/` workflow. Wire `make check`, `make audit`,
      `make dp-test`, and the integration/e2e suites into CI so the quality gates
      that `ROLLOUT.md` requires run on every change, not just locally.
- [ ] `*.localhost` name resolution. `start-dev.sh` assumes the resolver maps
      `*.localhost` to loopback and only warns otherwise. Document (or script,
      without editing `/etc/hosts` automatically) the host entries dev needs.
- [ ] Verify recorded phase status. Project memory notes "Phases 1-3 done, 4-5
      pending" while the git history has a "Phase 5 complete" commit and the
      README describes phase 5 cores as built. Reconcile the source of truth so
      onboarding is not misled.

## Nice-to-have follow-ups

- [ ] `ship-logs` cursor caveat: the cursor advances by max BigInteger id, so a
      row committing out of id order can be skipped (acceptable for
      at-least-once). If a strict pipeline is needed, add the small time-lag
      window noted in `docs/production.md`.
- [ ] Backup and restore runbook for the Postgres data (keys, sessions, audit
      trail) and a documented disaster-recovery path.
- [ ] Clock-skew monitoring (NTP): TOTP and token expiry depend on it; add an
      alert.
- [ ] Get rid of all comments across the code base except for install.sh
- [ ] Remove staging/dev concept and enviroment building. Installing this app
      should be fully productionized
- [ ] Create an automation to handle TPM
- [ ] Create unit tests for every part of the stack
- [ ] Start scripts should be able to automatically detect if a rebuild needs
      needs to be initiated if there were changes done to the source code that
      require rebuild.
- [ ] QR code for 2FA standard users