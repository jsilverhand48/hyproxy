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

Attention: `start-prod.sh` currently supervises the Python and Go services as
foreground child processes. That is a single point of failure with no restart,
health checking, or log rotation.

- [ ] Per-service process supervision. Add systemd units (or equivalent) for
      idp, admin, authz, data plane, and the tunnel, with restart policies,
      resource limits, and journald logging. Retire the foreground supervisor in
      `start-prod.sh` in favor of `systemctl start` once units exist.
- [ ] Application containerization. `docker-compose.yml` only defines Postgres,
      and with a dev-only password (`devonly`) and the dev `deploy/initdb` seed.
      `start-prod.sh` hard-requires Docker but only the database runs under it;
      the app tiers do not. Decide the model: either add Dockerfiles for the app
      tiers and a real production compose/stack, or run the DB as managed
      Postgres and drop the hard Docker requirement. Today's split is honest but
      half-containerized.
- [ ] Production database secrets. Do not ship the compose `devonly` password to
      prod. Use a managed instance or inject the password from the secrets
      backend; keep `HYPROXY_DB_URL` out of the repo.
- [ ] Readiness gating. The start scripts launch services without waiting for
      upstreams to be healthy (e.g. the data plane starts before the IdP is
      accepting connections). Add health/readiness polling between tiers so a
      slow start does not surface as transient 502s.

## Security posture before opening the public port (docs/production.md section 5)

- [ ] Migrate off the `file` secrets backend to TPM; destroy any on-disk master
      key afterward.
- [ ] Enforce backend TLS verification (no insecure skip-verify); pin/trust the
      internal CA before enabling any https backend.
- [ ] Retire the dev-only `idp_verify_tls=false` authz->IdP backchannel setting.
- [ ] Network segmentation: keep the admin API, `/authz/check`, `/guac/consume`,
      the guac tunnel, and guacd internal; only the single public port and the
      out-of-band WireGuard admin path face any network.
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
- [ ] `*.localhost` name resolution. `run.sh` assumes the resolver maps
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
