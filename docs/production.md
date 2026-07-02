# Production hardening runbook (Phase 5)

Everything required before the single public port faces the internet. Nothing
here changes application behaviour; it replaces dev-only stand-ins with
production-grade infrastructure behind the seams the earlier phases left, then
runs the dedicated security review. Software cores that could be built and
tested in-repo are noted; the rest are deployment integrations.

## Bootstrapping and starting

Two scripts wrap this runbook:

- `./bootstrap-prod.sh` runs once per deployment. It validates the environment
  fail-closed, syncs pinned dependencies, applies migrations, ensures signing
  keys, creates the first admin, registers the `admin-ui` OIDC client, builds
  the admin UI and the data-plane binary, and runs the audit/vet gates. It
  stops before the public port is opened and prints the section 5 checklist.
- `./start-prod.sh` starts the stack on every boot. It hard-requires Docker,
  refuses to start if any dependency, artifact (`dataplane/bin/dataplane`,
  `ui/dist`), or configuration value (issuer, secrets backend, TLS material) is
  missing, brings up Postgres under `docker compose`, applies migrations, and
  launches the loopback IdP/admin/authz services behind the single public data
  plane. It builds nothing.

Sequence for a new deployment: author `server/.env` and
`dataplane/config.json`, obtain certificates (section 2), run
`./bootstrap-prod.sh`, complete the section 5 checklist and security review,
then `./start-prod.sh`. Under a real deployment prefer per-service systemd units
over the foreground supervisor (see `docs/TODO.md`).

## 1. TPM-backed master key (secrets broker)

Seam: the `SecretsBackend` protocol (`core/secrets.py`). `FileSecretsBackend` is
the dev stand-in; `TpmSecretsBackend` is a drop-in whose master keys are
unsealed from the TPM into memory only. Selected by `HYPROXY_SECRETS_BACKEND`.

Built + tested in-repo:
- `TpmSecretsBackend` adapter (TPM call isolated behind an injected `unseal`
  callable; the adapter is unit-tested without hardware).
- Master-key rotation (`core/reencrypt.py`, CLI `rotate-master-key`): re-wraps
  every sealed blob (TOTP secrets, signing keys, connection secrets) to the
  current master key. Integration-tested end to end (plaintext preserved,
  idempotent).

Deployment integration (needs a TPM, absent on the dev machine):
1. Seal a fresh `key_id:base64key` master-key file to the TPM under a PCR policy
   (tpm2-tools: `tpm2_create`/`tpm2_load`/`tpm2_unseal`). Point
   `HYPROXY_TPM_SEALED_BLOB` at it and wire `core/secrets.tpm_unseal` to run
   `tpm2_unseal` (it currently raises `NotImplementedError` as a clear hook).
2. Migrate off the file key WITHOUT downtime:
   - Add the new TPM key as an additional master key (it becomes current).
   - `hyproxy.cli rotate-master-key` re-wraps all ciphertext to it (old key
     still decrypts until each blob is rewrapped; runs in one transaction).
   - Set `HYPROXY_SECRETS_BACKEND=tpm`, restart, then destroy the file key.
- Invariant: no unsealed master-key material on disk in production.

## 2. ACME DNS-01 certificates

Seam: the data plane's TLS `GetCertificate` hot-reload (`internal/tlsconf`). It
re-reads the cert/key files live, so issuance/renewal is a matter of writing new
files; no restart, no data-plane code change.

Do NOT hand-roll ACME (global constraint: no hand-rolled crypto). Use a vetted
client:
- `lego` (Go) or `certbot` with a DNS-01 plugin for your DNS provider.
- DNS-01 works behind CGNAT and issues wildcard certs for the app subdomains.
- Point the client's output at the `tls_cert`/`tls_key` paths in the data-plane
  config; the hot-reload seam picks them up.
- Store the DNS provider credentials sealed (SecretsBackend) or in the client's
  own protected store; never in the repo.
- Schedule renewal with a safety margin (e.g. daily check, renew < 30 days to
  expiry). Renewal failures must alert (section 4). Use the ACME staging
  directory first, then production.

## 3. Dynamic DNS (DDNS)

Built + tested in-repo: the decision core (`ops/ddns.py`): idempotent (no update
when the record already matches), backoff-limited (a minimum interval between
set attempts, so provider errors don't storm), provider-agnostic (the provider
API and public-IP lookup are isolated behind small interfaces).

Deployment integration: implement `DnsProvider` for your DNS host, feed it the
current public IP (an IP-echo service), and run `update_if_needed` on a timer.
Coordinate the same provider credentials with ACME DNS-01. A simulated IP change
must propagate within the record TTL with no update storm.

## 4. Off-box logging and alerting

Built + tested in-repo: the shipper (`audit/shipping.py`, CLI `ship-logs`). It
streams `auth_events`, `audit_log`, and `policy_changes` past a per-stream
cursor as JSON lines, flags high-severity events, and advances the cursor only
after the sink accepts a batch (at-least-once). High-severity set: break-glass
login, OIDC code replay, refresh reuse, source-IP session invalidation, step-up
failure, admin TOTP reset, and any data-plane deny.

Deployment integration:
- Cron `hyproxy.cli ship-logs` and pipe stdout to a syslog/OTLP forwarder that
  writes to an append-only collector the proxy host cannot delete from.
- Alert on `severity: "high"` records (SIEM rule), especially
  `login.break_glass.used` and `oidc.refresh.reuse_detected`.
- Monitor NTP/clock skew: TOTP and token expiry depend on it.
- Concurrency caveat (reviewer item): the cursor advances by max BigInteger id;
  a row committing out of id order could be skipped. Acceptable for
  at-least-once export; a strict pipeline ships with a small time-lag window.

## 5. Production posture + final security review

Before exposing the public port:
- Backends: enforce TLS verification (no insecure skip-verify); pin/trust an
  internal CA before enabling any https backend.
- Retire the dev-only `idp_verify_tls=false`: the authz->IdP backchannel must
  verify (internal CA) or use a verified endpoint.
- Network segmentation: the admin API, `/authz/check`, `/guac/consume`, the
  guac tunnel, and guacd are all internal; only the single public port and the
  out-of-band WireGuard admin path face any network (docs/admin-access.md).
- Run the dedicated security review against `docs/security-notes.md`; every
  dev-only accepted risk there must have a production resolution. Close findings.
- Only then open the public port.

Exit: review sign-off; `make audit` (bandit + pip-audit), `make dp-test`
(gofmt + vet), fuzz corpora, and the full test suite all clean.
