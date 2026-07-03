# Production hardening runbook (Phase 5)

Everything required before the single public port faces the internet. Nothing
here changes application behaviour; it replaces dev-only stand-ins with
production-grade infrastructure behind the seams the earlier phases left, then
runs the dedicated security review. Software cores that could be built and
tested in-repo are noted; the rest are deployment integrations.

## Bootstrapping and starting

Production runs as a hybrid: the control plane is containerized and the Go data
plane runs on baremetal. `docs/deployment.md` is the full topology reference.
Supported platform: Rocky Linux only for now (the scripts use `dnf` and
`firewalld`). For a hands-off install, `install.sh` prompts for config and runs
the whole sequence end to end (`docs/production-checklist.md`); the rest of this
section is the manual path it automates. Two scripts wrap this runbook:

- `./bootstrap-prod.sh` runs once per deployment. On Rocky Linux it first
  installs any missing host dependencies (Docker + the compose plugin, the Go
  toolchain, make, uv, and lego) and opens the public data-plane port in
  `firewalld`. It then validates the environment fail-closed, builds the
  container images (the UI is compiled inside the server image), applies
  migrations, ensures signing keys, creates the first admin, and registers the
  `admin-ui` OIDC client (all inside containers), builds the baremetal
  data-plane binary, and runs the audit/vet gates. It stops before starting the
  public ingress and prints the section 5 checklist. It is idempotent: it only
  installs or opens what is missing, so re-running is safe.
- `./start-prod.sh` starts the stack on every boot. It hard-requires Docker,
  refuses to start if any dependency, artifact (`dataplane/bin/dataplane`,
  `dataplane/config.json`), or configuration value (issuer, secrets backend, TLS
  material) is missing, brings up the containerized Postgres + control plane +
  guac bridge via `docker compose`, and then starts the baremetal data plane as
  the single public ingress. It builds nothing.

Sequence for a new deployment: copy `.env.example` to the repo-root `.env` and
fill it in, author `dataplane/config.json`, obtain certificates (section 2), run
`./bootstrap-prod.sh`, complete the section 5 checklist and security review,
then `./start-prod.sh`. The containerized services carry compose `restart`
policies; supervise the baremetal data plane with the shipped
`deploy/systemd/hyproxy-dataplane.service` (enable it instead of leaving
`start-prod.sh` in the foreground). Two host-integration notes learned on staging:

- SELinux (enforcing, e.g. RHEL/Rocky): systemd (`init_t`) cannot exec a binary
  that carries a home-dir/tmp type. Deploy the data-plane binary + `config.json`
  under a system path (the unit assumes `/opt/hyproxy`), not under `/root` or the
  build tree, and label the binary `bin_t` (`semanage fcontext -a -t bin_t ...;
  restorecon`) so the label survives a relabel. Run it de-privileged as `hyproxy`
  with `AmbientCapabilities=CAP_NET_BIND_SERVICE` to bind the public port.
- Host firewall: the single public port is not reachable until it is opened.
  `bootstrap-prod.sh` opens it in `firewalld` (derived from `DP_LISTEN` /
  `dataplane/config.json`, default 443); to do it by hand,
  `firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload`. The
  control-plane ports stay loopback-published and must NOT be opened.

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

The repo ships a ready lego DNS-01 flow (validated on staging, `docs/staging.md`):
- `deploy/acme/obtain-cert.sh` issues/renews the wildcard and installs it atomically
  into the data-plane paths (the key is written `0640` to `DP_TLS_GROUP` so a
  de-privileged data plane can read it); the hot-reload seam serves it with no
  restart. `deploy/acme/hyproxy-acme.{service,timer}` run the daily renewal check.
- Non-secret knobs and provider API credentials go in a root-owned `/etc/hyproxy/acme.env`
  (`0600`), never in the repo.
- lego v5 folds issue and renew into a single `run` subcommand, and its flags are
  subcommand-scoped (they follow `run`); the script accounts for both.
- Dry-run against the Let's Encrypt STAGING CA first (`ACME_STAGING=1`). The staging
  and production certs share lego's `certificates/` dir, so remove the staging
  artifact (`_.<domain>.*`) before issuing the real cert, or the "cert exists ->
  renew" path will keep serving the untrusted one.
- If the host cannot reach a public resolver to self-verify TXT propagation (e.g.
  a NAT-only VM whose only resolver caches NXDOMAIN), set `LEGO_DNS_PROPAGATION_WAIT`
  to skip the self-check and wait a fixed window; Let's Encrypt validates from its
  own resolvers regardless.

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
