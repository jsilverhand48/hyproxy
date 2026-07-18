# Data plane (Go)

The single internet-facing ingress for hyproxy. Terminates TLS on one public
port, routes by normalized Host header to allowlisted backends only,
forward-auths every application request against the control plane's
`/authz/check` (fails closed), drops bot traffic at the edge, and injects
identity headers after stripping any client-supplied copies. Runs baremetal
(not in Docker) so it can bind :443 with `CAP_NET_BIND_SERVICE` and keep
streaming traffic off the container network path.

## Layout

- `cmd/dataplane`: entrypoint and wiring (config -> loggers -> cert reloader
  -> authz client -> proxy -> listener), the DB route poller goroutine, and
  graceful shutdown (10s drain on SIGINT/SIGTERM).
- `internal/config`: config load + validation. The SSRF invariant is enforced
  here: backends must be absolute http(s) URLs with no path, and come only
  from this file or from control plane DB rows. `DisallowUnknownFields`, so
  a typoed key is a startup error, not silence.
- `internal/routing`: Host normalization + route table. `NormalizeHost`
  (lowercase, strip port and trailing dot, DNS label validation; bracketed
  IPv6 literals rejected by design) is the sole attacker-controlled parser
  and is fuzzed (`FuzzNormalizeHost`).
- `internal/listener`: the pluggable transport seam (interface only; the slot
  for a future raw-L4 transport).
- `internal/httpsl`: the v1 HTTPS listener. **HTTP/1.1 only**: WebSocket
  upgrades need it, and h2 flow control throttles high-bitrate media. No
  read/write timeouts (they would cut long streams and tunnels post-hijack);
  instead `ReadHeaderTimeout` 10s, `IdleTimeout` 90s, `MaxHeaderBytes` 64KB.
- `internal/tlsconf`: certificate hot-reload. `GetCertificate` re-checks the
  cert file mtime (at most once per second) and reloads; a bad reload keeps
  the old cert. TLS 1.2 floor. This is where ACME integration would slot in;
  today certs are managed externally (lego + systemd timer).
- `internal/authz`: forward-auth client (`/authz/check`, `/guac/consume`,
  `/authz/routes`), 5s timeout, tuned idle connection pool, fails closed.
- `internal/proxy`: the request handler (`server.go`), the allow-decision
  cache (`authzcache.go`), and the tuned upstream transport
  (`transport.go`).
- `internal/botfilter`: edge bot dropping (user agent, ASN, country, PTR)
  with a per-IP verdict cache.
- `internal/accesslog`: the canonical per-request access log.
- `internal/logrotate`: hand-rolled size-based rotating writer, so the binary
  keeps a near-zero dependency footprint (the only direct module dependency
  is `oschwald/maxminddb-golang` for the GeoIP lookups).

## Request path

1. TLS handshake (SNI-independent single cert), HTTP/1.1.
2. Bot filter (see below); a blocked request gets its connection closed with
   no response body (`panic(http.ErrAbortHandler)`).
3. `NormalizeHost`; unknown host -> **421 Misdirected Request** (reveal
   nothing, route nowhere).
4. Route kinds: the auth host (only `/gateway/*` and `/guac/token` are
   proxied to the control plane; everything else, including `/authz/check`
   and `/guac/consume`, is 404 to clients), guac tunnel routes (see below),
   `lan_only` routes, and ordinary app routes.
5. For auth-gated routes: extract the gateway cookie, POST `/authz/check`
   with `{host, method, uri, source_ip, backend_port, gateway_cookie}`.
   - `allow`: strip inbound `X-Forwarded-User`, `X-Auth-User-Id`,
     `X-Auth-Roles` (spoofed copies would be a full auth bypass), inject the
     control plane's values, remove the gateway cookie from the upstream
     Cookie header, replace `X-Forwarded-*`, proxy.
   - `auth_required` + GET/HEAD + redirect -> 302 into the login flow;
     otherwise 401.
   - anything else -> 403. A transport error to authz -> **503** (fail
     closed, never pass-through).

### Decision cache (`authzcache.go`)

Only `allow` decisions that the control plane explicitly marks
`cache_scope: "host"` are cached, for the server-provided TTL (capped at
60s), keyed by SHA-256 over host + port + source IP + cookie value (so raw
cookie secrets are never retained), max 4096 entries. Anonymous requests
never touch the cache. The cache is purged on any real route table change;
no-op poller swaps are detected and skipped so polling does not cap cache
lifetime. Denies are never cached: revocation must be immediate.

### Routes: static vs DB-driven

`routes` in the config file holds the **static infra routes only** (idp,
admin, the portal host), each an allowlisted backend origin. Application
routes are DB-driven: the proxy polls the control plane's internal
`/authz/routes` every `routes_refresh_secs` (default 10) and atomically
hot-swaps its route table, so an admin adding a resource makes the route live
with no restart. Static routes win on host conflict; a failed poll keeps the
last-good table; one bad row is skipped and logged, never fatal.

### Guacamole tunnel

Routes flagged `guac_tunnel` (or the `guac_tunnel_path` flag, which carves
`/guac/tunnel` out of a normal host such as the portal) require a `?token=`
query parameter and call `POST /guac/consume` instead of `/authz/check`. The
grant is single-use, IP-bound, and requires a live gateway session; on
success the WebSocket is reverse-proxied to `guac_backend` (the Node tunnel).

### Bot filter (`internal/botfilter`)

Signal order, cheapest first: user agent regex denylist (and optionally empty
UA) per request; then per-IP signals with a cached verdict
(`botfilter_cache_ttl_secs`, default 300): blocked ASNs (GeoLite2 ASN mmdb),
blocked countries (GeoLite2 Country mmdb), and reverse-DNS PTR suffix
matching (datacenter providers). PTR lookups fail **open** with a 2s timeout
so DNS hiccups never block real users. `block_any_resolvable_ptr` drops any
IP that has any PTR record; it is aggressive and over-blocks residential
ISPs, so leave it off unless you know your audience. Blocked requests are
dropped with a closed connection, not an error page.

### Streaming optimizations (`transport.go`)

Tuned for high-bitrate media through an auth-checking proxy: HTTP/1.1 forced
upstream as well, `MaxIdleConnsPerHost` 32 (the stdlib default of 2 starves
concurrent segment fetches), 64KB socket buffers, a pooled 64KB copy buffer,
and `FlushInterval: -1` on the reverse proxy so every write is flushed
immediately. The access log's response writer wrapper passes through
`Flush`/`Hijack`/`Unwrap` so streaming and WebSocket upgrades survive it.
Host-level kernel tuning (BBR congestion control) is installed by
`install.sh` and matters more than any of this on lossy WAN paths.

## Config reference (`config.json`)

See `config.example.json` for a working example. Loaded with unknown-field
rejection; validation errors abort startup.

| Field | Default | Meaning |
|---|---|---|
| `listen` | | Public listen address (`:443`) |
| `tls_cert` / `tls_key` | | Cert/key paths; hot-reloaded on change |
| `authz_url` | | Control plane authz base (`http://127.0.0.1:8500`) |
| `auth_host` | | Public hostname for the gateway endpoints |
| `auth_backend` | | Backend serving `/gateway/*` for the auth host (the authz service) |
| `gateway_cookie_name` | `__Secure-gw` | Cookie extracted for authz and stripped upstream |
| `guac_backend` | empty | Tunnel origin for DB vnc/rdp/ssh resources; empty disables guac routes |
| `routes_refresh_secs` | `10` | DB route poll interval |
| `lan_cidrs` | auto | LAN allowlist for `lan_only` routes; empty auto-detects host interface IPv4 subnets (fails closed if none resolve) |
| `lan_only_redirect` | empty | Where blocked GET/HEAD browsers are sent; non-GET/HEAD or empty -> 403 |
| `log_dir` | empty | Log directory; empty = stderr only |
| `log_level` | `info` | debug / info / warn / error |
| `log_max_bytes` | `52428800` | Rotation threshold |
| `log_backup_count` | `2` | Archives kept |
| `upstream_insecure_skip_verify` | `false` | Skip upstream TLS verification (self-signed or IP-only backends). Does not relax public TLS or the backend allowlist |
| `blocked_user_agents` | `[]` | Regex denylist, compiled at startup |
| `block_empty_user_agent` | `false` | Drop requests with no UA header |
| `blocked_asns` | `[]` | ASN denylist; requires `geoip_asn_db` |
| `blocked_countries` | `[]` | ISO alpha-2 denylist; requires `geoip_country_db` |
| `geoip_asn_db` / `geoip_country_db` | | Paths to MaxMind GeoLite2 `.mmdb` files (must exist when the matching list is non-empty) |
| `blocked_ptr_suffixes` | `[]` | Reverse-DNS suffixes to drop (e.g. cloud providers) |
| `block_any_resolvable_ptr` | `false` | Drop any IP with any PTR record (aggressive) |
| `botfilter_cache_ttl_secs` | `300` | Per-IP verdict cache TTL |
| `routes` | | Static infra routes: host -> `{backend, backend_port?, auth?, guac_tunnel?, guac_tunnel_path?, lan_only?}` |

Note: `config.example.json` documents everything, including bot filter and
`lan_only` fields a given deployment may not use; the rendered production
config is typically much smaller. `build.sh`/`install.sh` render
`config.json` from `.env` (`DP_*`, `*_BACKEND`, `ROUTES_REFRESH_SECS`
variables), but the file is plain JSON and hand-editable.

## Logging

Two outputs, both in the stack-wide JSON line scheme (`ts`, `level`,
`service: "dataplane"`, `msg`, extras):

- **Service log**: stderr always (journald) plus rotating
  `<log_dir>/dataplane.log` when `log_dir` is set.
- **Access log**: rotating `<log_dir>/dataplane-access.log`, file only,
  never stderr (per-request lines at streaming volume would drown journald).
  One line per request: `http_method`, `site`, `uri_path`, `uri_query`,
  `status`, `response_time` (ms), `bytes_out`, `src`, `http_user_agent`.

See the [root README](../README.md#logging-and-log-shipping) for the
whole-stack picture and the audit shipper (access **decisions** are also
recorded server-side in the `audit_log` table by `/authz/check` itself).

## Build and test

```sh
go build ./cmd/dataplane
go test ./...
go test ./internal/routing -fuzz=FuzzNormalizeHost -fuzztime=30s
./dataplane -config config.example.json
```

Or from the repo root: `make dp-build`, `make dp-test`, `make dp-fuzz`,
`make dp-run`. The only CLI flag is `-config <path>`.

`bin/` contains prebuilt binaries checked into the repo as artifacts;
installs build from source on the target host (`make dp-build`). Do not
deploy the committed binaries without rebuilding.

## Security invariants (summary)

- Backends come only from server-side config or DB rows; the proxy never
  dials anything a client can name (SSRF invariant).
- Identity headers and the gateway cookie are stripped from every inbound
  request before injection; backends must keep trusting only the proxy.
- Unknown hosts get 421; the auth host exposes exactly two path prefixes;
  internal authz endpoints are unreachable from outside.
- `lan_only` routes (the admin console) are invisible off-LAN even to
  authenticated users.
- Authz unavailability is a 503, never an open gate.
