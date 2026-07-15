# Edge bot / robot traffic filter

The data plane drops automated/bot traffic at the edge, before any routing or
authorization work. Enforced in the Go data plane (`dataplane/internal/botfilter`)
at the top of `Server.ServeHTTP`, so it covers every host (app, auth, and
unknown) and spends nothing on traffic it rejects.

For the broader per-phase security record, see `docs/security-notes.md`.

## What it does

Two independent signals; a match on either drops the request:

1. **User-Agent denylist** (per request). The `User-Agent` header is matched
   against configured regular expressions; optionally an empty/absent UA is
   dropped too. Cheap, never cached.
2. **Source-IP network reputation** (cached per source IP). A "does this look
   like datacenter, not residential" heuristic, evaluated cheapest-first:
   - **ASN** — MaxMind GeoLite2-ASN lookup; drop if the IP's autonomous system
     number is in the blocklist (cloud/hosting providers).
   - **Geo** — MaxMind GeoLite2-Country lookup; drop by ISO country code.
   - **Reverse DNS (PTR)** — drop if the IP reverse-resolves to a configured
     hosting suffix (e.g. `amazonaws.com`). An IP that resolves to a hosting
     domain is almost never a residential/public-wifi client. The PTR query is
     time-bounded (2s) and **fails open** on any resolver error or timeout, so a
     DNS hiccup never blocks a legitimate user.

TLS is terminated at the data plane, so the `User-Agent` and the real client IP
are already plaintext here; no separate decryption is needed.

### Block action

A blocked request has its **connection dropped** via `panic(http.ErrAbortHandler)`:
net/http closes the connection with **no HTTP response** and no stack-trace log.
The drop is recorded as a single service-log line:

```
bot_filter drop  host=<host> source_ip=<ip> reason=<reason> user_agent=<ua>
```

`reason` is one of `bad_user_agent`, `blocked_asn`, `blocked_geo`, `blocked_ptr`.

There is intentionally **no good-bot allowlist**: search-engine crawlers and
uptime monitors matching a signal are dropped too. This will de-index the sites
from search engines. Narrow the denylist if that matters.

## Configuration

Static fields in the data-plane config JSON (`dataplane/config.json`; the loader
rejects unknown keys). All fields are optional; if none are set the filter is
disabled entirely and adds zero per-request cost. See
`dataplane/config.example.json` for a populated example.

| Field | Type | Meaning |
|-------|------|---------|
| `blocked_user_agents` | `[]string` | RE2 regexes matched against `User-Agent`. Any match drops. Use `(?i)` for case-insensitive. |
| `block_empty_user_agent` | `bool` | Drop requests with no `User-Agent` header. |
| `blocked_asns` | `[]uint` | Autonomous system numbers to drop. Requires `geoip_asn_db`. |
| `blocked_ptr_suffixes` | `[]string` | Reverse-DNS hostname suffixes to drop (e.g. `amazonaws.com`). |
| `block_any_resolvable_ptr` | `bool` | Aggressive: drop ANY IP that returns a PTR record. Off by default (see caveat). |
| `blocked_countries` | `[]string` | ISO 3166-1 alpha-2 country codes to drop. Requires `geoip_country_db`. |
| `geoip_asn_db` | `string` | Path to a MaxMind GeoLite2-ASN `.mmdb`. Required (and must exist) when `blocked_asns` is set. |
| `geoip_country_db` | `string` | Path to a MaxMind GeoLite2-Country `.mmdb`. Required (and must exist) when `blocked_countries` is set. |
| `botfilter_cache_ttl_secs` | `int` | Per-source-IP verdict cache lifetime. Defaults to 300. |

Config is validated at load: bad regexes, malformed country codes, and missing
`.mmdb` files (when their block list is non-empty) fail startup.

### Caveat: `block_any_resolvable_ptr`

Presence of a PTR record does **not** reliably mean datacenter. Many residential
ISPs assign PTRs (`comcast.net`, `rr.com`, ...), so this mode over-blocks real
users. Prefer a curated `blocked_ptr_suffixes` list. The aggressive toggle is
provided for hosts that only ever serve a known audience.

### Example

```json
{
  "blocked_user_agents": [
    "(?i)(bot|crawler|spider|scrapy)",
    "(?i)(curl|wget|python-requests|go-http-client|libwww-perl)"
  ],
  "block_empty_user_agent": false,
  "blocked_ptr_suffixes": [
    "amazonaws.com", "googleusercontent.com", "cloudfront.net",
    "digitalocean.com", "linode.com", "ovh.net", "your-server.de"
  ],
  "blocked_asns": [16509, 14618, 15169, 8075, 14061, 16276, 24940, 63949],
  "blocked_countries": [],
  "geoip_asn_db": "/opt/hyproxy/geoip/GeoLite2-ASN.mmdb",
  "geoip_country_db": "/opt/hyproxy/geoip/GeoLite2-Country.mmdb",
  "botfilter_cache_ttl_secs": 300
}
```

The ASNs above are AWS (16509, 14618), Google (15169, 8075), Azure (8075 is
Microsoft; also 8068/8069), OVH (16276), DigitalOcean (14061), Hetzner (24940),
and Linode/Akamai (63949). Confirm current allocations before relying on them;
ASN ownership changes.

## Obtaining the MaxMind databases

ASN and geo blocking are **inert without the `.mmdb` files** (the regex and PTR
signals work standalone). GeoLite2 is free but requires an account:

1. Create a free MaxMind account and generate a license key.
2. Install `geoipupdate` (or script the download) and fetch `GeoLite2-ASN` and
   `GeoLite2-Country`.
3. Place the `.mmdb` files where `geoip_asn_db` / `geoip_country_db` point
   (e.g. `/opt/hyproxy/geoip/`).
4. Refresh them on a schedule (MaxMind updates weekly) via a `geoipupdate` cron.
   The data plane opens the files at startup; refreshed files apply on the next
   restart.

## Testing

### Unit tests (no live service)

```
cd dataplane
go test ./internal/botfilter/... -run TestDecide -count=1
```

Covers each signal against injected fakes (bad UA, empty UA, ASN hit, country
hit, PTR suffix hit, PTR-error-fails-open, clean residential IP, block-any-PTR).
No real `.mmdb` files needed. Build/vet the whole data plane with
`go build ./... && go vet ./...`.

### Local / staging smoke test

Rebuild and start per `CLAUDE.md` (`./build.sh --clean`, then `./start-staging.sh`),
then from a machine that is NOT in a blocked network:

```
# Bad user-agent -> connection dropped (curl reports connection reset / empty reply)
curl -k -A "python-requests/2.31.0" https://<host>/

# Normal browser UA from a residential IP -> served normally
curl -k -A "Mozilla/5.0" https://<host>/
```

Confirm the drop landed:

```
ssh hyproxy-dev
grep bot_filter ~/hyproxy/... /var/log/hyproxy/dataplane.log   # look for the JSON line
```

To exercise ASN/geo, request from a cloud VM whose ASN/country you have blocked.
To exercise PTR without cloud infra, temporarily add a suffix that matches your
own test client's reverse-DNS name.

## Next steps (deployment)

The feature is implemented and unit-tested but **not yet committed or deployed**.
To roll it out:

1. **Provision the GeoLite2 `.mmdb` files** on the host and set up the refresh
   cron (see above). Skip only if you use UA/PTR signals exclusively.
2. **Populate the deployed `dataplane/config.json`** with the desired
   `blocked_user_agents`, `blocked_asns`, `blocked_ptr_suffixes`, and any
   `blocked_countries` + the `geoip_*` paths. Start conservative (UA denylist +
   a small PTR suffix list), observe `bot_filter drop` logs, then widen.
3. **Rebuild and restart** the data plane (`./build.sh --clean` stops the stack;
   then start it). The new `maxminddb-golang` dependency is already vendored in
   `go.mod`/`go.sum`.
4. **Watch the access and service logs** for false positives before tightening.
   Every drop is one `bot_filter drop` line with host, source_ip, reason, and
   user_agent.
5. Mirror any staging config edits back into the repo (`config.example.json`
   and/or the checked-in config) per `CLAUDE.md`.

## Accepted risks / notes

- Adds `github.com/oschwald/maxminddb-golang`, the first external Go dependency
  in the otherwise stdlib-only data plane. Accepted as the cost of ASN/geo
  lookups.
- No good-bot allowlist: legitimate crawlers and monitors are dropped if they
  match a signal (de-indexing tradeoff, chosen deliberately).
- The PTR signal fails open on DNS error/timeout, trading completeness for not
  blocking real users during resolver trouble.
- Source IP is the TCP peer address (`clientIP`), correct because the data plane
  is the edge; there is no upstream proxy inserting `X-Forwarded-For`.
