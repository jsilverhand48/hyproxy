# Data plane (Go)

Single internet-facing ingress for hyproxy. Terminates TLS on one public port,
routes by normalized Host header to allowlisted backends only, forward-auths
every application request against the control plane's `/authz/check`, and
injects identity headers after stripping any client-supplied copies.

## Layout

- `cmd/dataplane` entrypoint.
- `internal/config` config load + validation (SSRF invariant: backends come
  only from here).
- `internal/routing` Host normalization + route table. The normalizer is the
  sole attacker-controlled parser and is fuzzed (`FuzzNormalizeHost`).
- `internal/listener` the pluggable transport seam (spec section 12).
- `internal/httpsl` the v1 HTTPS listener.
- `internal/tlsconf` certificate hot-reload (the ACME slot for Phase 5).
- `internal/authz` forward-auth client (fails closed).
- `internal/proxy` the request handler: routing, forward-auth, header hygiene,
  reverse proxy.

## Build and test

```sh
go build ./cmd/dataplane
go test ./...
go test ./internal/routing -fuzz=FuzzNormalizeHost -fuzztime=30s
./dataplane -config config.example.json
```

Or from the repo root: `make dp-build`, `make dp-test`, `make dp-fuzz`,
`make dp-run`.

## Config

See `config.example.json`. `routes` maps each public host to one allowlisted
backend origin (absolute http(s) URL, no path). `auth_host` is served by the
control plane's authz service and is the only host whose `/gateway/*` paths are
proxied there; nothing else on the auth host is reachable. The proxy never
dials anything not in this file.
