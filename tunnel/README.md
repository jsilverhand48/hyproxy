# Guacamole tunnel (guacamole-lite)

Internal Node service that terminates the Guacamole WebSocket, decrypts the
broker-minted token with the shared cypher key, and bridges the session to
`guacd` (the native Apache Guacamole daemon) over TCP. It is never
internet-facing: the Go data plane terminates TLS, forward-auths the connect,
and single-use-consumes the grant before reverse-proxying the WebSocket here.

## Architecture

```
browser (guacamole-common-js)
   | WSS  ?token=<broker token>
Go data plane  --forward-auth (gateway session + policy) + consume grant-->
   | WS reverse-proxy (loopback)
this service (guacamole-lite)  --decrypt token with shared key-->
   | guacd protocol (TCP)
guacd (native daemon)  -->  VNC / RDP / SSH target
```

The broker (`server/src/hyproxy/guac/`) mints tokens in guacamole-lite's
default AES-256-CBC envelope; this service holds the same key and can decrypt
them. The token carries the connection settings, including secrets decrypted
by the broker at mint time; neither the browser nor any log ever sees them in
cleartext.

Two hardening choices in `server.js`:

- `allowedUnencryptedConnectionSettings` restricts what the client may pass
  in the clear to display shaping only (`width`, `height`, `dpi`, `audio`,
  `image`, `timezone`). Target host and credentials come exclusively from
  the encrypted token.
- The HTTP listener answers only `GET /healthz`
  (`{"status":"ok","service":"guac-tunnel"}`); every other plain HTTP request
  gets `426 Upgrade Required`. The port serves the WebSocket tunnel and
  nothing else.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `GUAC_CYPHER_KEY` | **required** | Base64 of exactly 32 bytes; the process exits if missing or the wrong length. MUST be byte-identical to the control plane's `HYPROXY_GUAC_CYPHER_KEY` |
| `BIND_HOST` | `127.0.0.1` | Listen address (loopback; only the data plane should reach it) |
| `PORT` | `8600` | Listen port |
| `GUACD_HOST` / `GUACD_PORT` | `127.0.0.1` / `4822` | Where guacd runs (compose sets `guacd:4822`) |
| `LOG_LEVEL` | `NORMAL` | guacamole-lite verbosity |
| `LOG_DIR` | empty | When set, also append JSON lines to `LOG_DIR/tunnel.log` |
| `LOG_MAX_BYTES` | `52428800` | Rotation threshold; 2 archives kept (`.1`, `.2`) |

## Logging

`logger.js` emits the stack-wide JSON line scheme (`ts` ISO-8601 UTC,
`level`, `service: "tunnel"`, `logger`, `msg`, extras) to stdout (errors to
stderr), plus the rotating file when `LOG_DIR` is set. Writes are synchronous,
which is fine at tunnel volume. See the
[root README](../README.md#logging-and-log-shipping) for the whole-stack
logging picture.

## Run

```sh
npm install
GUAC_CYPHER_KEY=$(cd ../server && uv run python -m hyproxy.cli gen-guac-key) \
GUACD_HOST=127.0.0.1 GUACD_PORT=4822 PORT=8600 npm start
```

Or from the repo root: `make tunnel-install`, `make tunnel-run`. In
production this runs as the compose `tunnel` service (profile `guac`,
enabled only when `HYPROXY_GUAC_CYPHER_KEY` is set) next to the
`guacamole/guacd` container.

npm scripts: `start` (`node server.js`), `check` (`node --check server.js`,
syntax only). Single runtime dependency: `guacamole-lite`.

## Dockerfile

`node:22-alpine`, `NODE_ENV=production`, `npm ci --omit=dev`, copies only
`server.js` and `logger.js`, runs as the `node` user, exposes 8600,
`CMD node server.js`.

## Dev note

The dev machine has no `guacd` and no containers, so the end-to-end
remote-desktop path cannot be exercised locally. `npm run check` validates
the service parses; the token format is verified against the Python broker by
the server test suite.
