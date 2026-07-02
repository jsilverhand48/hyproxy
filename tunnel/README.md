# Guacamole tunnel (guacamole-lite)

Internal service that bridges the Guacamole WebSocket to `guacd`. It decrypts
the broker-minted token with the shared cypher key and opens the guacd
connection. Never internet-facing: the Go data plane terminates TLS,
forward-auths the connect, and single-use-consumes the grant before proxying
the WebSocket here.

## Architecture

```
browser (guacamole-common-js)
   | WSS  ?token=<broker token>
Go data plane  --forward-auth (gateway session + policy) + consume grant-->
   | WS reverse-proxy (loopback)
this service (guacamole-lite)  --decrypt token with shared key-->
   | guacd protocol (TCP)
guacd (native daemon)
```

The broker (`server/src/hyproxy/guac/`) mints tokens in guacamole-lite's default
AES-256-CBC envelope; this service is configured with the same key and so can
decrypt them. Neither the browser nor this service ever sees the sealed
connection secrets in cleartext beyond the single decrypted token.

## Run

```sh
npm install
GUAC_CYPHER_KEY=$(cd ../server && uv run python -m hyproxy.cli gen-guac-key) \
GUACD_HOST=127.0.0.1 GUACD_PORT=4822 PORT=8600 npm start
```

`GUAC_CYPHER_KEY` MUST equal the control plane's `HYPROXY_GUAC_CYPHER_KEY`
(base64 of the same 32 bytes). `guacd` itself is a native daemon (Apache
Guacamole); install/run it separately and point `GUACD_HOST`/`GUACD_PORT` at it.

## Dev note

This machine has no `guacd` and no containers, so the end-to-end remote-desktop
path cannot be exercised here. `npm run check` validates the service parses; the
token format is verified against the Python broker by
`server/tests/unit/test_guac_token.py`.
