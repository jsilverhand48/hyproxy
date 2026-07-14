"use strict";

// Internal guacamole-lite tunnel service.
//
// It terminates the Guacamole WebSocket, decrypts the broker-minted token with
// the SHARED cypher key (same value as HYPROXY_GUAC_CYPHER_KEY on the control
// plane), and connects to guacd. It is NEVER internet-facing: the Go data plane
// terminates TLS, forward-auths the connect (gateway session + policy), and
// single-use-consumes the grant BEFORE proxying the WebSocket here. This
// service therefore binds loopback and trusts its network path, exactly like
// the authz service.

const http = require("http");
const GuacamoleLite = require("guacamole-lite");
const logger = require("./logger");

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    logger.error(`missing required env ${name}`);
    process.exit(1);
  }
  return value;
}

const port = Number(process.env.PORT || 8600);
const host = process.env.BIND_HOST || "127.0.0.1";

// The key is base64 of 32 bytes; guacamole-lite's AES-256-CBC crypt uses these
// raw bytes. It MUST equal the control plane's HYPROXY_GUAC_CYPHER_KEY.
const key = Buffer.from(requiredEnv("GUAC_CYPHER_KEY"), "base64");
if (key.length !== 32) {
  logger.error("GUAC_CYPHER_KEY must decode to 32 bytes");
  process.exit(1);
}

const guacdOptions = {
  host: process.env.GUACD_HOST || "127.0.0.1",
  port: Number(process.env.GUACD_PORT || 4822),
};

const clientOptions = {
  crypt: { cypher: "AES-256-CBC", key },
  log: { level: process.env.LOG_LEVEL || "NORMAL" },
  // Tokens carry the full connection; do not accept client-supplied overrides.
  allowedUnencryptedConnectionSettings: {
    rdp: [],
    vnc: [],
    ssh: [],
  },
};

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"status":"ok","service":"guac-tunnel"}');
    return;
  }
  res.writeHead(426); // Upgrade Required: this port only serves the WS tunnel.
  res.end();
});

new GuacamoleLite({ server }, guacdOptions, clientOptions);

server.listen(port, host, () => {
  logger.info("guac tunnel listening", {
    host,
    port,
    guacd_host: guacdOptions.host,
    guacd_port: guacdOptions.port,
  });
});
