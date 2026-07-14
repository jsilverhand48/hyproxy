"use strict";

// Minimal centralized logger for the tunnel service, matching the stack-wide
// scheme: one JSON line with ts (ISO-8601 UTC), level, service, msg, extras.
// Always writes stdout/stderr (docker logs); when LOG_DIR is set it also
// appends to LOG_DIR/tunnel.log with the shared rotation policy: rotate at
// LOG_MAX_BYTES (default 50 MB), keep 2 archives (tunnel.log.1, .2), delete
// older. Sync fs calls are fine at tunnel event volume.

const fs = require("fs");
const path = require("path");

const LOG_DIR = process.env.LOG_DIR || "";
const MAX_BYTES = Number(process.env.LOG_MAX_BYTES || 52428800);
const BACKUPS = 2;

const file = LOG_DIR ? path.join(LOG_DIR, "tunnel.log") : null;

function rotateIfNeeded(line) {
  let size = 0;
  try {
    size = fs.statSync(file).size;
  } catch {
    return; // no live file yet; nothing to rotate
  }
  if (size + Buffer.byteLength(line) <= MAX_BYTES) return;
  try {
    fs.rmSync(`${file}.${BACKUPS}`, { force: true });
    for (let i = BACKUPS - 1; i >= 1; i--) {
      try {
        fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`);
      } catch {
        // archive slot empty; keep shifting
      }
    }
    fs.renameSync(file, `${file}.1`);
  } catch (err) {
    process.stderr.write(`tunnel logger: rotate failed: ${err}\n`);
  }
}

function log(level, msg, extra) {
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      level,
      service: "tunnel",
      logger: "tunnel",
      msg,
      ...extra,
    }) + "\n";
  (level === "error" ? process.stderr : process.stdout).write(line);
  if (!file) return;
  try {
    rotateIfNeeded(line);
    fs.appendFileSync(file, line);
  } catch (err) {
    process.stderr.write(`tunnel logger: write failed: ${err}\n`);
  }
}

module.exports = {
  info: (msg, extra) => log("info", msg, extra),
  warn: (msg, extra) => log("warn", msg, extra),
  error: (msg, extra) => log("error", msg, extra),
};
