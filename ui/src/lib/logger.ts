// Browser-side error reporting into the centralized ui.log via the admin
// app's unauthenticated POST /api/v1/ui-logs (rate-limited server-side).
// Buffered and debounced so a render loop cannot flood the endpoint;
// sendBeacon flushes survive page unloads. Never include tokens or
// request/response bodies in messages.

import { config } from "./config";

type Level = "info" | "warn" | "error";

interface Entry {
  level: Level;
  msg: string;
  stack?: string;
  url?: string;
  ts?: string;
}

const MAX_BATCH = 10;
const FLUSH_MS = 10_000;
const MAX_SENDS_PER_SESSION = 50;
const MAX_MSG = 2000;
const MAX_STACK = 8000;
const MAX_URL = 500;

let queue: Entry[] = [];
let timer: ReturnType<typeof setTimeout> | null = null;
let sends = 0;
let lastMsg = "";

const endpoint = () => `${config.apiBase}/ui-logs`;

function flush(): void {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  if (queue.length === 0 || sends >= MAX_SENDS_PER_SESSION) {
    queue = [];
    return;
  }
  sends += 1;
  const body = JSON.stringify({ entries: queue.slice(0, MAX_BATCH) });
  queue = [];
  const blob = new Blob([body], { type: "application/json" });
  if (!navigator.sendBeacon || !navigator.sendBeacon(endpoint(), blob)) {
    void fetch(endpoint(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {
      // Logging must never cascade into more errors.
    });
  }
}

function push(level: Level, msg: string, stack?: string): void {
  if (msg === lastMsg) return; // dedupe consecutive repeats (render loops)
  lastMsg = msg;
  queue.push({
    level,
    msg: msg.slice(0, MAX_MSG),
    stack: stack ? stack.slice(0, MAX_STACK) : undefined,
    url: window.location.href.slice(0, MAX_URL),
    ts: new Date().toISOString(),
  });
  if (queue.length >= MAX_BATCH) {
    flush();
  } else if (!timer) {
    timer = setTimeout(flush, FLUSH_MS);
  }
}

export function logError(msg: string, stack?: string): void {
  push("error", msg, stack);
}

export function logWarn(msg: string, stack?: string): void {
  push("warn", msg, stack);
}

export function installGlobalHandlers(): void {
  window.addEventListener("error", (event) => {
    logError(String(event.message ?? "window.onerror"), event.error?.stack);
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason: unknown = event.reason;
    if (reason instanceof Error) {
      logError(`unhandledrejection: ${reason.message}`, reason.stack);
    } else {
      logError(`unhandledrejection: ${String(reason)}`);
    }
  });
  window.addEventListener("pagehide", flush);
}
