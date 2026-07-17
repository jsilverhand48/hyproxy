// Guacamole tunnel-token client. Unlike the admin API (same-origin, DPoP),
// /guac/token lives on the auth host and authenticates with the gateway
// session cookie, so this is a plain cross-origin fetch with credentials.

import { config } from "./config";

export interface GuacToken {
  token: string;
  protocol: string;
  expires_at: string;
}

export class GuacError extends Error {
  constructor(
    readonly reason: string,
    message: string,
  ) {
    super(message);
    this.name = "GuacError";
  }
}

const MESSAGES: Record<string, string> = {
  guac_disabled: "Remote sessions are disabled on this server.",
  no_connection: "This resource has no connection configured.",
  unknown_resource: "Unknown resource.",
};

// Mints a single-use tunnel token (60s TTL: mint immediately before each
// connect, never reuse). A missing gateway session bounces the browser
// through the gateway login and back to the current URL.
export async function mintGuacToken(resourceId: string): Promise<GuacToken> {
  if (!config.authOrigin) {
    throw new GuacError("not_configured", "Auth origin not configured (VITE_AUTH_ORIGIN).");
  }
  const resp = await fetch(`${config.authOrigin}/guac/token`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ resource_id: resourceId }),
  });
  if (resp.ok) return (await resp.json()) as GuacToken;

  let reason = resp.statusText;
  try {
    const data = (await resp.json()) as { error?: unknown };
    if (typeof data.error === "string") reason = data.error;
  } catch {
    // non-JSON error body; keep the status text
  }
  if (resp.status === 401) {
    const rd = encodeURIComponent(window.location.href);
    window.location.assign(`${config.authOrigin}/gateway/start?rd=${rd}`);
    throw new GuacError("auth_required", "Signing in...");
  }
  throw new GuacError(reason, MESSAGES[reason] ?? `Not allowed: ${reason}`);
}
