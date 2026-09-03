// RTSP stream-token client. Like /guac/token, this lives on the auth host and
// authenticates with the gateway session cookie, so it is a plain cross-origin
// fetch with credentials rather than the admin API's same-origin DPoP path.
//
// The camera username and password travel in this request body. They are the
// SECOND authentication factor (to the camera, not to hyproxy), are held only
// in the calling component's state, and are never persisted anywhere.

import { config } from "./config";

export interface RtspToken {
  token: string;
  expires_at: string;
}

export class RtspError extends Error {
  constructor(
    readonly reason: string,
    message: string,
  ) {
    super(message);
    this.name = "RtspError";
  }
}

const MESSAGES: Record<string, string> = {
  rtsp_disabled: "Camera streaming is disabled on this server.",
  no_connection: "This resource has no camera connection configured.",
  unknown_resource: "Unknown resource.",
  rtsp_auth_failed: "The camera rejected that username or password.",
  rtsp_unreachable: "The camera did not answer.",
  rtsp_stream_not_found: "The camera has no stream at that path.",
  rtsp_no_video: "That stream carries no video track.",
  rtsp_failed: "The camera stream could not be opened.",
  too_many_streams: "You already have the maximum number of streams open.",
  invalid_token: "The stream authorization expired. Try again.",
  missing_token: "The stream authorization was missing. Try again.",
};

export function rtspMessage(reason: string): string {
  return MESSAGES[reason] ?? `Stream failed: ${reason}`;
}

// Mints a single-use stream token (60s TTL: mint immediately before each
// connect, never reuse). A missing gateway session bounces the browser through
// the gateway login and back to the current URL.
export async function mintRtspToken(
  resourceId: string,
  username: string,
  password: string,
): Promise<RtspToken> {
  if (!config.authOrigin) {
    throw new RtspError("not_configured", "Auth origin not configured (VITE_AUTH_ORIGIN).");
  }
  const resp = await fetch(`${config.authOrigin}/rtsp/token`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ resource_id: resourceId, username, password }),
  });
  if (resp.ok) return (await resp.json()) as RtspToken;

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
    throw new RtspError("auth_required", "Signing in...");
  }
  throw new RtspError(reason, rtspMessage(reason));
}
