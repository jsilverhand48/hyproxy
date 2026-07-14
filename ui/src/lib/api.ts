// Admin API client: attaches a DPoP-bound access token plus a fresh proof per
// call (same-origin with the admin app). It transparently retries once on 401
// (refresh the token) and surfaces the step-up requirement as a typed error the
// UI turns into the IdP step-up redirect.

import { forceRefresh, getAccessToken } from "./auth";
import { config } from "./config";
import { loadDpopKey } from "./dpop";
import { logError } from "./logger";

export class StepUpRequired extends Error {
  constructor() {
    super("stepup_required");
    this.name = "StepUpRequired";
  }
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
  }
}

async function send(method: string, path: string, body: unknown, token: string): Promise<Response> {
  const url = `${window.location.origin}${config.apiBase}${path}`;
  const dpop = await loadDpopKey();
  const proof = await dpop.makeProof(method, url, token);
  const headers: Record<string, string> = { Authorization: `DPoP ${token}`, DPoP: proof };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return fetch(`${config.apiBase}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function detailOf(resp: Response): Promise<string> {
  try {
    const data = (await resp.json()) as { detail?: unknown };
    return typeof data.detail === "string" ? data.detail : resp.statusText;
  } catch {
    return resp.statusText;
  }
}

export async function apiFetch<T>(method: string, path: string, body?: unknown): Promise<T> {
  let token = await getAccessToken();
  let resp: Response;
  try {
    resp = await send(method, path, body, token);

    if (resp.status === 401 && (await forceRefresh())) {
      token = await getAccessToken();
      resp = await send(method, path, body, token);
    }
  } catch (err) {
    // Network-level failure; 4xx (auth, step-up, validation) are expected
    // flows and not reported. Never log request bodies.
    logError(`network error: ${method} ${path}`, err instanceof Error ? err.stack : undefined);
    throw err;
  }

  if (resp.status === 403) {
    const detail = await detailOf(resp);
    if (detail === "stepup_required") throw new StepUpRequired();
    throw new ApiError(403, detail);
  }
  if (!resp.ok) {
    const detail = await detailOf(resp);
    if (resp.status >= 500) logError(`api error: ${method} ${path} -> ${resp.status} ${detail}`);
    throw new ApiError(resp.status, detail);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export const api = {
  get: <T>(path: string) => apiFetch<T>("GET", path),
  post: <T>(path: string, body?: unknown) => apiFetch<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => apiFetch<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => apiFetch<T>("PATCH", path, body),
  del: (path: string) => apiFetch<void>("DELETE", path),
};
