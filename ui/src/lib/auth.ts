// OIDC public-client auth for the admin SPA: authorization code + PKCE (S256)
// with DPoP-bound tokens. The access token lives in memory only; on reload the
// app silently re-runs authorize (the IdP session cookie makes it seamless
// while the session is alive). Step-up is a top-level redirect to the IdP.

import { config } from "./config";
import { loadDpopKey } from "./dpop";
import { challengeFromVerifier, randomToken } from "./pkce";

interface Tokens {
  access: string;
  refresh?: string;
  idClaims?: Record<string, unknown>;
  expiresAt: number;
}

interface FlowState {
  verifier: string;
  state: string;
  nonce: string;
  // In-app path to restore after the OIDC round-trip (e.g. /connect/<id>).
  returnTo?: string;
}

const FLOW_KEY = "hyproxy-oidc-flow";
let tokens: Tokens | null = null;

function parseJwtClaims(jwt: string): Record<string, unknown> {
  try {
    const payload = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function store(data: Record<string, unknown>): void {
  const expiresIn = typeof data.expires_in === "number" ? data.expires_in : 600;
  tokens = {
    access: String(data.access_token),
    refresh: typeof data.refresh_token === "string" ? data.refresh_token : undefined,
    idClaims: typeof data.id_token === "string" ? parseJwtClaims(data.id_token) : tokens?.idClaims,
    // Refresh 30s before actual expiry to avoid racing the clock.
    expiresAt: Date.now() + expiresIn * 1000 - 30_000,
  };
}

export function isAuthenticated(): boolean {
  return tokens !== null && tokens.expiresAt > Date.now();
}

export function currentUserEmail(): string | null {
  const email = tokens?.idClaims?.email;
  return typeof email === "string" ? email : null;
}


// Tier is carried in the ID token's acr claim as "tier:<auth_tier>". The admin
// panel must never render for a non-admin, so the app gates on this.
export function isAdmin(): boolean {
  return tokens?.idClaims?.acr === "tier:admin";
}

// Authenticated but not an admin: bounce to the IdP's signed-in page (which
// offers a logout button) instead of ever exposing the panel.
export function showSignedIn(): void {
  window.location.assign(`${config.issuer}/auth/done`);
}

export async function beginLogin(): Promise<void> {
  const flow: FlowState = {
    verifier: randomToken(48),
    state: randomToken(16),
    nonce: randomToken(16),
    returnTo: window.location.pathname + window.location.search,
  };
  sessionStorage.setItem(FLOW_KEY, JSON.stringify(flow));
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: config.scope,
    state: flow.state,
    nonce: flow.nonce,
    code_challenge: await challengeFromVerifier(flow.verifier),
    code_challenge_method: "S256",
  });
  window.location.assign(`${config.issuer}/oidc/authorize?${params.toString()}`);
}

// Resolves to the in-app path the user was on when the login began, so the
// caller can restore it (deep links like /connect/<id> survive the redirect).
export async function completeLogin(search: string): Promise<string | null> {
  const q = new URLSearchParams(search);
  const code = q.get("code");
  const returnedState = q.get("state");
  const raw = sessionStorage.getItem(FLOW_KEY);
  sessionStorage.removeItem(FLOW_KEY);
  if (!code || !raw) throw new Error("missing authorization code");
  const flow = JSON.parse(raw) as FlowState;
  if (returnedState !== flow.state) throw new Error("state mismatch");

  const dpop = await loadDpopKey();
  const proof = await dpop.makeProof("POST", `${config.issuer}/oidc/token`);
  const resp = await fetch(`${config.issuer}/oidc/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: proof },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code,
      redirect_uri: config.redirectUri,
      code_verifier: flow.verifier,
    }),
  });
  if (!resp.ok) throw new Error(`token exchange failed (${resp.status})`);
  store((await resp.json()) as Record<string, unknown>);
  return flow.returnTo && !flow.returnTo.startsWith("/callback") ? flow.returnTo : null;
}

async function refresh(): Promise<boolean> {
  if (!tokens?.refresh) return false;
  const dpop = await loadDpopKey();
  const proof = await dpop.makeProof("POST", `${config.issuer}/oidc/token`);
  const resp = await fetch(`${config.issuer}/oidc/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: proof },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: config.clientId,
      refresh_token: tokens.refresh,
    }),
  });
  if (!resp.ok) {
    tokens = null;
    return false;
  }
  store((await resp.json()) as Record<string, unknown>);
  return true;
}

// Returns a currently-valid access token, refreshing if needed. If neither the
// token nor a refresh works, it kicks off a full re-login (and never returns).
export async function getAccessToken(): Promise<string> {
  if (tokens && tokens.expiresAt > Date.now()) return tokens.access;
  if (await refresh()) return tokens!.access;
  await beginLogin();
  throw new Error("redirecting to sign in");
}

// Force a refresh regardless of expiry (used after a 401 that may mean the
// access token was rejected but the session is still live).
export async function forceRefresh(): Promise<boolean> {
  return refresh();
}

// Top-level navigation to the IdP step-up page; it returns to this exact URL.
export function beginStepUp(): void {
  const params = new URLSearchParams({ return_to: window.location.href });
  window.location.assign(`${config.issuer}/auth/stepup?${params.toString()}`);
}

export function signOut(): void {
  tokens = null;
  // Full-page navigation to the IdP so it revokes the browser session and
  // clears its cookie; otherwise /oidc/authorize would silently re-log-in.
  const params = new URLSearchParams({
    client_id: config.clientId,
    post_logout_redirect_uri: `${window.location.origin}/`,
  });
  window.location.assign(`${config.issuer}/oidc/logout?${params.toString()}`);
}
