// Runtime configuration. Defaults target the dev topology; override at build
// time with VITE_* env vars. The API is same-origin (served by the admin app),
// so only the IdP issuer is cross-origin.
const env = import.meta.env as Record<string, string | undefined>;

// Host (host[:port]) the standard-user portal is served on. When the SPA is
// loaded from this host, admins see only the portal sections too: the
// management API rejects off-LAN calls anyway.
const portalHost = env.VITE_PORTAL_HOST ?? "";

export const config = {
  issuer: (env.VITE_IDP_ISSUER ?? "https://idp.localhost:8300").replace(/\/$/, ""),
  clientId: env.VITE_ADMIN_UI_CLIENT_ID ?? "admin-ui",
  redirectUri: `${window.location.origin}/callback`,
  apiBase: "/api/v1",
  scope: "openid profile email",
  portalHost,
  isPortal: portalHost !== "" && window.location.host === portalHost,
  // Auth-host origin: guac tunnel tokens are minted at <origin>/guac/token
  // (cookie-authed, cross-origin from the SPA).
  authOrigin: (env.VITE_AUTH_ORIGIN ?? "").replace(/\/$/, ""),
};
