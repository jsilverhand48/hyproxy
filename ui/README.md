# Web UI (React)

One SPA, two faces. This app is both the **admin console** (users, roles,
resources, policies, audit viewers) and the **standard-user portal** (my
resources, downloads, account, in-browser remote desktop). Which sections a
visitor sees is decided at runtime by identity tier (`acr` claim in the ID
token) and by the host serving the app: on the portal host
(`VITE_PORTAL_HOST`) even admins get portal-only sections. The server
enforces tier and LAN restrictions regardless of what the client renders;
the gating here is purely presentation.

The build is served by the admin FastAPI app (same origin as `/api/v1`), not
by the data plane and not from a CDN. The admin surface is LAN-only; the
portal surface is internet-facing through the data plane.

## Auth model

First-class OIDC public client (`admin-ui`) of the self-built IdP:
authorization code + PKCE (S256) with DPoP-bound tokens.

- `src/lib/dpop.ts` generates a non-extractable P-256 keypair in WebCrypto
  and keeps it in IndexedDB; every token and API call carries a fresh DPoP
  proof. This mirrors the IdP's own `dpop.js`; the two implementations must
  stay in sync.
- `src/lib/auth.ts` runs the code flow, keeps the access token in memory
  only, silently re-authorizes on reload via the IdP session cookie, and
  refreshes 30 seconds before expiry. `isAdmin()` reads `acr === "tier:admin"`
  from the ID token.
- `src/lib/api.ts` attaches `Authorization: DPoP <token>` plus a proof to
  every `/api/v1` call, retries once on 401 with a forced refresh, and
  surfaces `403 stepup_required` as a typed error.
- Mutations require fresh WebAuthn step-up: on `stepup_required` the app does
  a top-level redirect to the IdP step-up page (so the SameSite=Lax IdP
  cookie rides along), then returns and retries.

## Structure

No react-router and no data-fetching library, deliberately: routing is a few
lines in `App.tsx` and `src/lib/useApi.ts` provides small hooks
(`useResource`, `usePaged` keyset pagination, `runMutation` with step-up
handling). This keeps the bundle small and the CSP strict.

- `src/App.tsx`: manual routing on `window.location.pathname`:
  - `/callback` finishes the OIDC login;
  - `/connect/<uuid>` is the full-screen Guacamole session view;
  - everything else renders the sidebar layout with in-memory section state.
  Admin sections vs portal sections are selected here (see top).
- `src/views/`: `Users`, `Roles`, `Resources`, `Policies`, `AccessAudit`,
  `AuthEvents`, `PolicyChanges` (admin); `MyResources`, `Downloads`,
  `Account`, `Connect` (portal).
- `src/components/`: `ResourceDialog`, `ConfirmDialog`, `ErrorBoundary`,
  shared primitives in `ui.tsx`.
- `src/lib/`: `config.ts` (all `VITE_*` runtime config), `auth.ts`,
  `dpop.ts`, `pkce.ts`, `api.ts`, `guac.ts`, `useApi.ts`, `logger.ts`,
  `types.ts`.

### Remote desktop (`Connect.tsx` + `lib/guac.ts`)

The view fetches a single-use ~60s token from `<VITE_AUTH_ORIGIN>/guac/token`
with `credentials: "include"` (the gateway session cookie; this is the one
cookie-authenticated cross-origin call, and the authz service allows exactly
this origin). It then opens
`wss://<VITE_PORTAL_HOST>/guac/tunnel?token=...` with `guacamole-common-js`;
the data plane consumes the grant and proxies the WebSocket to the tunnel
service. A fresh token is minted on every (re)connect. A 401 on minting
bounces the browser through `/gateway/start?rd=` to log in.

### Error reporting (`lib/logger.ts`)

Global error handlers batch uncaught errors to the unauthenticated
`POST /api/v1/ui-logs` endpoint via `sendBeacon`, with hard caps (sends per
session, batch size, dedupe). Never logs tokens or request bodies. The server
writes these to `ui.log`.

## Configuration (build time)

All configuration is baked into the bundle by Vite at build time; changing it
means rebuilding (in production, rebuilding the server image, which builds
the SPA in its first stage).

| Variable | Default | Meaning |
|---|---|---|
| `VITE_IDP_ISSUER` | dev IdP origin | IdP origin for authorize/token/logout/step-up |
| `VITE_ADMIN_UI_CLIENT_ID` | `admin-ui` | Registered OIDC client id |
| `VITE_PORTAL_HOST` | empty | Hostname on which the app renders portal-only sections |
| `VITE_AUTH_ORIGIN` | empty | Origin that mints Guacamole tokens (`/guac/token`) |

The admin app must run with `HYPROXY_ADMIN_UI_ORIGIN` set to this app's
origin: that is the sole IdP CORS allowance and the only permitted step-up
return target.

## Develop and build

```sh
npm install
npm run dev      # http://127.0.0.1:5173, proxies /api to the admin app (:8400)
npm run lint     # eslint + tsc --noEmit
npm run build    # tsc -b && vite build -> dist/ (served by the admin app)
```

From the repo root: `make ui-install`, `make ui-build`, `make ui-dev`.

The dev server proxies `/api` to `http://127.0.0.1:8400` with
`changeOrigin: false`, so the SPA stays same-origin with the admin API and no
CORS is needed anywhere except the IdP token exchange.

## Intricacies

- **Drift hazards:** `src/lib/types.ts` mirrors the server's Pydantic schemas
  and `src/lib/dpop.ts` mirrors the IdP's DPoP script. Neither is generated;
  a server-side change breaks them silently.
- **CSP:** the app is designed for a strict same-origin CSP. Hashed asset
  filenames keep `script-src 'self'` viable; there are no CDN scripts,
  fonts, or external images. Theme art is imported from `src/assets/theme/`
  through Vite (fingerprinted into `/assets/`) rather than `public/`, so it
  is served from the same origin the CSP allows. See
  [docs/THEME-ASSETS.md](../docs/THEME-ASSETS.md) for the drop-in asset
  slots; rebuild after swapping.
- Admin sections apply a distinct theme class; portal sections keep the plain
  dark theme. Motion is disabled under `prefers-reduced-motion`.
