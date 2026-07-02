# Admin UI (React)

Management-plane admin UI for hyproxy: users, roles, resources, policies, and
read-only audit / policy-change viewers. Served only on the management plane
(LAN/WireGuard), never internet-facing.

## Auth model

The UI is a first-class OIDC public client (`admin-ui`) of the self-built IdP.
It runs authorization code + PKCE (S256) with DPoP-bound tokens: a
non-extractable P-256 key is generated in WebCrypto and kept in IndexedDB
(`src/lib/dpop.ts`), the code is exchanged at the IdP token endpoint with a DPoP
proof, and every admin API call carries `Authorization: DPoP <token>` plus a
fresh proof (`src/lib/api.ts`). The build is served by the admin FastAPI app, so
`/api/v1/*` is same-origin (no CORS); only the token exchange is cross-origin to
the IdP, which allows exactly this one origin.

Mutations require a fresh WebAuthn step-up. On a `403 stepup_required` the app
does a top-level redirect to the IdP step-up page (so the SameSite=Lax IdP
session cookie is sent), then returns here and retries.

## Develop

```sh
npm install
npm run dev      # http://127.0.0.1:5173, proxies /api to the admin app (:8400)
npm run lint     # eslint + tsc --noEmit
npm run build    # -> dist/ (served by the admin app)
```

Configure the IdP origin and client id at build time via `VITE_IDP_ISSUER` and
`VITE_ADMIN_UI_CLIENT_ID` (defaults target the dev topology). The admin app
must run with `HYPROXY_ADMIN_UI_ORIGIN` set to this UI's origin so the IdP CORS
allowance and the step-up return target are enabled.

From the repo root: `make ui-install`, `make ui-build`, `make ui-dev`.
