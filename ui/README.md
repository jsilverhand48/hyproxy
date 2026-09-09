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
  - `/watch/<uuid>` is the full-screen RTSP camera view;
  - everything else renders the sidebar layout with in-memory section state.
  Admin sections vs portal sections are selected here (see top).
- `src/views/`: `Users`, `Roles`, `Resources`, `Policies`, `AccessAudit`,
  `AuthEvents`, `PolicyChanges` (admin); `MyResources`, `Downloads`,
  `Account`, `Connect`, `Watch` (portal).
- `src/components/`: `ResourceDialog`, `ConfirmDialog`, `ErrorBoundary`,
  shared primitives in `ui.tsx`.

  `ResourceDialog` also drives **public (password-gated) access** for http/https
  resources: a checkbox plus a one-glob-per-line path list. The admin never
  types that password -- it is generated server-side and returned exactly once,
  on create or via "Regenerate password", so the dialog renders it immediately
  and stays open rather than losing it. Regenerating signs out everyone using
  the link, so it is behind a `ConfirmDialog`. `Resources.tsx` shows the mode in
  an "Access" column and flags a public resource that has no password yet.
- `src/lib/`: `config.ts` (all `VITE_*` runtime config), `auth.ts`,
  `dpop.ts`, `pkce.ts`, `api.ts`, `guac.ts`, `rtsp.ts`, `useApi.ts`,
  `logger.ts`, `types.ts`.
- `src/managed-media-source.d.ts`: ambient declaration for
  `ManagedMediaSource`, which TypeScript 5.7's DOM lib does not have and
  `Watch.tsx` needs on iPhone. Delete it once the lib ships the type.

Shared primitives live in `src/components/ui.tsx`: `Section`, `Banner`,
`AsyncBody`, plus `TableWrap` (per-table horizontal scroll, and the hook the
mobile card layout hangs off) and `LoadMore` (the keyset pagination control the
three audit viewers share).

### Remote desktop (`Connect.tsx` + `lib/guac.ts`)

The view fetches a single-use ~60s token from `<VITE_AUTH_ORIGIN>/guac/token`
with `credentials: "include"` (the gateway session cookie; this is the one
cookie-authenticated cross-origin call, and the authz service allows exactly
this origin). It then opens
`wss://<VITE_PORTAL_HOST>/guac/tunnel?token=...` with `guacamole-common-js`;
the data plane consumes the grant and proxies the WebSocket to the tunnel
service. A fresh token is minted on every (re)connect. A 401 on minting
bounces the browser through `/gateway/start?rd=` to log in.

**Touch input.** `Guacamole.Mouse` listens for mouse events, which a touch
browser synthesizes late, without hover, and not at all for drags - so on a
phone the session is effectively unclickable. When
`matchMedia("(pointer: coarse)")` matches, the view binds
`Guacamole.Mouse.Touchscreen` instead (tap = click at that point, long-press =
right-click) and calls `display.showCursor(true)`, since there is no real
pointer to draw. The desktop branch is unchanged. `touch-action: none` on
`.connect-display` stops the browser claiming drags that belong to the session.

Keyboard input on touch borrows the OS keyboard: a **Keyboard** button focuses
an offscreen `<textarea>`, and because `Guacamole.Keyboard` is bound to
`document`, keys typed into it bubble up and forward like any other keystroke.
Known limitation: Android IMEs report `keyCode 229` / `key: "Unidentified"` for
composed text, so typing is reliable for ASCII on iOS and only partially on
Android. Deliberately **not** implemented yet (follow-up work):
`Guacamole.OnScreenKeyboard` (needs a full layout object, its own CSS and
injected markup), pinch-zoom/pan of the remote display, and a Ctrl/Alt/Tab/Esc
modifier bar for terminal use.

### Camera streaming (`Watch.tsx` + `lib/rtsp.ts`)

Same token-then-WebSocket shape as remote desktop, with a second credential
prompt in front of it: the camera has its own username and password, which the
view collects and posts to `<VITE_AUTH_ORIGIN>/rtsp/token`. They stay in
component state (so a dropped stream can reconnect without re-prompting) and are
never written to `localStorage` or anywhere else.

It then opens `wss://<VITE_PORTAL_HOST>/rtsp/stream?token=...`. Text frames are
JSON control messages; the `ready` frame carries the codec string used to build
the `SourceBuffer`, and binary frames are fragmented MP4 appended to it. There
is no player library: the Media Source API and `<video>` are browser built-ins.
Appends go through a queue drained on `updateend` (`appendBuffer` throws while an
append is in flight), and the buffer is trimmed past ~60s so a long session does
not grow without bound.

**There are two Media Source implementations to satisfy**, which is why this
view is more than `new MediaSource()`:

| | Desktop + Android Chrome | iPhone Safari (iOS 17.1+) |
|---|---|---|
| Constructor | `MediaSource` | `ManagedMediaSource` only - `window.MediaSource` is **undefined** |
| Attachment | `blob:` object URL on `video.src` | `video.srcObject` |
| Extra requirement | none | `video.disableRemotePlayback = true` before attaching, or WebKit refuses it |
| Buffer control | ours alone | UA also emits `startstreaming` / `endstreaming` |

`MediaSource` is preferred wherever it exists (including desktop Safari, which
has both) so every browser that already worked keeps its exact previous code
path; the managed branch is purely additive for iPhone. `isTypeSupported` is
called on whichever constructor won, because `ManagedMediaSource`'s reflects the
hardware decoder and is legitimately stricter.

The `endstreaming` hint is honoured by dropping backlog rather than appending -
for a live camera freshness beats completeness, and every fragment starts with a
keyframe so dropping whole fragments resyncs cleanly. It is deliberately **not**
applied before the first successful append: a UA that reports `streaming` false
up front would otherwise deadlock the stream by never receiving the init segment.

Autoplay can still be refused (iOS Low Power Mode blocks it even for muted
video), so a rejected `play()` surfaces a **Play** button instead of a black
rectangle labelled "Live". The `<video>` keeps `muted playsInline` for the same
family of reasons. A `video` `error` listener reports decode failures, which
would otherwise be invisible: `appendBuffer` errors are swallowed on purpose (a
wedged buffer resyncs on the next keyframe), so without it a rejected bitstream
reads as "Live" forever.

This is why the admin app's CSP carries `media-src 'self' blob:` - the
non-Safari attachment is a `blob:` object URL, and `default-src 'none'` would
otherwise block every `<video>` source. The `srcObject` path needs no CSP entry
but the `blob:` one must stay.

## Responsive layout

All of it lives in `src/styles.css`, which carries the conventions in a comment
block at the top. Summary:

- **One width breakpoint: `max-width: 60em` (960px)**, called *compact*. 932px is
  the widest phone viewport (iPhone Pro Max landscape) and 1024px the narrowest
  tablet landscape, so every phone gets the mobile layout in both orientations
  and no tablet or desktop layout changes. Do not add a second width breakpoint
  without a reason that cannot be solved inside this one.
- **Touch sizing is device-gated, not width-gated:**
  `@media (hover: none) and (pointer: coarse)` carries 16px inputs (below that
  iOS zooms the page on focus) and ~44px tap targets. Both are properties of the
  input device, not the viewport - an iPad at 1024px needs them while a narrow
  desktop window must keep its dense layout. Keep that block to sizing and
  typography only; a layout rule in there would give a large touchscreen a phone
  layout.
- **z-index scale**, layered around the theme cobwebs, which are `position:
  fixed; z-index: 50` and stay that way: `50` cobwebs, `60` `.topbar`, `70`
  `.nav-backdrop`, `80` `.sidebar` as drawer, `100` `.modal-overlay`.
- **Navigation** below the breakpoint is an off-canvas drawer: the 220px sidebar
  grid track collapses, `.sidebar` becomes `position: fixed` and slides in from a
  hamburger in `.topbar`. Escape and a backdrop tap close it, picking a section
  closes it, focus moves into the drawer and back to the toggle, and the body
  scroll-locks while it is open. There is **no focus trap**, deliberately
  matching the existing `Modal` in `ConfirmDialog.tsx` rather than introducing
  two standards. `.topbar` is `display: none` on desktop, which is load-bearing:
  a `display: none` grid child contributes no track, so the desktop grid (and
  `.layout.theme-crypt`'s marquee row) is completely unaffected.
- **Tables become stacked cards.** Wrap a table in `<TableWrap>` and give every
  `<td>` a `data-label` matching its `<th>`:

  ```tsx
  <TableWrap>
    <table>
      <thead><tr><th>Name</th><th>Ports</th><th></th></tr></thead>
      <tbody>
        <tr>
          <td data-label="Name">{r.name}</td>
          <td data-label="Ports">{r.ports.join(", ")}</td>
          <td className="actions" data-label="">…</td>
        </tr>
      </tbody>
    </table>
  </TableWrap>
  ```

  `data-label=""` opts a cell out of labelling (action clusters, `colSpan`
  detail rows, which also take `className="row-detail"`). Outside the compact
  query `data-label` has no effect at all, so desktop cannot be affected. This
  was chosen over a generic `DataTable` component because `Downloads` changes its
  column count by role and `Users`/`Roles` have expander rows - a column-config
  component would need row-expander, cell-renderer and per-cell className APIs.
  Trade-off: `display: block` strips implicit table roles, so the phone rendering
  is a list of labelled pairs, which is why the label is repeated in every cell.
- **Forms stack automatically.** Inside the compact query, direct children of
  `.row` go full width, which handles every filter and create form without
  per-view markup. Add `.row-inline` to opt a pure toolbar out.
- `TableWrap` also owns horizontal scroll on desktop, so a wide table no longer
  drags its section heading and toolbar sideways the way it did when `.content`
  was the only scroll container.

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
| `VITE_AUTH_ORIGIN` | empty | Origin that mints Guacamole and RTSP tokens (`/guac/token`, `/rtsp/token`) |

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
  a server-side change breaks them silently. Third one: a `<td>`'s `data-label`
  must match its `<th>` text, and is repeated per row - nothing checks it, and a
  mismatch is invisible until someone looks at the page on a phone.
- **CSP:** the app is designed for a strict same-origin CSP. Hashed asset
  filenames keep `script-src 'self'` viable; there are no CDN scripts,
  fonts, or external images. Theme art is imported from `src/assets/theme/`
  through Vite (fingerprinted into `/assets/`) rather than `public/`, so it
  is served from the same origin the CSP allows. See
  [docs/THEME-ASSETS.md](../docs/THEME-ASSETS.md) for the drop-in asset
  slots; rebuild after swapping.
- Admin sections apply a distinct theme class; portal sections keep the plain
  dark theme. Motion is disabled under `prefers-reduced-motion`.
- The graveyard decorations are unchanged by the responsive work: the marquee,
  tiled background, custom cursor and both fixed cobwebs still render on a
  phone. The only adjustment is the cobwebs' `top`, which offsets them below the
  mobile top bar so they decorate the content instead of sitting behind it. They
  keep `pointer-events: none`, so they never intercepted taps.
- Values that used to be reachable only through a `title` tooltip are now real
  UI, because touch cannot show a tooltip and the keyboard cannot reach one: the
  download failure reason is a disclosure toggle, and the magnet URI unclamps
  into its card on phones (it stays ellipsised on desktop).
