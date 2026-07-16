# Retro theme assets

Two hand-themed surfaces ship with **placeholder GIF/PNG art** (generated pixel
art). Every file below is a drop-in slot: overwrite it with a "real" retro GIF of
the **same filename** and the theme picks it up with no code changes. Keep the
listed dimensions (or close) so layout stays sane.

Hard constraints (do not break these):

- **Same-origin only.** Both apps run a strict CSP with no external hosts. Assets
  must stay in the directories below. No CDN, no hotlinking.
- **IdP** (`img-src 'self'`): plain files served from `/static/img/`.
- **Admin** (`img-src 'self' data:`): files are **imported/referenced from
  `ui/src/`** so Vite fingerprints them into `/assets/`. The admin server only
  serves `/assets` (all other paths fall back to `index.html`), so **do not** move
  these into `ui/public/`.

## IdP -- "Space / Stars" theme

Directory: `server/src/hyproxy/idp/web/static/img/`

| File                     | Purpose                                   | Size (px) |
|--------------------------|-------------------------------------------|-----------|
| `stars-tile.gif`         | Tessellated deep-space page background     | 64x64 (seamless) |
| `star.gif`               | Twinkling star (marquee + page accents)    | 16x16     |
| `rocket.gif`             | Login / enroll / signed-in mascot          | 48x48     |
| `ufo.gif`                | Header + passkey/TOTP mascot               | 48x32     |
| `planet.gif`            | Header + TOTP mascot                        | 40x40     |
| `alien.gif`              | Footer + error/step-up mascot              | 32x32     |
| `under-construction.gif` | Classic caution banner (footer)            | 88x31     |
| `rainbow-line.gif`       | Horizontal rainbow rule (repeats-x)        | ~120x6    |
| `netscape-badge.gif`     | "Best viewed at 800x600" badge             | 88x31     |
| `cursor-star.png`        | Custom cursor (`cursor: url(...)`)         | 16x16     |

Referenced from: `static/css/main.css` (backgrounds, cursor, rainbow rule) and
`templates/base.html` + the per-page templates (mascots, badges). The footer
visitor counter is driven by `static/js/retro.js` (no image needed).

## Admin -- "Graveyard" theme (admin sections only)

Directory: `ui/src/assets/theme/`

| File                  | Purpose                                       | Size (px) |
|-----------------------|-----------------------------------------------|-----------|
| `graveyard-tile.gif`  | Tessellated dark-dirt background (admin only)  | 64x64 (seamless) |
| `skull.gif`           | Top epitaph marquee                            | 32x32     |
| `bat.gif`             | Flapping bat in the marquee                     | 32x16     |
| `cobweb.gif`          | Fixed corner cobwebs (top-left + mirrored TR)  | 48x48     |
| `tombstone.gif`       | Spare grave accent (available for future use)  | 32x36     |
| `cursor-skull.png`    | Custom cursor (`cursor: url(...)`)             | 16x16     |

Referenced from: `ui/src/styles.css` (background tile + cursor, under
`.theme-crypt`) and `ui/src/App.tsx` (marquee skull/bat, cobweb corners, imported
so Vite bundles them). After swapping any admin asset, rebuild: `cd ui && npm run
build`.

## Notes

- The theme is deliberately over-the-top (marquees, blink, twinkle, flicker).
  Motion is disabled under `prefers-reduced-motion`.
- The admin graveyard theme is scoped to **admin** sections. The user-facing
  portal pages (My resources / Downloads / Account) intentionally keep the plain
  dark theme.
