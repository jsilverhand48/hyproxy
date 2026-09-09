import { useEffect, useRef, useState } from "react";
import {
  beginLogin,
  completeLogin,
  currentUserEmail,
  isAdmin,
  isAuthenticated,
  signOut,
} from "./lib/auth";
import { config } from "./lib/config";
import { Users } from "./views/Users";
import { Roles } from "./views/Roles";
import { Resources } from "./views/Resources";
import { Policies } from "./views/Policies";
import { AccessAudit } from "./views/AccessAudit";
import { AuthEvents } from "./views/AuthEvents";
import { PolicyChanges } from "./views/PolicyChanges";
import { MyResources } from "./views/MyResources";
import { Connect } from "./views/Connect";
import { Watch } from "./views/Watch";
import { Downloads } from "./views/Downloads";
import { Account } from "./views/Account";
// Graveyard-theme chrome assets. Imported so Vite fingerprints them into
// /assets/ -- the admin server only serves that mount (every other path falls
// back to index.html), so these must not live in ui/public.
import skullGif from "./assets/theme/skull.gif";
import batGif from "./assets/theme/bat.gif";
import cobwebGif from "./assets/theme/cobweb.gif";

type Boot = "loading" | "ready" | "error";

const ADMIN_SECTIONS = [
  { id: "users", label: "Users", render: () => <Users /> },
  { id: "roles", label: "Roles", render: () => <Roles /> },
  { id: "resources", label: "Resources", render: () => <Resources /> },
  { id: "policies", label: "Policies", render: () => <Policies /> },
  { id: "access", label: "Access audit", render: () => <AccessAudit /> },
  { id: "auth", label: "Auth events", render: () => <AuthEvents /> },
  { id: "changes", label: "Policy changes", render: () => <PolicyChanges /> },
] as const;

const PORTAL_SECTIONS = [
  { id: "my-resources", label: "My resources", render: () => <MyResources /> },
  { id: "downloads", label: "Downloads", render: () => <Downloads /> },
  { id: "account", label: "Account", render: () => <Account /> },
] as const;

// Standard users only ever get the portal sections. Admins get the management
// sections too, except on the portal host, where the management API would
// reject off-LAN calls anyway (the server enforces tier and LAN regardless of
// what is rendered here).
function visibleSections() {
  return isAdmin() && !config.isPortal ? [...ADMIN_SECTIONS, ...PORTAL_SECTIONS] : [...PORTAL_SECTIONS];
}

export function App() {
  const [boot, setBoot] = useState<Boot>("loading");
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<string | null>(null);
  // Off-canvas drawer state. Only has an effect below the compact breakpoint
  // (see styles.css); on desktop the sidebar is always in the grid and .topbar
  // is display:none, so this stays false and costs nothing.
  const [navOpen, setNavOpen] = useState(false);
  const hamburgerRef = useRef<HTMLButtonElement | null>(null);
  const drawerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (window.location.pathname === "/callback") {
          const returnTo = await completeLogin(window.location.search);
          window.history.replaceState({}, "", returnTo ?? "/");
        }
        if (!isAuthenticated()) {
          await beginLogin(); // navigates away; nothing below runs
          return;
        }
        if (!cancelled) setBoot("ready");
      } catch (e: unknown) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setBoot("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // While the drawer covers the page: Escape closes it, the page behind must not
  // scroll, and focus moves into the drawer and back to the toggle on close.
  // There is no focus trap, matching the existing Modal in ConfirmDialog.
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawerRef.current?.querySelector<HTMLButtonElement>("button.nav")?.focus();
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
      hamburgerRef.current?.focus();
    };
  }, [navOpen]);

  if (boot === "loading") return <p className="center">Signing in...</p>;
  if (boot === "error")
    return (
      <div className="center">
        <p className="error">Sign-in failed: {error}</p>
        <button onClick={() => beginLogin()}>Try again</button>
      </div>
    );

  // Full-screen guac session and rtsp camera views; the resource id is
  // authorized server-side (token mint + portal listing), the path only
  // selects the view.
  const connectMatch = window.location.pathname.match(/^\/connect\/([0-9a-f-]{36})$/i);
  if (connectMatch) return <Connect resourceId={connectMatch[1]} />;

  const watchMatch = window.location.pathname.match(/^\/watch\/([0-9a-f-]{36})$/i);
  if (watchMatch) return <Watch resourceId={watchMatch[1]} />;

  const sections = visibleSections();
  const active = sections.find((s) => s.id === section) ?? sections[0];
  // Spooky graveyard theme applies to admin sections only; portal sections
  // (my-resources / downloads / account) keep the plain dark theme.
  const isAdminView = ADMIN_SECTIONS.some((s) => s.id === active.id);
  return (
    <div
      className={`layout${isAdminView ? " theme-crypt" : ""}${navOpen ? " nav-open" : ""}`}
    >
      {/* Mobile chrome only: styles.css keeps .topbar display:none above the
          compact breakpoint, and a display:none grid child contributes no track,
          so the desktop grid -- including .layout.theme-crypt's marquee row --
          is untouched by this existing. */}
      <div className="topbar">
        <button
          className="hamburger"
          ref={hamburgerRef}
          aria-label={navOpen ? "Close menu" : "Open menu"}
          aria-expanded={navOpen}
          aria-controls="sidebar-nav"
          onClick={() => setNavOpen((o) => !o)}
        >
          <span aria-hidden="true">&#9776;</span>
        </button>
        <span className="topbar-title">hyproxy</span>
        <span className="topbar-section">{active.label}</span>
      </div>
      {isAdminView && (
        <>
          <div className="crypt-marquee" aria-hidden="true">
            <span className="crypt-marquee-track">
              <img src={skullGif} width={20} alt="" /> R.I.P. unauthorized
              access &mdash; here lies every request that failed policy &mdash; enter,
              mortal administrator <img src={batGif} width={28} alt="" /> R.I.P.
              unauthorized access &mdash; here lies every request that failed policy
              &mdash; enter, mortal administrator <img src={batGif} width={28} alt="" />
            </span>
          </div>
          <img className="cobweb cobweb-tl" src={cobwebGif} width={48} height={48} alt="" aria-hidden="true" />
          <img className="cobweb cobweb-tr" src={cobwebGif} width={48} height={48} alt="" aria-hidden="true" />
        </>
      )}
      {navOpen && <div className="nav-backdrop" onClick={() => setNavOpen(false)} />}
      <nav className="sidebar" id="sidebar-nav" ref={drawerRef}>
        <h1>hyproxy</h1>
        <ul>
          {sections.map((s) => (
            <li key={s.id}>
              <button
                className={s.id === active.id ? "nav active" : "nav"}
                onClick={() => {
                  setSection(s.id);
                  setNavOpen(false);
                }}
              >
                {s.label}
              </button>
            </li>
          ))}
        </ul>
        <div className="who">
          <span>{currentUserEmail() ?? "signed in"}</span>
          <button className="link" onClick={() => signOut()}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="content">{active.render()}</main>
    </div>
  );
}
