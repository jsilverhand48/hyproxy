import { useEffect, useState } from "react";
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

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (window.location.pathname === "/callback") {
          await completeLogin(window.location.search);
          window.history.replaceState({}, "", "/");
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

  if (boot === "loading") return <p className="center">Signing in...</p>;
  if (boot === "error")
    return (
      <div className="center">
        <p className="error">Sign-in failed: {error}</p>
        <button onClick={() => beginLogin()}>Try again</button>
      </div>
    );

  const sections = visibleSections();
  const active = sections.find((s) => s.id === section) ?? sections[0];
  // Spooky graveyard theme applies to admin sections only; portal sections
  // (my-resources / downloads / account) keep the plain dark theme.
  const isAdminView = ADMIN_SECTIONS.some((s) => s.id === active.id);
  return (
    <div className={isAdminView ? "layout theme-crypt" : "layout"}>
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
      <nav className="sidebar">
        <h1>hyproxy</h1>
        <ul>
          {sections.map((s) => (
            <li key={s.id}>
              <button
                className={s.id === active.id ? "nav active" : "nav"}
                onClick={() => setSection(s.id)}
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
