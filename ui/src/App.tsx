import { useEffect, useState } from "react";
import { beginLogin, completeLogin, currentUserEmail, isAuthenticated, signOut } from "./lib/auth";
import { Users } from "./views/Users";
import { Roles } from "./views/Roles";
import { Resources } from "./views/Resources";
import { Policies } from "./views/Policies";
import { AccessAudit } from "./views/AccessAudit";
import { AuthEvents } from "./views/AuthEvents";
import { PolicyChanges } from "./views/PolicyChanges";

type Boot = "loading" | "ready" | "error";

const SECTIONS = [
  { id: "users", label: "Users", render: () => <Users /> },
  { id: "roles", label: "Roles", render: () => <Roles /> },
  { id: "resources", label: "Resources", render: () => <Resources /> },
  { id: "policies", label: "Policies", render: () => <Policies /> },
  { id: "access", label: "Access audit", render: () => <AccessAudit /> },
  { id: "auth", label: "Auth events", render: () => <AuthEvents /> },
  { id: "changes", label: "Policy changes", render: () => <PolicyChanges /> },
] as const;

export function App() {
  const [boot, setBoot] = useState<Boot>("loading");
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<string>("users");

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

  const active = SECTIONS.find((s) => s.id === section) ?? SECTIONS[0];
  return (
    <div className="layout">
      <nav className="sidebar">
        <h1>hyproxy</h1>
        <ul>
          {SECTIONS.map((s) => (
            <li key={s.id}>
              <button
                className={s.id === section ? "nav active" : "nav"}
                onClick={() => setSection(s.id)}
              >
                {s.label}
              </button>
            </li>
          ))}
        </ul>
        <div className="who">
          <span>{currentUserEmail() ?? "admin"}</span>
          <button className="link" onClick={() => signOut()}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="content">{active.render()}</main>
    </div>
  );
}
