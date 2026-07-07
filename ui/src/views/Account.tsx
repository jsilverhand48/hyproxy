import { useState } from "react";
import { api } from "../lib/api";
import { currentUserEmail } from "../lib/auth";
import { runMutation } from "../lib/useApi";
import { Banner, Section } from "../components/ui";

export function Account() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [kind, setKind] = useState<"error" | "info">("info");

  async function changePassword() {
    if (next !== confirm) {
      setKind("error");
      setMsg("New passwords do not match.");
      return;
    }
    if (next.length < 12) {
      setKind("error");
      setMsg("New password must be at least 12 characters.");
      return;
    }
    const err = await runMutation(() =>
      api.post("/portal/me/password", { current_password: current, new_password: next }),
    );
    if (err) {
      setKind("error");
      setMsg(err);
      return;
    }
    setKind("info");
    setMsg("Password changed; your other sessions were signed out.");
    setCurrent("");
    setNext("");
    setConfirm("");
  }

  return (
    <Section title="Account">
      <Banner kind={kind} message={msg} />
      <p className="muted">Signed in as {currentUserEmail() ?? "unknown"}</p>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void changePassword();
        }}
      >
        <input
          type="password"
          placeholder="current password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="new password (min 12 chars)"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="confirm new password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
        />
        <button type="submit">Change password</button>
      </form>
    </Section>
  );
}
