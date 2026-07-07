import { useState } from "react";
import { api } from "../lib/api";
import { isAdmin } from "../lib/auth";
import type { DownloadRequest } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";

// Client-side fast feedback only; the server is authoritative
// (MAGNET_RE in server/src/hyproxy/admin/schemas.py).
const MAGNET_RE = /^magnet:\?xt=urn:btih:(?:[0-9a-fA-F]{40}|[a-zA-Z2-7]{32})(?:&\S*)?$/;

const TARGETS = ["Alpha", "Bravo"] as const;

export function Downloads() {
  const admin = isAdmin();
  const { data, error, loading, reload } = useResource<DownloadRequest[]>("/portal/downloads");
  const [msg, setMsg] = useState<string | null>(null);
  const [kind, setKind] = useState<"error" | "info">("info");
  const [magnet, setMagnet] = useState("");
  const [target, setTarget] = useState<"alpha" | "bravo">("alpha");

  async function submit() {
    if (!MAGNET_RE.test(magnet.trim())) {
      setKind("error");
      setMsg("Enter a magnet link (magnet:?xt=urn:btih:...).");
      return;
    }
    const err = await runMutation(() =>
      api.post<DownloadRequest>("/portal/downloads", { magnet: magnet.trim(), target }),
    );
    if (err) {
      setKind("error");
      setMsg(err);
    } else {
      setKind("info");
      setMsg(admin ? "Download submitted." : "Request submitted for approval.");
      setMagnet("");
    }
    reload();
  }

  async function review(r: DownloadRequest, decision: "approve" | "deny") {
    const err = await runMutation(() => api.post(`/portal/downloads/${r.id}/${decision}`, {}));
    setKind(err ? "error" : "info");
    setMsg(err ?? (decision === "approve" ? "Request approved and submitted." : "Request denied."));
    reload();
  }

  return (
    <Section title="Downloads">
      <Banner kind={kind} message={msg} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <input
          className="grow"
          placeholder="magnet:?xt=urn:btih:..."
          value={magnet}
          onChange={(e) => setMagnet(e.target.value)}
          required
        />
        <select value={target} onChange={(e) => setTarget(e.target.value as "alpha" | "bravo")}>
          {TARGETS.map((t) => (
            <option key={t} value={t.toLowerCase()}>
              {t}
            </option>
          ))}
        </select>
        <button type="submit">{admin ? "Add download" : "Request download"}</button>
      </form>
      {!admin && <p className="muted">Requests are queued until an administrator approves them.</p>}

      <AsyncBody loading={loading} error={error} empty={(data ?? []).length === 0}>
        <table>
          <thead>
            <tr>
              {admin && <th>Requested by</th>}
              <th>Magnet</th>
              <th>Destination</th>
              <th>Status</th>
              <th>Requested</th>
              {admin && <th></th>}
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((r) => (
              <tr key={r.id}>
                {admin && <td>{r.user_email ?? r.user_id}</td>}
                <td className="mono magnet" title={r.magnet}>
                  {r.magnet}
                </td>
                <td>{r.target === "alpha" ? "Alpha" : "Bravo"}</td>
                <td>
                  <span className={`status ${r.status}`}>{r.status}</span>
                  {r.error && r.status === "pending" && (
                    <span className="error" title={r.error}>
                      {" "}
                      (failed)
                    </span>
                  )}
                </td>
                <td>{new Date(r.created_at).toLocaleString()}</td>
                {admin && (
                  <td className="actions">
                    {r.status === "pending" && (
                      <>
                        <button className="link" onClick={() => void review(r, "approve")}>
                          Approve
                        </button>
                        <button className="link danger" onClick={() => void review(r, "deny")}>
                          Deny
                        </button>
                      </>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBody>
    </Section>
  );
}
