import { useState } from "react";
import { api } from "../lib/api";
import type { Resource } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section, TableWrap } from "../components/ui";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ResourceDialog } from "../components/ResourceDialog";

// Reached through a fixed path on the portal host, so they never carry a
// public host of their own.
const TUNNEL_PROTOCOLS = new Set(["vnc", "rdp", "ssh", "rtsp"]);

export function Resources() {
  const { data, error, loading, reload } = useResource<Resource[]>("/resources");
  const [msg, setMsg] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Resource | null>(null);
  // null = closed; { resource: null } = add; { resource } = edit.
  const [dialog, setDialog] = useState<{ resource: Resource | null } | null>(null);

  async function toggle(r: Resource) {
    setMsg(await runMutation(() => api.patch<Resource>(`/resources/${r.id}`, { enabled: !r.enabled })));
    reload();
  }

  async function remove(id: string) {
    setMsg(await runMutation(() => api.del(`/resources/${id}`)));
    reload();
  }

  return (
    <Section title="Resources">
      <Banner kind="info" message={msg} />
      <div className="row">
        <button onClick={() => setDialog({ resource: null })}>Add resource</button>
      </div>

      <AsyncBody loading={loading} error={error} empty={(data ?? []).length === 0}>
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Protocol</th>
                <th>Public host</th>
                <th>Backend host</th>
                <th>Ports</th>
                <th>Access</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((r) => (
                <tr key={r.id}>
                  <td data-label="Name">{r.name}</td>
                  <td data-label="Protocol">{r.protocol}</td>
                  <td data-label="Public host">
                    {TUNNEL_PROTOCOLS.has(r.protocol) ? (
                      <span className="muted">(tunnel)</span>
                    ) : (
                      r.public_host ?? <span className="muted">(no route)</span>
                    )}
                  </td>
                  <td data-label="Backend host">{r.host}</td>
                  <td data-label="Access">
                    {r.public_access ? (
                      // A public resource with no password generated yet is
                      // unreachable, so flag it rather than showing it as live.
                      r.public_password_set ? (
                        "public (password)"
                      ) : (
                        <span className="muted">public (no password)</span>
                      )
                    ) : (
                      <span className="muted">sign-in</span>
                    )}
                  </td>
                  <td data-label="Enabled">{r.enabled ? "yes" : "no"}</td>
                  <td className="actions" data-label="">
                    <button className="link" onClick={() => setDialog({ resource: r })}>
                      Edit
                    </button>
                    <button className="link" onClick={() => toggle(r)}>
                      {r.enabled ? "Disable" : "Enable"}
                    </button>
                    <button className="link danger" onClick={() => setPendingDelete(r)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </AsyncBody>
      {dialog !== null && (
        <ResourceDialog
          resource={dialog.resource}
          onClose={() => setDialog(null)}
          onSaved={reload}
        />
      )}
      {pendingDelete !== null && (
        <ConfirmDialog
          title="Delete resource"
          message={`Delete resource "${pendingDelete.name}"? Policies referencing it are affected.`}
          confirmLabel="Delete"
          danger
          onConfirm={() => {
            void remove(pendingDelete.id);
            setPendingDelete(null);
          }}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </Section>
  );
}
