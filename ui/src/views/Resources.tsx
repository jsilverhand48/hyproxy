import { useState } from "react";
import { api } from "../lib/api";
import type { Resource } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ResourceDialog } from "../components/ResourceDialog";

const GUAC_PROTOCOLS = new Set(["vnc", "rdp", "ssh"]);

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
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Protocol</th>
              <th>Public host</th>
              <th>Backend host</th>
              <th>Ports</th>
              <th>Enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>{r.protocol}</td>
                <td>
                  {GUAC_PROTOCOLS.has(r.protocol) ? (
                    <span className="muted">(tunnel)</span>
                  ) : (
                    r.public_host ?? <span className="muted">(no route)</span>
                  )}
                </td>
                <td>{r.host}</td>
                <td>{r.ports.join(", ")}</td>
                <td>{r.enabled ? "yes" : "no"}</td>
                <td className="actions">
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
