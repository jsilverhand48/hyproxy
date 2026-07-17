import { useState } from "react";
import { api } from "../lib/api";
import type { Resource } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ConnectionDialog } from "../components/ConnectionDialog";

const PROTOCOLS = ["http", "https", "tcp", "vnc", "rdp", "ssh"];
const GUAC_PROTOCOLS = new Set(["vnc", "rdp", "ssh"]);

export function Resources() {
  const { data, error, loading, reload } = useResource<Resource[]>("/resources");
  const [msg, setMsg] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Resource | null>(null);
  const [editingConnection, setEditingConnection] = useState<Resource | null>(null);
  const [form, setForm] = useState({ name: "", protocol: "https", public_host: "", host: "", ports: "" });

  async function create() {
    const ports = form.ports
      .split(",")
      .map((p) => Number(p.trim()))
      .filter((p) => Number.isInteger(p) && p > 0);
    setMsg(
      await runMutation(() =>
        api.post<Resource>("/resources", {
          name: form.name,
          protocol: form.protocol,
          public_host: form.public_host.trim() || null,
          host: form.host,
          ports,
        }),
      ),
    );
    setForm({ name: "", protocol: "https", public_host: "", host: "", ports: "" });
    reload();
  }

  async function toggle(r: Resource) {
    setMsg(await runMutation(() => api.patch<Resource>(`/resources/${r.id}`, { enabled: !r.enabled })));
    reload();
  }

  async function editRoute(r: Resource) {
    const next = window.prompt(
      `Public host (routing key) for "${r.name}". Blank removes the route.`,
      r.public_host ?? "",
    );
    if (next === null) return; // cancelled
    setMsg(
      await runMutation(() =>
        api.patch<Resource>(`/resources/${r.id}`, { public_host: next.trim() || null }),
      ),
    );
    reload();
  }

  async function remove(id: string) {
    setMsg(await runMutation(() => api.del(`/resources/${id}`)));
    reload();
  }

  return (
    <Section title="Resources">
      <Banner kind="info" message={msg} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <input
          placeholder="name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          required
        />
        <select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
          {PROTOCOLS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <input
          placeholder="public host (route)"
          value={form.public_host}
          onChange={(e) => setForm({ ...form, public_host: e.target.value })}
        />
        <input
          placeholder="backend host"
          value={form.host}
          onChange={(e) => setForm({ ...form, host: e.target.value })}
          required
        />
        <input
          placeholder="ports (comma sep)"
          value={form.ports}
          onChange={(e) => setForm({ ...form, ports: e.target.value })}
          required
        />
        <button type="submit">Add resource</button>
      </form>

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
                <td>{r.public_host ?? <span className="muted">(no route)</span>}</td>
                <td>{r.host}</td>
                <td>{r.ports.join(", ")}</td>
                <td>{r.enabled ? "yes" : "no"}</td>
                <td className="actions">
                  <button className="link" onClick={() => editRoute(r)}>
                    Route
                  </button>
                  {GUAC_PROTOCOLS.has(r.protocol) && (
                    <button className="link" onClick={() => setEditingConnection(r)}>
                      Connection
                    </button>
                  )}
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
      {editingConnection !== null && (
        <ConnectionDialog resource={editingConnection} onClose={() => setEditingConnection(null)} />
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
