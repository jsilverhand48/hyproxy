import { useState } from "react";
import { api } from "../lib/api";
import type { Policy, Resource, Role } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";

export function Policies() {
  const policies = useResource<Policy[]>("/policies");
  const roles = useResource<Role[]>("/roles");
  const resources = useResource<Resource[]>("/resources");
  const [msg, setMsg] = useState<string | null>(null);
  const [form, setForm] = useState({ role_id: "", resource_id: "", action: "allow" });

  const roleName = (id: string) => roles.data?.find((r) => r.id === id)?.name ?? id;
  const resourceName = (id: string) => resources.data?.find((r) => r.id === id)?.name ?? id;

  async function create() {
    if (!form.role_id || !form.resource_id) {
      setMsg("Pick a role and a resource.");
      return;
    }
    setMsg(await runMutation(() => api.post<Policy>("/policies", form)));
    policies.reload();
  }

  async function toggle(p: Policy) {
    setMsg(await runMutation(() => api.patch<Policy>(`/policies/${p.id}`, { enabled: !p.enabled })));
    policies.reload();
  }

  async function remove(id: string) {
    setMsg(await runMutation(() => api.del(`/policies/${id}`)));
    policies.reload();
  }

  return (
    <Section title="Policies">
      <Banner kind="info" message={msg} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <select value={form.role_id} onChange={(e) => setForm({ ...form, role_id: e.target.value })}>
          <option value="">role...</option>
          {(roles.data ?? []).map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
        <select
          value={form.resource_id}
          onChange={(e) => setForm({ ...form, resource_id: e.target.value })}
        >
          <option value="">resource...</option>
          {(resources.data ?? []).map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
        <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
        <button type="submit">Add policy</button>
      </form>

      <AsyncBody
        loading={policies.loading}
        error={policies.error}
        empty={(policies.data ?? []).length === 0}
      >
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Resource</th>
              <th>Action</th>
              <th>Enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(policies.data ?? []).map((p) => (
              <tr key={p.id}>
                <td>{roleName(p.role_id)}</td>
                <td>{resourceName(p.resource_id)}</td>
                <td className={p.action === "deny" ? "danger" : ""}>{p.action}</td>
                <td>{p.enabled ? "yes" : "no"}</td>
                <td className="actions">
                  <button className="link" onClick={() => toggle(p)}>
                    {p.enabled ? "Disable" : "Enable"}
                  </button>
                  <button className="link danger" onClick={() => remove(p.id)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBody>
    </Section>
  );
}
