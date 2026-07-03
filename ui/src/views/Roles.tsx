import { useState } from "react";
import { api } from "../lib/api";
import type { Role } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";

export function Roles() {
  const { data, error, loading, reload } = useResource<Role[]>("/roles");
  const [msg, setMsg] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", description: "" });

  async function create() {
    setMsg(
      await runMutation(() =>
        api.post<Role>("/roles", { name: form.name, description: form.description || null }),
      ),
    );
    setForm({ name: "", description: "" });
    reload();
  }

  async function remove(id: string) {
    setMsg(await runMutation(() => api.del(`/roles/${id}`)));
    reload();
  }

  return (
    <Section title="Roles">
      <Banner kind="info" message={msg} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <input
          placeholder="role name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          required
        />
        <input
          placeholder="description (optional)"
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
        />
        <button type="submit">Add role</button>
      </form>

      <AsyncBody loading={loading} error={error} empty={(data ?? []).length === 0}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>{r.description}</td>
                <td className="actions">
                  <button className="link danger" onClick={() => remove(r.id)}>
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
