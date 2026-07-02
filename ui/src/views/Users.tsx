import { useState } from "react";
import { api } from "../lib/api";
import type { User } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";

export function Users() {
  const { data, error, loading, reload } = useResource<User[]>("/users");
  const [msg, setMsg] = useState<string | null>(null);
  const [form, setForm] = useState({
    email: "",
    display_name: "",
    auth_tier: "standard",
    temp_password: "",
  });

  async function create() {
    setMsg(await runMutation(() => api.post<User>("/users", form)));
    setForm({ email: "", display_name: "", auth_tier: "standard", temp_password: "" });
    reload();
  }

  async function remove(id: string) {
    setMsg(await runMutation(() => api.del(`/users/${id}`)));
    reload();
  }

  async function setStatus(u: User, status: string) {
    setMsg(await runMutation(() => api.patch<User>(`/users/${u.id}`, { status })));
    reload();
  }

  return (
    <Section title="Users">
      <Banner kind="info" message={msg} />
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <input
          placeholder="email"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
          required
        />
        <input
          placeholder="display name"
          value={form.display_name}
          onChange={(e) => setForm({ ...form, display_name: e.target.value })}
          required
        />
        <select
          value={form.auth_tier}
          onChange={(e) => setForm({ ...form, auth_tier: e.target.value })}
        >
          <option value="standard">standard</option>
          <option value="admin">admin</option>
        </select>
        <input
          type="password"
          placeholder="temp password (>=12)"
          value={form.temp_password}
          onChange={(e) => setForm({ ...form, temp_password: e.target.value })}
          minLength={12}
          required
        />
        <button type="submit">Add user</button>
      </form>

      <AsyncBody loading={loading} error={error} empty={(data ?? []).length === 0}>
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Name</th>
              <th>Tier</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((u) => (
              <tr key={u.id}>
                <td>{u.email}</td>
                <td>{u.display_name}</td>
                <td>{u.auth_tier}</td>
                <td>{u.status}</td>
                <td className="actions">
                  {u.status === "active" ? (
                    <button className="link" onClick={() => setStatus(u, "disabled")}>
                      Disable
                    </button>
                  ) : (
                    <button className="link" onClick={() => setStatus(u, "active")}>
                      Enable
                    </button>
                  )}
                  <button className="link danger" onClick={() => remove(u.id)}>
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
