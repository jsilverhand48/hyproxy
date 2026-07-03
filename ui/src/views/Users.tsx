import { Fragment, useState } from "react";
import { api } from "../lib/api";
import type { Role, User } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";

// Inline role management for one user. The list endpoint returns role *names*
// (list[str]); attach/detach are keyed by role *id*, so we map name -> id from
// the full roles list. Writes require a fresh step-up, which runMutation turns
// into the IdP redirect.
function RolePanel({ user, allRoles }: { user: User; allRoles: Role[] }) {
  const { data, error, loading, reload } = useResource<string[]>(`/users/${user.id}/roles`);
  const [msg, setMsg] = useState<string | null>(null);
  const [selected, setSelected] = useState("");

  const assigned = data ?? [];
  const assignable = allRoles.filter((r) => !assigned.includes(r.name));
  const nameToId = new Map(allRoles.map((r) => [r.name, r.id]));

  async function assign() {
    if (!selected) return;
    setMsg(await runMutation(() => api.put(`/users/${user.id}/roles/${selected}`)));
    setSelected("");
    reload();
  }

  async function unassign(roleName: string) {
    const roleId = nameToId.get(roleName);
    if (!roleId) return;
    setMsg(await runMutation(() => api.del(`/users/${user.id}/roles/${roleId}`)));
    reload();
  }

  return (
    <div className="rolepanel">
      <Banner kind="info" message={msg} />
      <AsyncBody loading={loading} error={error} empty={false}>
        <div className="chips">
          {assigned.length === 0 && <span className="muted">No roles assigned.</span>}
          {assigned.map((name) => (
            <span key={name} className="chip">
              {name}
              <button
                className="link danger chip-x"
                title="Remove role"
                onClick={() => void unassign(name)}
              >
                &times;
              </button>
            </span>
          ))}
        </div>
        <div className="row">
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            <option value="">Add role...</option>
            {assignable.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
          <button onClick={() => void assign()} disabled={!selected}>
            Assign
          </button>
        </div>
      </AsyncBody>
    </div>
  );
}

export function Users() {
  const { data, error, loading, reload } = useResource<User[]>("/users");
  const roles = useResource<Role[]>("/roles");
  const [msg, setMsg] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
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
              <Fragment key={u.id}>
                <tr>
                  <td>{u.email}</td>
                  <td>{u.display_name}</td>
                  <td>{u.auth_tier}</td>
                  <td>{u.status}</td>
                  <td className="actions">
                    <button
                      className="link"
                      onClick={() => setOpenId(openId === u.id ? null : u.id)}
                    >
                      {openId === u.id ? "Hide roles" : "Roles"}
                    </button>
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
                {openId === u.id && (
                  <tr>
                    <td colSpan={5}>
                      {roles.error ? (
                        <p className="error">{roles.error}</p>
                      ) : (
                        <RolePanel user={u} allRoles={roles.data ?? []} />
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </AsyncBody>
    </Section>
  );
}
