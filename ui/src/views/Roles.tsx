import { Fragment, useState } from "react";
import { api } from "../lib/api";
import type { Role, User } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";

// Inline membership management for one role. Members are attached/detached via
// the same user-role endpoints the Users view uses, just keyed from the role
// side (PUT/DELETE /users/{user_id}/roles/{role_id}). Writes require a fresh
// step-up, which runMutation turns into the IdP redirect.
function MemberPanel({ role, allUsers }: { role: Role; allUsers: User[] }) {
  const { data, error, loading, reload } = useResource<User[]>(`/roles/${role.id}/users`);
  const [msg, setMsg] = useState<string | null>(null);
  const [selected, setSelected] = useState("");

  const members = data ?? [];
  const memberIds = new Set(members.map((u) => u.id));
  const assignable = allUsers.filter((u) => !memberIds.has(u.id));

  async function assign() {
    if (!selected) return;
    setMsg(await runMutation(() => api.put(`/users/${selected}/roles/${role.id}`)));
    setSelected("");
    reload();
  }

  async function unassign(userId: string) {
    setMsg(await runMutation(() => api.del(`/users/${userId}/roles/${role.id}`)));
    reload();
  }

  return (
    <div className="rolepanel">
      <Banner kind="info" message={msg} />
      <AsyncBody loading={loading} error={error} empty={false}>
        <div className="chips">
          {members.length === 0 && <span className="muted">No members.</span>}
          {members.map((u) => (
            <span key={u.id} className="chip">
              {u.email}
              <button
                className="link danger chip-x"
                title="Remove member"
                onClick={() => void unassign(u.id)}
              >
                &times;
              </button>
            </span>
          ))}
        </div>
        <div className="row">
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            <option value="">Add user...</option>
            {assignable.map((u) => (
              <option key={u.id} value={u.id}>
                {u.email}
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

export function Roles() {
  const { data, error, loading, reload } = useResource<Role[]>("/roles");
  const users = useResource<User[]>("/users");
  const [msg, setMsg] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
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
              <Fragment key={r.id}>
                <tr>
                  <td>{r.name}</td>
                  <td>{r.description}</td>
                  <td className="actions">
                    <button
                      className="link"
                      onClick={() => setOpenId(openId === r.id ? null : r.id)}
                    >
                      {openId === r.id ? "Hide members" : "Members"}
                    </button>
                    <button className="link danger" onClick={() => remove(r.id)}>
                      Delete
                    </button>
                  </td>
                </tr>
                {openId === r.id && (
                  <tr>
                    <td colSpan={3}>
                      {users.error ? (
                        <p className="error">{users.error}</p>
                      ) : (
                        <MemberPanel role={r} allUsers={users.data ?? []} />
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
