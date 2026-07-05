import { Fragment, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { Role, User } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";
import { ConfirmDialog } from "../components/ConfirmDialog";

// Inline membership management for one role. The backend exposes the user-role
// relationship only from the user side (GET/PUT/DELETE
// /users/{user_id}/roles/{role_id}); there is no GET /roles/{id}/users. So we
// derive this role's current members client-side by asking each user which
// roles they hold and keeping the ones that include this role. Attach/detach
// reuse those same user-centric endpoints. Writes require a fresh step-up,
// which runMutation turns into the IdP redirect.
function MemberPanel({ role, allUsers }: { role: Role; allUsers: User[] }) {
  const [memberIds, setMemberIds] = useState<Set<string> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [selected, setSelected] = useState("");
  const [tick, setTick] = useState(0);
  const [pendingRemove, setPendingRemove] = useState<User | null>(null);

  useEffect(() => {
    let live = true;
    setMemberIds(null);
    setError(null);
    Promise.all(
      allUsers.map(async (u) => {
        const names = await api.get<string[]>(`/users/${u.id}/roles`);
        return names.includes(role.name) ? u.id : null;
      }),
    )
      .then((ids) => {
        if (live) setMemberIds(new Set(ids.filter((id): id is string => id !== null)));
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      live = false;
    };
  }, [role.id, role.name, allUsers, tick]);

  const reload = () => setTick((t) => t + 1);
  const members = memberIds ? allUsers.filter((u) => memberIds.has(u.id)) : [];
  const assignable = memberIds ? allUsers.filter((u) => !memberIds.has(u.id)) : [];

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
      <AsyncBody loading={memberIds === null && error === null} error={error} empty={false}>
        <div className="chips">
          {members.length === 0 && <span className="muted">No members.</span>}
          {members.map((u) => (
            <span key={u.id} className="chip">
              {u.email}
              <button
                className="link danger chip-x"
                title="Remove member"
                onClick={() => setPendingRemove(u)}
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
      {pendingRemove !== null && (
        <ConfirmDialog
          title="Remove member"
          message={`Remove role "${role.name}" from ${pendingRemove.email}?`}
          confirmLabel="Remove"
          danger
          onConfirm={() => {
            void unassign(pendingRemove.id);
            setPendingRemove(null);
          }}
          onCancel={() => setPendingRemove(null)}
        />
      )}
    </div>
  );
}

export function Roles() {
  const { data, error, loading, reload } = useResource<Role[]>("/roles");
  const users = useResource<User[]>("/users");
  const [msg, setMsg] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Role | null>(null);
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
                    <button className="link danger" onClick={() => setPendingDelete(r)}>
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
      {pendingDelete !== null && (
        <ConfirmDialog
          title="Delete role"
          message={`Delete role "${pendingDelete.name}"? Policies referencing it are affected.`}
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
