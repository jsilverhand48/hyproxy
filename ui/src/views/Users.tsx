import { Fragment, useState } from "react";
import { api } from "../lib/api";
import { currentUserEmail } from "../lib/auth";
import type { Role, User } from "../lib/types";
import { runMutation, useResource } from "../lib/useApi";
import { AsyncBody, Banner, Section } from "../components/ui";
import { ConfirmDialog, Modal } from "../components/ConfirmDialog";

// Inline role management for one user. The list endpoint returns role *names*
// (list[str]); attach/detach are keyed by role *id*, so we map name -> id from
// the full roles list. Writes require a fresh step-up, which runMutation turns
// into the IdP redirect.
function RolePanel({ user, allRoles }: { user: User; allRoles: Role[] }) {
  const { data, error, loading, reload } = useResource<string[]>(`/users/${user.id}/roles`);
  const [msg, setMsg] = useState<string | null>(null);
  const [selected, setSelected] = useState("");
  const [pendingRemove, setPendingRemove] = useState<string | null>(null);

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
                onClick={() => setPendingRemove(name)}
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
      {pendingRemove !== null && (
        <ConfirmDialog
          title="Remove role"
          message={`Remove role "${pendingRemove}" from ${user.email}?`}
          confirmLabel="Remove"
          danger
          onConfirm={() => {
            void unassign(pendingRemove);
            setPendingRemove(null);
          }}
          onCancel={() => setPendingRemove(null)}
        />
      )}
    </div>
  );
}

export function Users() {
  const { data, error, loading, reload } = useResource<User[]>("/users");
  const roles = useResource<Role[]>("/roles");
  const [msg, setMsg] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<{ kind: "delete" | "reset-totp"; user: User } | null>(
    null,
  );
  const [pwTarget, setPwTarget] = useState<User | null>(null);
  const [newPw, setNewPw] = useState("");
  const [form, setForm] = useState({
    email: "",
    display_name: "",
    auth_tier: "standard",
    temp_password: "",
  });

  const selfEmail = (currentUserEmail() ?? "").toLowerCase();

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

  async function resetTotp(u: User) {
    setMsg(
      (await runMutation(() => api.post(`/users/${u.id}/reset-totp`))) ??
        `2FA reset for ${u.email}; they re-enroll at next login.`,
    );
    reload();
  }

  async function resetPassword(u: User, tempPassword: string) {
    setMsg(
      (await runMutation(() =>
        api.post(`/users/${u.id}/reset-password`, { temp_password: tempPassword }),
      )) ?? `Password reset for ${u.email}; all their sessions were revoked.`,
    );
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
                    {u.status === "active"
                      ? !u.is_protected && (
                          <button className="link" onClick={() => setStatus(u, "disabled")}>
                            Disable
                          </button>
                        )
                      : (
                          <button className="link" onClick={() => setStatus(u, "active")}>
                            Enable
                          </button>
                        )}
                    <button className="link" onClick={() => setPwTarget(u)}>
                      Reset password
                    </button>
                    {u.auth_tier === "standard" && (
                      <button
                        className="link"
                        onClick={() => setConfirming({ kind: "reset-totp", user: u })}
                      >
                        Reset 2FA
                      </button>
                    )}
                    {!u.is_protected && u.email.toLowerCase() !== selfEmail && (
                      <button
                        className="link danger"
                        onClick={() => setConfirming({ kind: "delete", user: u })}
                      >
                        Delete
                      </button>
                    )}
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

      {confirming?.kind === "delete" && (
        <ConfirmDialog
          title="Delete user"
          message={`Delete user ${confirming.user.email}? Their sessions are revoked and this cannot be undone.`}
          confirmLabel="Delete"
          danger
          onConfirm={() => {
            void remove(confirming.user.id);
            setConfirming(null);
          }}
          onCancel={() => setConfirming(null)}
        />
      )}
      {confirming?.kind === "reset-totp" && (
        <ConfirmDialog
          title="Reset 2FA"
          message={`Reset 2FA for ${confirming.user.email}? Their authenticator and unused recovery codes are removed, sessions revoked, and they re-enroll at next login.`}
          confirmLabel="Reset 2FA"
          danger
          onConfirm={() => {
            void resetTotp(confirming.user);
            setConfirming(null);
          }}
          onCancel={() => setConfirming(null)}
        />
      )}
      {pwTarget !== null && (
        <Modal
          title="Reset password"
          onClose={() => {
            setPwTarget(null);
            setNewPw("");
          }}
        >
          <p>
            Set a new temporary password for {pwTarget.email}. All their sessions will be
            revoked.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void resetPassword(pwTarget, newPw);
              setPwTarget(null);
              setNewPw("");
            }}
          >
            <input
              type="password"
              placeholder="new temp password (>=12)"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              minLength={12}
              required
              autoFocus
            />
            <div className="modal-actions">
              <button
                type="button"
                onClick={() => {
                  setPwTarget(null);
                  setNewPw("");
                }}
              >
                Cancel
              </button>
              <button type="submit">Reset password</button>
            </div>
          </form>
        </Modal>
      )}
    </Section>
  );
}
