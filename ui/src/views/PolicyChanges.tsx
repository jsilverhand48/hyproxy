import { useState } from "react";
import type { PolicyChange as Row } from "../lib/types";
import { usePaged } from "../lib/useApi";
import { AsyncBody, Section } from "../components/ui";

export function PolicyChanges() {
  const [entityType, setEntityType] = useState("");
  const query = entityType ? `entity_type=${encodeURIComponent(entityType)}` : "";
  const { items, cursor, loading, error, loadMore } = usePaged<Row>("/policy-changes", query);

  return (
    <Section
      title="Policy changes"
      actions={
        <select value={entityType} onChange={(e) => setEntityType(e.target.value)}>
          <option value="">all entities</option>
          <option value="user">user</option>
          <option value="role">role</option>
          <option value="resource">resource</option>
          <option value="policy">policy</option>
          <option value="totp_reset">totp_reset</option>
        </select>
      }
    >
      <AsyncBody loading={loading && items.length === 0} error={error} empty={items.length === 0}>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Entity</th>
              <th>Action</th>
              <th>Change</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td>{new Date(r.ts).toLocaleString()}</td>
                <td>{r.actor_email}</td>
                <td>{r.entity_type}</td>
                <td>{r.action}</td>
                <td className="mono">{JSON.stringify(r.change_json)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {cursor != null && (
          <button onClick={loadMore} disabled={loading}>
            {loading ? "Loading..." : "Load more"}
          </button>
        )}
      </AsyncBody>
    </Section>
  );
}
