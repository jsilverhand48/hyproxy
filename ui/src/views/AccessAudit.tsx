import { useState } from "react";
import type { AccessAudit as Row } from "../lib/types";
import { usePaged } from "../lib/useApi";
import { AsyncBody, Section } from "../components/ui";

export function AccessAudit() {
  const [decision, setDecision] = useState("");
  const query = decision ? `decision=${encodeURIComponent(decision)}` : "";
  const { items, cursor, loading, error, loadMore } = usePaged<Row>("/audit/access", query);

  return (
    <Section
      title="Access audit"
      actions={
        <select value={decision} onChange={(e) => setDecision(e.target.value)}>
          <option value="">all decisions</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      }
    >
      <AsyncBody loading={loading && items.length === 0} error={error} empty={items.length === 0}>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Decision</th>
              <th>Reason</th>
              <th>Port</th>
              <th>Source IP</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td>{new Date(r.ts).toLocaleString()}</td>
                <td className={r.decision === "deny" ? "danger" : ""}>{r.decision}</td>
                <td>{r.reason}</td>
                <td>{r.port}</td>
                <td>{r.source_ip}</td>
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
