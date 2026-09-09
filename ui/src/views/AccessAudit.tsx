import { useState } from "react";
import type { AccessAudit as Row } from "../lib/types";
import { usePaged } from "../lib/useApi";
import { AsyncBody, LoadMore, Section, TableWrap } from "../components/ui";

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
        <TableWrap>
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
                  <td data-label="Time">{new Date(r.ts).toLocaleString()}</td>
                  <td data-label="Decision" className={r.decision === "deny" ? "danger" : ""}>
                    {r.decision}
                  </td>
                  <td data-label="Reason">{r.reason}</td>
                  <td data-label="Port">{r.port}</td>
                  <td data-label="Source IP">{r.source_ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
        <LoadMore cursor={cursor} loading={loading} onClick={loadMore} />
      </AsyncBody>
    </Section>
  );
}
