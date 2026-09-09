import { useState } from "react";
import type { AuthEvent as Row } from "../lib/types";
import { usePaged } from "../lib/useApi";
import { AsyncBody, LoadMore, Section, TableWrap } from "../components/ui";

export function AuthEvents() {
  const [eventType, setEventType] = useState("");
  const query = eventType ? `event_type=${encodeURIComponent(eventType)}` : "";
  const { items, cursor, loading, error, loadMore } = usePaged<Row>("/audit/auth", query);

  return (
    <Section
      title="Auth events"
      actions={
        <input
          placeholder="filter event_type"
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
        />
      }
    >
      <AsyncBody loading={loading && items.length === 0} error={error} empty={items.length === 0}>
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>OK</th>
                <th>Source IP</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td data-label="Time">{new Date(r.ts).toLocaleString()}</td>
                  <td data-label="Event">{r.event_type}</td>
                  <td data-label="OK" className={r.success ? "" : "danger"}>
                    {r.success ? "yes" : "no"}
                  </td>
                  <td data-label="Source IP">{r.source_ip}</td>
                  <td data-label="Detail" className="mono">
                    {JSON.stringify(r.detail)}
                  </td>
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
