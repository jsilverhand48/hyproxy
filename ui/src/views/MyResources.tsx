import { config } from "../lib/config";
import type { MyResource } from "../lib/types";
import { useResource } from "../lib/useApi";
import { AsyncBody, Section, TableWrap } from "../components/ui";

const GUAC_PROTOCOLS = new Set(["vnc", "rdp", "ssh"]);

export function MyResources() {
  const { data, error, loading } = useResource<MyResource[]>("/portal/me/resources");

  return (
    <Section title="My resources">
      <AsyncBody loading={loading} error={error} empty={(data ?? []).length === 0}>
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Protocol</th>
                <th>Address</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((r) => (
                <tr key={r.id}>
                  <td data-label="Name">{r.name}</td>
                  <td data-label="Protocol">{r.protocol}</td>
                  <td data-label="Address">
                    {GUAC_PROTOCOLS.has(r.protocol) ? (
                      // Guac resources have no public host; the connect view and
                      // its WS tunnel live on the portal host, so link there
                      // absolutely (admins may be browsing on the admin host).
                      // .action-link gets this a real tap target on touch: it is
                      // the portal's primary action, not incidental prose.
                      <a
                        className="action-link"
                        href={
                          config.portalHost
                            ? `https://${config.portalHost}/connect/${r.id}`
                            : `/connect/${r.id}`
                        }
                        target="_blank"
                        rel="noreferrer"
                      >
                        Connect
                      </a>
                    ) : r.protocol === "rtsp" ? (
                      // Same arrangement for cameras: the watch view and its
                      // stream WebSocket both live on the portal host.
                      <a
                        className="action-link"
                        href={
                          config.portalHost
                            ? `https://${config.portalHost}/watch/${r.id}`
                            : `/watch/${r.id}`
                        }
                        target="_blank"
                        rel="noreferrer"
                      >
                        Watch
                      </a>
                    ) : !r.public_host ? (
                      <span className="muted">(not routed)</span>
                    ) : (
                      <a href={`https://${r.public_host}`} target="_blank" rel="noreferrer">
                        {r.public_host}
                      </a>
                    )}
                  </td>
                  <td data-label="Description">
                    {r.description ?? <span className="muted">-</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </AsyncBody>
    </Section>
  );
}
