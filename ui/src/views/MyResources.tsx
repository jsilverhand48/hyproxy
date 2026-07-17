import { config } from "../lib/config";
import type { MyResource } from "../lib/types";
import { useResource } from "../lib/useApi";
import { AsyncBody, Section } from "../components/ui";

const GUAC_PROTOCOLS = new Set(["vnc", "rdp", "ssh"]);

export function MyResources() {
  const { data, error, loading } = useResource<MyResource[]>("/portal/me/resources");

  return (
    <Section title="My resources">
      <AsyncBody loading={loading} error={error} empty={(data ?? []).length === 0}>
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
                <td>{r.name}</td>
                <td>{r.protocol}</td>
                <td>
                  {GUAC_PROTOCOLS.has(r.protocol) ? (
                    // Guac resources have no public host; the connect view and
                    // its WS tunnel live on the portal host, so link there
                    // absolutely (admins may be browsing on the admin host).
                    <a
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
                  ) : !r.public_host ? (
                    <span className="muted">(not routed)</span>
                  ) : (
                    <a href={`https://${r.public_host}`} target="_blank" rel="noreferrer">
                      {r.public_host}
                    </a>
                  )}
                </td>
                <td>{r.description ?? <span className="muted">-</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBody>
    </Section>
  );
}
