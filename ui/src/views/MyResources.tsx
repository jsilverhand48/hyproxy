import type { MyResource } from "../lib/types";
import { useResource } from "../lib/useApi";
import { AsyncBody, Section } from "../components/ui";

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
                  {r.public_host ? (
                    <a href={`https://${r.public_host}`} target="_blank" rel="noreferrer">
                      {r.public_host}
                    </a>
                  ) : (
                    <span className="muted">(not routed)</span>
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
