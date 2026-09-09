import type { ReactNode } from "react";

export function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <header className="section-head">
        <h2>{title}</h2>
        <div>{actions}</div>
      </header>
      {children}
    </section>
  );
}

export function Banner({ kind, message }: { kind: "error" | "info"; message: string | null }) {
  if (!message) return null;
  return <p className={kind === "error" ? "error banner" : "info banner"}>{message}</p>;
}

export function AsyncBody({
  loading,
  error,
  empty,
  children,
}: {
  loading: boolean;
  error: string | null;
  empty: boolean;
  children: ReactNode;
}) {
  if (loading) return <p>Loading...</p>;
  if (error) return <p className="error">{error}</p>;
  if (empty) return <p className="muted">Nothing to show.</p>;
  return <>{children}</>;
}

// Wraps one table so IT owns horizontal scroll instead of the whole .content
// column (which made headings and toolbars scroll away with a wide table), and
// so styles.css can restyle the table into stacked cards on phones. Every <td>
// inside needs a data-label matching its <th>; see the card block in styles.css.
export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="table-wrap">{children}</div>;
}

// Keyset pagination control for the audit viewers. usePaged returns cursor ===
// null when there is no further page. Kept here so its mobile sizing and
// disabled state cannot drift between the three views that use it.
export function LoadMore({
  cursor,
  loading,
  onClick,
}: {
  cursor: number | null;
  loading: boolean;
  onClick: () => void;
}) {
  if (cursor == null) return null;
  return (
    <div className="row">
      <button onClick={onClick} disabled={loading}>
        {loading ? "Loading..." : "Load more"}
      </button>
    </div>
  );
}
