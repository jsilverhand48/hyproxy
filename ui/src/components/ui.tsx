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
