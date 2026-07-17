// Per-resource Guacamole connection editor (vnc/rdp/ssh): hostname/port,
// non-secret guacd params, and write-only secret params. Secrets are sealed
// server-side and never read back: leaving the secret field blank keeps the
// existing value (PUT omits secret_params), "clear" sends an empty dict.

import { useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { Resource, ResourceConnection } from "../lib/types";
import { runMutation } from "../lib/useApi";
import { Banner } from "./ui";
import { Modal } from "./ConfirmDialog";

const SECRET_KEY_BY_PROTOCOL: Record<string, string> = {
  vnc: "password",
  rdp: "password",
  ssh: "password",
};

function paramsToText(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
}

function textToParams(text: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq > 0) params[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return params;
}

export function ConnectionDialog({ resource, onClose }: { resource: Resource; onClose: () => void }) {
  const [existing, setExisting] = useState<ResourceConnection | null>(null);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);
  const [hostname, setHostname] = useState("");
  const [port, setPort] = useState("");
  const [paramsText, setParamsText] = useState("");
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .get<ResourceConnection>(`/resources/${resource.id}/connection`)
      .then((conn) => {
        if (!live) return;
        setExisting(conn);
        setHostname(conn.hostname);
        setPort(String(conn.port));
        setParamsText(paramsToText(conn.params));
      })
      .catch((e: unknown) => {
        if (!live) return;
        // 404 = no connection yet; start from an empty form.
        if (!(e instanceof ApiError && e.status === 404)) {
          setMsg(e instanceof Error ? e.message : String(e));
        }
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [resource.id]);

  const secretKey = SECRET_KEY_BY_PROTOCOL[resource.protocol] ?? "password";

  async function save() {
    const body: Record<string, unknown> = {
      protocol: resource.protocol,
      hostname: hostname.trim(),
      port: Number(port),
      params: textToParams(paramsText),
    };
    // Absent -> keep existing secret; {} -> clear; value -> reseal.
    if (clearSecret) body.secret_params = {};
    else if (secret) body.secret_params = { [secretKey]: secret };
    const err = await runMutation(() =>
      api.put<ResourceConnection>(`/resources/${resource.id}/connection`, body),
    );
    setMsg(err);
    if (err === null) onClose();
  }

  async function remove() {
    const err = await runMutation(() => api.del(`/resources/${resource.id}/connection`));
    setMsg(err);
    if (err === null) onClose();
  }

  return (
    <Modal title={`Connection: ${resource.name} (${resource.protocol})`} onClose={onClose}>
      <Banner kind="info" message={msg} />
      {loading ? (
        <p className="muted">Loading...</p>
      ) : (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <input
            placeholder="hostname (reachable from guacd)"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            required
          />
          <input
            placeholder="port"
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            required
          />
          <textarea
            placeholder={"guacd params, one per line (key=value)\ne.g. username=user or ignore-cert=true"}
            rows={4}
            value={paramsText}
            onChange={(e) => setParamsText(e.target.value)}
          />
          <input
            type="password"
            placeholder={
              existing?.has_secret
                ? `${secretKey} (set; blank keeps current)`
                : `${secretKey} (optional)`
            }
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            disabled={clearSecret}
            autoComplete="new-password"
          />
          {existing?.has_secret && (
            <label className="muted">
              <input
                type="checkbox"
                checked={clearSecret}
                onChange={(e) => setClearSecret(e.target.checked)}
              />{" "}
              clear stored secret ({existing.secret_keys.join(", ")})
            </label>
          )}
          <div className="modal-actions">
            {existing !== null && (
              <button type="button" className="danger" onClick={() => void remove()}>
                Delete
              </button>
            )}
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button type="submit">Save</button>
          </div>
        </form>
      )}
    </Modal>
  );
}
