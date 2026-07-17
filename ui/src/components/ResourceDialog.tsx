// Add/edit resource modal. The type dropdown drives which fields are shown:
// - http/https: public host (route) + backend host/ports
// - tcp: backend host/ports only (no route is emitted for tcp)
// - vnc/rdp/ssh: the guacd target (hostname/port), username/password and extra
//   guacd params; no public host, sessions ride the portal host's fixed
//   /guac/tunnel path. Create sends one POST (resource + connection); edit
//   PATCHes the resource then PUTs the connection.
// Secrets are sealed server-side and never read back: leaving the password
// blank keeps the existing value, "clear" sends an empty dict.

import { useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { Resource, ResourceConnection } from "../lib/types";
import { runMutation } from "../lib/useApi";
import { Banner } from "./ui";
import { Modal } from "./ConfirmDialog";

const PROTOCOLS = ["http", "https", "tcp", "vnc", "rdp", "ssh"];
const GUAC_PROTOCOLS = new Set(["vnc", "rdp", "ssh"]);
const DEFAULT_GUAC_PORT: Record<string, string> = { vnc: "5900", rdp: "3389", ssh: "22" };

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

function parsePorts(text: string): number[] {
  return text
    .split(",")
    .map((p) => Number(p.trim()))
    .filter((p) => Number.isInteger(p) && p > 0);
}

export function ResourceDialog({
  resource,
  onClose,
  onSaved,
}: {
  resource: Resource | null; // null = create
  onClose: () => void;
  onSaved: () => void;
}) {
  const editing = resource !== null;
  const [msg, setMsg] = useState<string | null>(null);
  const [protocol, setProtocol] = useState(resource?.protocol ?? "https");
  const [name, setName] = useState(resource?.name ?? "");
  const [publicHost, setPublicHost] = useState(resource?.public_host ?? "");
  const [host, setHost] = useState(resource?.host ?? "");
  const [ports, setPorts] = useState(resource?.ports.join(", ") ?? "");
  const [description, setDescription] = useState(resource?.description ?? "");
  const isGuac = GUAC_PROTOCOLS.has(protocol);

  // Guac connection fields (vnc/rdp/ssh only). The username lives in guacd
  // params; it gets its own input and is merged over the extra-params text.
  const [existingConn, setExistingConn] = useState<ResourceConnection | null>(null);
  const [loadingConn, setLoadingConn] = useState(editing && GUAC_PROTOCOLS.has(protocol));
  const [hostname, setHostname] = useState(editing && isGuac ? "" : resource?.host ?? "");
  const [guacPort, setGuacPort] = useState(DEFAULT_GUAC_PORT[protocol] ?? "");
  const [username, setUsername] = useState("");
  const [paramsText, setParamsText] = useState("");
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);

  useEffect(() => {
    if (!editing || !GUAC_PROTOCOLS.has(resource.protocol)) return;
    let live = true;
    api
      .get<ResourceConnection>(`/resources/${resource.id}/connection`)
      .then((conn) => {
        if (!live) return;
        setExistingConn(conn);
        setHostname(conn.hostname);
        setGuacPort(String(conn.port));
        const { username: user, ...rest } = conn.params;
        setUsername(user ?? "");
        setParamsText(paramsToText(rest));
      })
      .catch((e: unknown) => {
        if (!live) return;
        // 404 = no connection yet; start from the resource's host/port.
        if (e instanceof ApiError && e.status === 404) {
          setHostname(resource.host);
          setGuacPort(String(resource.ports[0] ?? DEFAULT_GUAC_PORT[resource.protocol] ?? ""));
        } else {
          setMsg(e instanceof Error ? e.message : String(e));
        }
      })
      .finally(() => {
        if (live) setLoadingConn(false);
      });
    return () => {
      live = false;
    };
  }, [editing, resource]);

  function changeProtocol(next: string) {
    // Prefill the guac port unless the admin already typed a non-default one.
    if (GUAC_PROTOCOLS.has(next) && (!guacPort || guacPort === DEFAULT_GUAC_PORT[protocol])) {
      setGuacPort(DEFAULT_GUAC_PORT[next]);
    }
    setProtocol(next);
  }

  function guacParams(): Record<string, string> {
    const params = textToParams(paramsText);
    if (username.trim()) params.username = username.trim();
    else delete params.username;
    return params;
  }

  async function save() {
    const desc = description.trim() || null;
    if (!editing) {
      const body: Record<string, unknown> = { name: name.trim(), protocol, description: desc };
      if (isGuac) {
        const connection: Record<string, unknown> = {
          hostname: hostname.trim(),
          port: Number(guacPort),
          params: guacParams(),
        };
        if (secret) connection.secret_params = { password: secret };
        // host/ports mirror the guacd target server-side; send them anyway to
        // satisfy the schema.
        Object.assign(body, { host: hostname.trim(), ports: [Number(guacPort)], connection });
      } else {
        body.host = host.trim();
        body.ports = parsePorts(ports);
        body.public_host = protocol === "tcp" ? null : publicHost.trim() || null;
      }
      const err = await runMutation(() => api.post<Resource>("/resources", body));
      setMsg(err);
      if (err === null) {
        onSaved();
        onClose();
      }
      return;
    }

    const patch: Record<string, unknown> = { name: name.trim(), description: desc };
    if (!isGuac) {
      patch.host = host.trim();
      patch.ports = parsePorts(ports);
      if (protocol !== "tcp") patch.public_host = publicHost.trim() || null;
    }
    const patchErr = await runMutation(() => api.patch<Resource>(`/resources/${resource.id}`, patch));
    if (patchErr !== null) {
      setMsg(patchErr);
      return;
    }
    if (isGuac) {
      const body: Record<string, unknown> = {
        protocol,
        hostname: hostname.trim(),
        port: Number(guacPort),
        params: guacParams(),
      };
      // Absent -> keep existing secret; {} -> clear; value -> reseal.
      if (clearSecret) body.secret_params = {};
      else if (secret) body.secret_params = { password: secret };
      const connErr = await runMutation(() =>
        api.put<ResourceConnection>(`/resources/${resource.id}/connection`, body),
      );
      if (connErr !== null) {
        setMsg(connErr);
        return;
      }
    }
    onSaved();
    onClose();
  }

  return (
    <Modal title={editing ? `Edit resource: ${resource.name}` : "Add resource"} onClose={onClose}>
      <Banner kind="info" message={msg} />
      {loadingConn ? (
        <p className="muted">Loading...</p>
      ) : (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <select
            value={protocol}
            onChange={(e) => changeProtocol(e.target.value)}
            disabled={editing}
            aria-label="type"
          >
            {PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <input
            placeholder="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          {isGuac ? (
            <>
              <input
                placeholder="hostname (reachable from guacd)"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                required
              />
              <input
                placeholder="port"
                inputMode="numeric"
                value={guacPort}
                onChange={(e) => setGuacPort(e.target.value)}
                required
              />
              <input
                placeholder="username (optional)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
              <input
                type="password"
                placeholder={
                  existingConn?.has_secret ? "password (set; blank keeps current)" : "password (optional)"
                }
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                disabled={clearSecret}
                autoComplete="new-password"
              />
              {existingConn?.has_secret && (
                <label className="muted">
                  <input
                    type="checkbox"
                    checked={clearSecret}
                    onChange={(e) => setClearSecret(e.target.checked)}
                  />{" "}
                  clear stored secret ({existingConn.secret_keys.join(", ")})
                </label>
              )}
              <textarea
                placeholder={"extra guacd params, one per line (key=value)\ne.g. ignore-cert=true"}
                rows={3}
                value={paramsText}
                onChange={(e) => setParamsText(e.target.value)}
              />
            </>
          ) : (
            <>
              {protocol !== "tcp" && (
                <input
                  placeholder="public host (route)"
                  value={publicHost}
                  onChange={(e) => setPublicHost(e.target.value)}
                />
              )}
              <input
                placeholder="backend host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                required
              />
              <input
                placeholder="ports (comma sep)"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                required
              />
            </>
          )}
          <input
            placeholder="description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button type="submit">{editing ? "Save" : "Add"}</button>
          </div>
        </form>
      )}
    </Modal>
  );
}
