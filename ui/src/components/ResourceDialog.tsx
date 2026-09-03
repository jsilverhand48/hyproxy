// Add/edit resource modal. The type dropdown drives which fields are shown:
// - http/https: public host (route) + backend host/ports
// - tcp: backend host/ports only (no route is emitted for tcp)
// - vnc/rdp/ssh: the guacd target (hostname/port), username/password and extra
//   guacd params; no public host, sessions ride the portal host's fixed
//   /guac/tunnel path.
// - rtsp: the camera target (hostname/port) and its stream path; no public
//   host, streams ride the portal host's fixed /rtsp/stream path. Deliberately
//   NO credential fields: RTSP credentials are prompted per viewing session and
//   are never stored, so there is nothing here to seal.
// Create sends one POST (resource + connection); edit PATCHes the resource then
// PUTs the connection.
// Secrets are sealed server-side and never read back: leaving the password
// blank keeps the existing value, "clear" sends an empty dict.

import { useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { Resource, ResourceConnection } from "../lib/types";
import { runMutation } from "../lib/useApi";
import { Banner } from "./ui";
import { Modal } from "./ConfirmDialog";

const PROTOCOLS = ["http", "https", "tcp", "vnc", "rdp", "ssh", "rtsp"];
const GUAC_PROTOCOLS = new Set(["vnc", "rdp", "ssh"]);
// Protocols that carry a ResourceConnection and are reached through a fixed
// path on the portal host instead of their own public hostname.
const TUNNEL_PROTOCOLS = new Set([...GUAC_PROTOCOLS, "rtsp"]);
const DEFAULT_TUNNEL_PORT: Record<string, string> = {
  vnc: "5900",
  rdp: "3389",
  ssh: "22",
  rtsp: "554",
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
  const isRtsp = protocol === "rtsp";
  const isTunnel = TUNNEL_PROTOCOLS.has(protocol);

  // Connection fields (vnc/rdp/ssh/rtsp only). For guac the username lives in
  // guacd params and gets its own input, merged over the extra-params text; for
  // rtsp the stream path lives in params the same way.
  const [existingConn, setExistingConn] = useState<ResourceConnection | null>(null);
  const [loadingConn, setLoadingConn] = useState(editing && TUNNEL_PROTOCOLS.has(protocol));
  const [hostname, setHostname] = useState(editing && isTunnel ? "" : resource?.host ?? "");
  const [connPort, setConnPort] = useState(DEFAULT_TUNNEL_PORT[protocol] ?? "");
  const [username, setUsername] = useState("");
  const [streamPath, setStreamPath] = useState("");
  const [transcodeAudio, setTranscodeAudio] = useState(false);
  const [paramsText, setParamsText] = useState("");
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);

  useEffect(() => {
    if (!editing || !TUNNEL_PROTOCOLS.has(resource.protocol)) return;
    let live = true;
    api
      .get<ResourceConnection>(`/resources/${resource.id}/connection`)
      .then((conn) => {
        if (!live) return;
        setExistingConn(conn);
        setHostname(conn.hostname);
        setConnPort(String(conn.port));
        const { username: user, path, audio, ...rest } = conn.params;
        setUsername(user ?? "");
        setStreamPath(path ?? "");
        setTranscodeAudio(audio === "aac");
        setParamsText(paramsToText(rest));
      })
      .catch((e: unknown) => {
        if (!live) return;
        // 404 = no connection yet; start from the resource's host/port.
        if (e instanceof ApiError && e.status === 404) {
          setHostname(resource.host);
          setConnPort(String(resource.ports[0] ?? DEFAULT_TUNNEL_PORT[resource.protocol] ?? ""));
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
    // Prefill the port unless the admin already typed a non-default one.
    if (TUNNEL_PROTOCOLS.has(next) && (!connPort || connPort === DEFAULT_TUNNEL_PORT[protocol])) {
      setConnPort(DEFAULT_TUNNEL_PORT[next]);
    }
    setProtocol(next);
  }

  function connParams(): Record<string, string> {
    const params = textToParams(paramsText);
    if (isRtsp) {
      // The stream path varies by vendor (/Streaming/Channels/101 on Hikvision,
      // /cam/realmonitor?channel=1&subtype=0 on Dahua), so it is configured
      // rather than guessed.
      if (streamPath.trim()) params.path = streamPath.trim();
      else delete params.path;
      // Camera audio is usually G.711, which browsers cannot play, so it is
      // dropped unless the admin asks for an AAC transcode.
      if (transcodeAudio) params.audio = "aac";
      else delete params.audio;
      return params;
    }
    if (username.trim()) params.username = username.trim();
    else delete params.username;
    return params;
  }

  async function save() {
    const desc = description.trim() || null;
    if (!editing) {
      const body: Record<string, unknown> = { name: name.trim(), protocol, description: desc };
      if (isTunnel) {
        const connection: Record<string, unknown> = {
          hostname: hostname.trim(),
          port: Number(connPort),
          params: connParams(),
        };
        // rtsp never sends secret_params: the server rejects stored credentials
        // for it, because viewers authenticate to the camera per session.
        if (secret && !isRtsp) connection.secret_params = { password: secret };
        // host/ports mirror the connection target server-side; send them anyway
        // to satisfy the schema.
        Object.assign(body, { host: hostname.trim(), ports: [Number(connPort)], connection });
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
    if (!isTunnel) {
      patch.host = host.trim();
      patch.ports = parsePorts(ports);
      if (protocol !== "tcp") patch.public_host = publicHost.trim() || null;
    }
    const patchErr = await runMutation(() => api.patch<Resource>(`/resources/${resource.id}`, patch));
    if (patchErr !== null) {
      setMsg(patchErr);
      return;
    }
    if (isTunnel) {
      const body: Record<string, unknown> = {
        protocol,
        hostname: hostname.trim(),
        port: Number(connPort),
        params: connParams(),
      };
      // Absent -> keep existing secret; {} -> clear; value -> reseal.
      if (!isRtsp) {
        if (clearSecret) body.secret_params = {};
        else if (secret) body.secret_params = { password: secret };
      }
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
          {isTunnel ? (
            <>
              <input
                placeholder={isRtsp ? "camera hostname or IP" : "hostname (reachable from guacd)"}
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                required
              />
              <input
                placeholder="port"
                inputMode="numeric"
                value={connPort}
                onChange={(e) => setConnPort(e.target.value)}
                required
              />
              {isRtsp ? (
                <>
                  <input
                    placeholder="stream path (e.g. /Streaming/Channels/101)"
                    value={streamPath}
                    onChange={(e) => setStreamPath(e.target.value)}
                    required
                  />
                  <label className="muted">
                    <input
                      type="checkbox"
                      checked={transcodeAudio}
                      onChange={(e) => setTranscodeAudio(e.target.checked)}
                    />{" "}
                    include audio (transcoded to AAC)
                  </label>
                  <p className="muted">
                    Viewers are prompted for the camera username and password each session;
                    they are never stored here.
                  </p>
                  <textarea
                    placeholder={"extra params, one per line (key=value)"}
                    rows={3}
                    value={paramsText}
                    onChange={(e) => setParamsText(e.target.value)}
                  />
                </>
              ) : (
                <>
                  <input
                    placeholder="username (optional)"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="off"
                  />
                  <input
                    type="password"
                    placeholder={
                      existingConn?.has_secret
                        ? "password (set; blank keeps current)"
                        : "password (optional)"
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
              )}
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
