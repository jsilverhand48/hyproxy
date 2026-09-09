// Add/edit resource modal. The type dropdown drives which fields are shown:
// - http/https: public host (route) + backend host/ports, and optionally the
//   password-only public mode (see below)
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
//
// Public mode (http/https only) makes the resource reachable by anyone on the
// internet who has its password, with no sign-in and no policy. The admin never
// types that password: it is generated server-side and returned exactly once,
// on create or on rotate, so it is rendered here immediately and cannot be
// fetched again. Only the path globs listed exist; everything else 404s.

import { useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import type {
  PublicPassword,
  Resource,
  ResourceConnection,
  ResourceCreated,
} from "../lib/types";
import { runMutation } from "../lib/useApi";
import { Banner } from "./ui";
import { ConfirmDialog, Modal } from "./ConfirmDialog";

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

// One glob per line. `*` matches within a path segment, `**` across segments;
// the server rejects a bare /* or /** since that would expose the whole host.
function pathsToText(paths: string[] | null): string {
  return (paths ?? []).join("\n");
}

function textToPaths(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
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
  const [publicAccess, setPublicAccess] = useState(resource?.public_access ?? false);
  const [publicPaths, setPublicPaths] = useState(pathsToText(resource?.public_paths ?? null));
  // Shown once, right after the server generates it. Never re-fetchable.
  const [issuedPassword, setIssuedPassword] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const isRtsp = protocol === "rtsp";
  const isHttp = protocol === "http" || protocol === "https";
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

  // Rotating is also the revoke button: the server kills every live session on
  // the link, so anyone holding the old password is locked out immediately.
  async function rotatePassword() {
    if (!editing) return;
    const err = await runMutation(async () => {
      const out = await api.post<PublicPassword>(
        `/resources/${resource.id}/public-password`,
        {},
      );
      setIssuedPassword(out.password);
      return out;
    });
    setMsg(err);
    if (err === null) onSaved();
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
        if (isHttp && publicAccess) {
          body.public_access = true;
          body.public_paths = textToPaths(publicPaths);
        }
      }
      // runMutation only surfaces the error, so the response is captured in the
      // closure (same shape as rotatePassword below).
      const issued = { password: null as string | null };
      const err = await runMutation(async () => {
        const created = await api.post<ResourceCreated>("/resources", body);
        issued.password = created.public_password;
        return created;
      });
      setMsg(err);
      if (err === null) {
        onSaved();
        // Keep the modal open when there is a generated password to show: it is
        // returned once and closing would lose it for good.
        if (issued.password) setIssuedPassword(issued.password);
        else onClose();
      }
      return;
    }

    const patch: Record<string, unknown> = { name: name.trim(), description: desc };
    if (!isTunnel) {
      patch.host = host.trim();
      patch.ports = parsePorts(ports);
      if (protocol !== "tcp") patch.public_host = publicHost.trim() || null;
      if (isHttp) {
        patch.public_access = publicAccess;
        // Editing the exposed paths revokes every live session server-side.
        if (publicAccess) patch.public_paths = textToPaths(publicPaths);
      }
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
    // A resource just turned public has no password yet; say so rather than
    // silently leaving a link nobody can open.
    if (isHttp && publicAccess && !resource.public_password_set && !issuedPassword) {
      setMsg("Public access is on, but no password exists yet. Generate one below.");
      return;
    }
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
              {isHttp && (
                <>
                  <label className="muted">
                    <input
                      type="checkbox"
                      checked={publicAccess}
                      onChange={(e) => setPublicAccess(e.target.checked)}
                    />{" "}
                    public &mdash; password only, no sign-in
                  </label>
                  {publicAccess && (
                    <>
                      <textarea
                        placeholder={
                          "public paths, one per line\ne.g. /my/uri/path/*\n" +
                          "* matches one segment, ** matches any depth"
                        }
                        rows={3}
                        value={publicPaths}
                        onChange={(e) => setPublicPaths(e.target.value)}
                        required
                      />
                      <p className="muted">
                        Anyone with the password reaches these paths. Everything else on{" "}
                        {publicHost.trim() || "this host"} returns 404.
                      </p>
                      {editing && (
                        <button type="button" onClick={() => setConfirmRotate(true)}>
                          {resource.public_password_set
                            ? "Regenerate password"
                            : "Generate password"}
                        </button>
                      )}
                    </>
                  )}
                </>
              )}
            </>
          )}
          <input
            placeholder="description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          {issuedPassword && (
            <div className="stack" style={{ border: "1px solid", padding: "0.75rem" }}>
              <strong>Share password (shown once)</strong>
              <code style={{ fontSize: "1.15rem", userSelect: "all" }}>{issuedPassword}</code>
              {publicHost.trim() && textToPaths(publicPaths).length > 0 && (
                <code style={{ userSelect: "all", overflowWrap: "anywhere" }}>
                  {`https://${publicHost.trim()}${
                    textToPaths(publicPaths)[0].split("*")[0] || "/"
                  }`}
                </code>
              )}
              <p className="muted">
                Copy this now. It is not stored in readable form and cannot be shown again;
                the only way to recover access is to generate a new one.
              </p>
            </div>
          )}
          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              {issuedPassword ? "Done" : "Cancel"}
            </button>
            <button type="submit">{editing ? "Save" : "Add"}</button>
          </div>
        </form>
      )}
      {confirmRotate && (
        <ConfirmDialog
          title="Generate a new password?"
          message={
            "Everyone currently using this link is signed out immediately, and the old " +
            "password stops working. The new one is shown once."
          }
          confirmLabel="Generate"
          onConfirm={() => {
            setConfirmRotate(false);
            void rotatePassword();
          }}
          onCancel={() => setConfirmRotate(false)}
        />
      )}
    </Modal>
  );
}
