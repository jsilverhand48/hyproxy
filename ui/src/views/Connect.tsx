// Full-screen Guacamole session view (/connect/:resourceId). Mints a
// single-use tunnel token at the auth host, then opens the WebSocket tunnel
// on the portal host's fixed path (wss://<portal_host>/guac/tunnel?token=...).
// Tokens are single-use with a short TTL, so every (re)connect mints a fresh
// one.

import { useEffect, useRef, useState } from "react";
import Guacamole from "guacamole-common-js";
import { config } from "../lib/config";
import type { MyResource } from "../lib/types";
import { useResource } from "../lib/useApi";
import { GuacError, mintGuacToken } from "../lib/guac";

type SessionState = "connecting" | "connected" | "closed" | "error";

const STATE_CONNECTED = 3;
const STATE_DISCONNECTED = 5;

export function Connect({ resourceId }: { resourceId: string }) {
  const { data, error, loading } = useResource<MyResource[]>("/portal/me/resources");
  const resource = (data ?? []).find((r) => r.id === resourceId) ?? null;

  const containerRef = useRef<HTMLDivElement | null>(null);
  const [session, setSession] = useState<SessionState>("connecting");
  const [message, setMessage] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  // The tunnel rides the portal host; fall back to the current host for dev
  // builds without VITE_PORTAL_HOST (the connect view already lives there).
  const tunnelHost = config.portalHost || window.location.host;

  useEffect(() => {
    const container = containerRef.current;
    if (!resource || !container) return;

    let disposed = false;
    let client: Guacamole.Client | null = null;
    let keyboard: Guacamole.Keyboard | null = null;
    let onWindowResize: (() => void) | null = null;
    let onWindowBlur: (() => void) | null = null;

    const fail = (msg: string) => {
      if (disposed) return;
      setSession("error");
      setMessage(msg);
    };

    void (async () => {
      setSession("connecting");
      setMessage(null);

      let minted;
      try {
        minted = await mintGuacToken(resourceId);
      } catch (e: unknown) {
        fail(e instanceof GuacError ? e.message : `Token request failed: ${String(e)}`);
        return;
      }
      if (disposed) return;

      const tunnel = new Guacamole.WebSocketTunnel(`wss://${tunnelHost}/guac/tunnel`);
      client = new Guacamole.Client(tunnel);
      const display = client.getDisplay();
      container.replaceChildren(display.getElement());

      client.onstatechange = (state: number) => {
        if (disposed) return;
        if (state === STATE_CONNECTED) setSession("connected");
        if (state === STATE_DISCONNECTED) setSession((s) => (s === "error" ? s : "closed"));
      };
      client.onerror = (status) => fail(status.message || "Connection error");
      tunnel.onerror = (status) => fail(status.message || "Tunnel error");

      // Letterbox-fit the remote display into the container.
      const fit = () => {
        const w = display.getWidth();
        const h = display.getHeight();
        if (w > 0 && h > 0) {
          display.scale(Math.min(container.clientWidth / w, container.clientHeight / h, 1));
        }
      };
      display.onresize = fit;
      onWindowResize = () => {
        client?.sendSize(container.clientWidth, container.clientHeight);
        fit();
      };
      window.addEventListener("resize", onWindowResize);

      const mouse = new Guacamole.Mouse(display.getElement());
      mouse.onEach(["mousedown", "mouseup", "mousemove"], (e) => {
        // second arg maps element coords through the current display scale
        client?.sendMouseState((e as Guacamole.Mouse.Event).state, true);
      });

      keyboard = new Guacamole.Keyboard(document);
      keyboard.onkeydown = (keysym: number) => client?.sendKeyEvent(1, keysym);
      keyboard.onkeyup = (keysym: number) => client?.sendKeyEvent(0, keysym);
      // Releases held modifiers when the tab loses focus (alt-tab, etc.).
      onWindowBlur = () => keyboard?.reset();
      window.addEventListener("blur", onWindowBlur);

      const w = container.clientWidth || window.innerWidth;
      const h = container.clientHeight || window.innerHeight;
      const dpi = Math.round(96 * window.devicePixelRatio);
      client.connect(`token=${encodeURIComponent(minted.token)}&width=${w}&height=${h}&dpi=${dpi}`);
    })();

    return () => {
      disposed = true;
      if (keyboard) {
        keyboard.onkeydown = null;
        keyboard.onkeyup = null;
      }
      if (onWindowResize) window.removeEventListener("resize", onWindowResize);
      if (onWindowBlur) window.removeEventListener("blur", onWindowBlur);
      client?.disconnect();
      container.replaceChildren();
    };
  }, [resource, tunnelHost, resourceId, attempt]);

  if (loading) return <p className="center">Loading resource...</p>;
  if (error) return <p className="center error">Failed to load resources: {error}</p>;
  if (!resource) return <p className="center error">Unknown or unauthorized resource.</p>;

  return (
    <div className="connect-view">
      <div className="connect-bar">
        <span>
          {resource.name} ({resource.protocol})
        </span>
        <span className={session === "error" ? "error" : "muted"}>
          {session === "connecting" && "Connecting..."}
          {session === "connected" && "Connected"}
          {session === "closed" && "Disconnected"}
          {session === "error" && (message ?? "Error")}
        </span>
        {(session === "closed" || session === "error") && (
          <button className="link" onClick={() => setAttempt((a) => a + 1)}>
            Reconnect
          </button>
        )}
        <a className="link" href="/">
          Back
        </a>
      </div>
      <div className="connect-display" ref={containerRef} />
    </div>
  );
}
