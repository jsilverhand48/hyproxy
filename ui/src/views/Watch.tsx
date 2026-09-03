// Full-screen RTSP camera view (/watch/:resourceId).
//
// Two-stage authentication: the hyproxy gateway session already got the viewer
// this far, and this view collects the camera's OWN username and password as a
// second factor against the backend. Those credentials live in this component's
// state and in the short-lived encrypted stream token, and nowhere else.
//
// The mint happens at the auth host, then the stream WebSocket opens on the
// portal host's fixed path (wss://<portal_host>/rtsp/stream?token=...). Tokens
// are single-use with a short TTL, so every (re)connect mints a fresh one.
//
// The bridge sends fragmented MP4 that the browser plays natively through a
// MediaSource; there is no player library and no plugin. Text frames are JSON
// control messages, binary frames are media.

import { useEffect, useRef, useState } from "react";
import { config } from "../lib/config";
import type { MyResource } from "../lib/types";
import { useResource } from "../lib/useApi";
import { RtspError, mintRtspToken, rtspMessage } from "../lib/rtsp";

type StreamState = "idle" | "connecting" | "playing" | "error";

interface Credentials {
  username: string;
  password: string;
}

// Keep roughly a minute of video buffered; trim the rest so an hours-long
// session does not grow without bound.
const BUFFER_KEEP_SECS = 30;
const BUFFER_TRIM_ABOVE_SECS = 60;

export function Watch({ resourceId }: { resourceId: string }) {
  const { data, error, loading } = useResource<MyResource[]>("/portal/me/resources");
  const resource = (data ?? []).find((r) => r.id === resourceId) ?? null;

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [state, setState] = useState<StreamState>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  // Held in memory for the life of this view so a dropped stream can reconnect
  // without prompting again. Never written to storage.
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const [attempt, setAttempt] = useState(0);

  // The stream rides the portal host; fall back to the current host for dev
  // builds without VITE_PORTAL_HOST (the watch view already lives there).
  const streamHost = config.portalHost || window.location.host;

  useEffect(() => {
    const video = videoRef.current;
    if (!resource || !video || !credentials) return;

    let disposed = false;
    let ws: WebSocket | null = null;
    let mediaSource: MediaSource | null = null;
    let sourceBuffer: SourceBuffer | null = null;
    let objectUrl: string | null = null;
    const queue: ArrayBuffer[] = [];

    const fail = (msg: string) => {
      if (disposed) return;
      setState("error");
      setMessage(msg);
    };

    // SourceBuffer.appendBuffer throws while an append is in flight, so every
    // segment goes through this queue and is drained on updateend.
    const drain = () => {
      if (disposed || !sourceBuffer || sourceBuffer.updating || queue.length === 0) return;
      const chunk = queue.shift();
      if (!chunk) return;
      try {
        sourceBuffer.appendBuffer(new Uint8Array(chunk));
      } catch {
        // QuotaExceeded on a wedged tab: drop what we are holding and let the
        // next keyframe fragment resync rather than tearing the stream down.
        queue.length = 0;
      }
    };

    const trim = () => {
      if (disposed || !sourceBuffer || sourceBuffer.updating) return;
      const buffered = sourceBuffer.buffered;
      if (buffered.length === 0) return;
      const start = buffered.start(0);
      const end = buffered.end(buffered.length - 1);
      if (end - start > BUFFER_TRIM_ABOVE_SECS) {
        try {
          sourceBuffer.remove(start, end - BUFFER_KEEP_SECS);
        } catch {
          // remove() races with an append that started first; retry next tick.
        }
      }
    };

    const startPlayback = (codec: string) => {
      const mime = `video/mp4; codecs="${codec}"`;
      if (!("MediaSource" in window) || !MediaSource.isTypeSupported(mime)) {
        fail("This browser cannot play the camera's video format.");
        return;
      }
      mediaSource = new MediaSource();
      objectUrl = URL.createObjectURL(mediaSource);
      video.src = objectUrl;
      mediaSource.addEventListener("sourceopen", () => {
        if (disposed || !mediaSource) return;
        try {
          sourceBuffer = mediaSource.addSourceBuffer(mime);
        } catch {
          fail("This browser cannot play the camera's video format.");
          return;
        }
        sourceBuffer.mode = "segments";
        sourceBuffer.addEventListener("updateend", () => {
          trim();
          drain();
        });
        setState("playing");
        setMessage(null);
        drain();
      });
    };

    void (async () => {
      setState("connecting");
      setMessage(null);

      let minted;
      try {
        minted = await mintRtspToken(resourceId, credentials.username, credentials.password);
      } catch (e: unknown) {
        fail(e instanceof RtspError ? e.message : `Token request failed: ${String(e)}`);
        return;
      }
      if (disposed) return;

      ws = new WebSocket(
        `wss://${streamHost}/rtsp/stream?token=${encodeURIComponent(minted.token)}`,
      );
      ws.binaryType = "arraybuffer";

      ws.onmessage = (event: MessageEvent<string | ArrayBuffer>) => {
        if (disposed) return;
        if (typeof event.data === "string") {
          let control: { type?: string; codec?: string; reason?: string };
          try {
            control = JSON.parse(event.data) as typeof control;
          } catch {
            return;
          }
          if (control.type === "ready" && control.codec) startPlayback(control.codec);
          else if (control.type === "error") fail(rtspMessage(control.reason ?? "rtsp_failed"));
          return;
        }
        queue.push(event.data);
        drain();
      };
      ws.onerror = () => fail("The stream connection failed.");
      ws.onclose = () => {
        if (disposed) return;
        // An error frame already explained itself; a bare close did not.
        setState((s) => (s === "error" ? s : "idle"));
        setMessage((m) => m ?? "Stream ended.");
      };
    })();

    return () => {
      disposed = true;
      if (ws) {
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
      }
      queue.length = 0;
      video.removeAttribute("src");
      video.load();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [resource, resourceId, streamHost, credentials, attempt]);

  if (loading) return <p className="center">Loading resource...</p>;
  if (error) return <p className="center error">Failed to load resources: {error}</p>;
  if (!resource) return <p className="center error">Unknown or unauthorized resource.</p>;

  const needsCredentials = credentials === null;

  return (
    <div className="watch-view">
      <div className="watch-bar">
        <span>
          {resource.name} ({resource.protocol})
        </span>
        <span className={state === "error" ? "error" : "muted"}>
          {state === "idle" && (message ?? "Sign in to the camera")}
          {state === "connecting" && "Connecting..."}
          {state === "playing" && "Live"}
          {state === "error" && (message ?? "Error")}
        </span>
        {!needsCredentials && (state === "error" || state === "idle") && (
          <button className="link" onClick={() => setAttempt((a) => a + 1)}>
            Reconnect
          </button>
        )}
        {!needsCredentials && (
          <button
            className="link"
            onClick={() => {
              setCredentials(null);
              setPassword("");
              setState("idle");
              setMessage(null);
            }}
          >
            Sign out of camera
          </button>
        )}
        <a className="link" href="/">
          Back
        </a>
      </div>
      {needsCredentials ? (
        <form
          className="watch-login stack"
          onSubmit={(e) => {
            e.preventDefault();
            setMessage(null);
            setCredentials({ username, password });
          }}
        >
          <p className="muted">
            This camera has its own credentials. They are used for this session only and are
            not stored.
          </p>
          <input
            placeholder="camera username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
          />
          <input
            type="password"
            placeholder="camera password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
          <button type="submit">Watch</button>
        </form>
      ) : (
        <video className="watch-video" ref={videoRef} autoPlay muted playsInline controls />
      )}
    </div>
  );
}
