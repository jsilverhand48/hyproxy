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
// Media Source; there is no player library and no plugin. Text frames are JSON
// control messages, binary frames are media.
//
// There are TWO Media Source implementations to satisfy, which is the whole
// reason this file is more complicated than "new MediaSource()":
//
//   - Desktop browsers and Android Chrome have MediaSource, attached by handing
//     the <video> a blob: object URL (hence media-src 'self' blob: in the admin
//     CSP).
//   - iPhone Safari has NO MediaSource at all. It exposes ManagedMediaSource
//     (iOS 17.1+), which is attached via srcObject, refuses to work unless the
//     element has disableRemotePlayback set (it must not be able to hand off to
//     AirPlay), and emits startstreaming/endstreaming to say when it actually
//     wants data.
//
// MediaSource is preferred wherever it exists so every browser that already
// worked keeps its exact previous code path; the managed branch is purely
// additive for iPhone. Autoplay can still be refused (iOS Low Power Mode blocks
// it even for muted video), so a rejected play() surfaces a Play button rather
// than a black rectangle that claims to be live.

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

// The Media Source constructor this browser gives us, or undefined if it has
// neither. Prefer the unmanaged one where both exist (desktop Safari 17.1+) so
// that only iPhone, which has no choice, takes the managed path.
type MseCtor = { new (): MediaSource; isTypeSupported(type: string): boolean };
const MANAGED_MSE = window.ManagedMediaSource;
const MSE_CTOR: MseCtor | undefined =
  typeof window.MediaSource !== "undefined" ? window.MediaSource : MANAGED_MSE;

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
  // Autoplay was refused (iOS Low Power Mode, some Android data savers). The
  // stream is fine; it just needs a gesture, so offer one.
  const [needsTap, setNeedsTap] = useState(false);

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
    // Non-null means the blob: attachment path was used, which is also what
    // teardown keys off; the managed path uses srcObject instead.
    let objectUrl: string | null = null;
    const queue: ArrayBuffer[] = [];
    // ManagedMediaSource's buffering hint, and whether anything has been fed in
    // yet. Both only matter on the managed path; on the plain MediaSource path
    // `streaming` stays true forever and the gate in drain() is inert.
    let streaming = true;
    let appendedAny = false;

    setNeedsTap(false);

    const fail = (msg: string) => {
      if (disposed) return;
      setState("error");
      setMessage(msg);
    };

    // Without this the element can reject the stream (unsupported bitstream,
    // decoder failure) while the UI still reads "Live" over a black frame,
    // because appendBuffer errors are swallowed below. On a phone we cannot
    // open a console, so the element has to tell us itself.
    const onVideoError = () => {
      const code = video.error?.code;
      fail(
        code === MediaError.MEDIA_ERR_DECODE
          ? "The camera's video could not be decoded on this device."
          : "Video playback failed.",
      );
    };
    video.addEventListener("error", onVideoError);

    // SourceBuffer.appendBuffer throws while an append is in flight, so every
    // segment goes through this queue and is drained on updateend.
    const drain = () => {
      if (disposed || !sourceBuffer || sourceBuffer.updating || queue.length === 0) return;
      // ManagedMediaSource asking us to back off. For a live camera freshness
      // beats completeness, so collapse the backlog to the newest fragment
      // instead of appending: every fragment starts with a keyframe
      // (-movflags +frag_keyframe), so dropping whole fragments resyncs
      // cleanly. Deliberately NOT applied before the first successful append --
      // the init segment must always get in, or a UA that reports
      // streaming === false up front would deadlock the stream forever.
      if (!streaming && appendedAny) {
        if (queue.length > 1) queue.splice(0, queue.length - 1);
        return;
      }
      const chunk = queue.shift();
      if (!chunk) return;
      try {
        sourceBuffer.appendBuffer(new Uint8Array(chunk));
        appendedAny = true;
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

    // Autoplay is best-effort: the attributes normally carry it, but iOS Low
    // Power Mode refuses even muted video, and by this point we are several
    // awaits past the user's gesture, so there is no gesture to borrow.
    const tryPlay = () => {
      void video.play().catch((e: unknown) => {
        if (disposed) return;
        if (e instanceof DOMException && e.name === "NotAllowedError") {
          setNeedsTap(true);
          setMessage("Tap Play to start the stream.");
        } else {
          setMessage("Playback could not start.");
        }
      });
    };

    const startPlayback = (codec: string) => {
      const mime = `video/mp4; codecs="${codec}"`;
      if (!MSE_CTOR) {
        fail("This browser cannot play live video. Use Safari 17.1+ or Chrome.");
        return;
      }
      // Ask the constructor we are actually going to use:
      // ManagedMediaSource.isTypeSupported reflects the hardware decoder and is
      // legitimately stricter than MediaSource's.
      if (!MSE_CTOR.isTypeSupported(mime)) {
        fail("This browser cannot play the camera's video format.");
        return;
      }
      const managed = MSE_CTOR === MANAGED_MSE;
      mediaSource = new MSE_CTOR();

      // WebKit refuses a ManagedMediaSource on an element that could still hand
      // off to AirPlay, so this must be set before attaching. Harmless
      // elsewhere: this is a live camera, never a cast target.
      video.disableRemotePlayback = true;

      if (managed) {
        streaming = (mediaSource as ManagedMediaSource).streaming ?? true;
        mediaSource.addEventListener("startstreaming", () => {
          streaming = true;
          drain();
        });
        mediaSource.addEventListener("endstreaming", () => {
          streaming = false;
        });
        // srcObject is the documented attachment for ManagedMediaSource; a
        // blob: URL is not reliably accepted for it.
        try {
          video.srcObject = mediaSource;
        } catch {
          objectUrl = URL.createObjectURL(mediaSource);
          video.src = objectUrl;
        }
      } else {
        objectUrl = URL.createObjectURL(mediaSource);
        video.src = objectUrl;
      }

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
        tryPlay();
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
      video.removeEventListener("error", onVideoError);
      video.pause();
      // Detach whichever way we attached, or the next connect inherits a dead
      // source (and on the managed path leaks the old one).
      if (objectUrl) {
        video.removeAttribute("src");
        URL.revokeObjectURL(objectUrl);
        objectUrl = null;
      } else {
        video.srcObject = null;
      }
      video.load();
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
        {needsTap && (
          <button
            className="link"
            onClick={() => {
              setNeedsTap(false);
              setMessage(null);
              void videoRef.current?.play();
            }}
          >
            Play
          </button>
        )}
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
