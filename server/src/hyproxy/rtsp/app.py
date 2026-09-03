"""The RTSP bridge service: RTSP in, fragmented MP4 out over a WebSocket.

Internal-only (loopback / data-plane network), exactly like the guac tunnel.
The Go data plane terminates TLS, forward-auths the connect against a live
gateway session, and single-use-consumes the RtspGrant BEFORE proxying the
WebSocket here, so this service trusts its network path. Decrypting the token is
the second gate: only the broker holds the key, so a forged token cannot reach
ffmpeg.

It runs as its own process rather than a router on the authz app because ffmpeg
subprocesses and hour-long streams must not contend with the latency-critical
/authz/check path.

Wire protocol to the browser:
  - TEXT frames are JSON control messages: {"type":"ready","codec":...} once the
    stream is confirmed, or {"type":"error","reason":...} before close.
  - BINARY frames are fragmented-MP4 bytes, appended verbatim to a MediaSource
    SourceBuffer.

The stream URL carries the viewer's camera password, so it is never logged: use
`urls.redact` on anything that might contain it.
"""

import asyncio
import contextlib
import json
import logging
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from hyproxy.config import get_settings
from hyproxy.core.sealedtoken import decrypt_token, load_cypher_key
from hyproxy.logs import setup_logging
from hyproxy.rtsp.urls import redact

log = logging.getLogger("hyproxy.rtsp.bridge")

# Time budget for the one-shot ffprobe and for the first byte out of ffmpeg. A
# camera that cannot answer in this window is treated as unreachable.
PROBE_TIMEOUT = 12.0
FIRST_BYTE_TIMEOUT = 20.0
# A viewer whose socket has not drained in this long is wedged; drop it rather
# than let ffmpeg block forever on a full pipe.
SEND_TIMEOUT = 30.0
# No fragment in this long once the stream is running means the camera stalled.
STALL_TIMEOUT = 30.0
READ_CHUNK = 32768

# WebSocket close codes. 1008 = policy violation, 1011 = internal error.
CLOSE_POLICY = 1008
CLOSE_INTERNAL = 1011

# H.264 profile_idc + constraint flags, keyed by the profile name ffprobe
# reports. The MSE codec string is avc1.<profile><constraints><level>, and
# addSourceBuffer throws if it does not describe the actual stream.
_AVC_PROFILES = {
    "Constrained Baseline": "42E0",
    "Baseline": "4200",
    "Main": "4D40",
    "Extended": "5800",
    "High": "6400",
    "High 10": "6E00",
    "High 4:2:2": "7A00",
    "High 4:4:4 Predictive": "F400",
}
_FALLBACK_AVC = "avc1.4D401F"
# What we ask libx264 for when transcoding, and the codec string it produces.
_TRANSCODE_ARGS = [
    "-c:v",
    "libx264",
    "-preset",
    "veryfast",
    "-tune",
    "zerolatency",
    "-profile:v",
    "high",
    "-level",
    "4.1",
    "-pix_fmt",
    "yuv420p",
    "-g",
    "50",
]
_TRANSCODE_AVC = "avc1.640029"

# Concurrent streams per user, enforced per bridge process. Transcoding an
# H.265 camera costs real CPU, so this is a guard against one viewer opening
# tabs until the box falls over.
_active: dict[str, int] = {}
_active_lock = asyncio.Lock()


def create_app() -> FastAPI:
    setup_logging("rtspbridge")
    app = FastAPI(title="hyproxy-rtsp-bridge", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "rtspbridge"}

    @app.websocket("/rtsp/stream")
    async def stream(ws: WebSocket) -> None:
        await _serve_stream(ws)

    return app


def _avc_codec_string(profile: str | None, level: int | None) -> str:
    """Build the MSE codec string for a passthrough H.264 stream."""
    prefix = _AVC_PROFILES.get(profile or "")
    if prefix is None or not level or level <= 0 or level > 255:
        return _FALLBACK_AVC
    return f"avc1.{prefix}{level:02X}"


def _classify_ffmpeg_error(stderr: str) -> str:
    low = stderr.lower()
    if "401" in low or "unauthorized" in low:
        return "rtsp_auth_failed"
    if "404" in low or "not found" in low:
        return "rtsp_stream_not_found"
    if "connection refused" in low or "timed out" in low or "no route to host" in low:
        return "rtsp_unreachable"
    return "rtsp_failed"


async def _probe(url: str) -> tuple[str, str | None, int | None, str]:
    """ffprobe the first video stream. Returns (codec_name, profile, level, error)."""
    proc = await asyncio.create_subprocess_exec(
        "ffprobe",
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-select_streams",
        "v:0",
        "-show_entries",
        "stream=codec_name,profile,level",
        "-of",
        "json",
        url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=PROBE_TIMEOUT)
    except TimeoutError:
        await _terminate(proc)
        return "", None, None, "rtsp_unreachable"
    if proc.returncode != 0:
        return "", None, None, _classify_ffmpeg_error(err.decode("utf-8", "replace"))
    try:
        streams = json.loads(out or b"{}").get("streams") or []
    except ValueError:
        return "", None, None, "rtsp_failed"
    if not streams:
        return "", None, None, "rtsp_no_video"
    first = streams[0]
    level = first.get("level")
    return (
        str(first.get("codec_name") or ""),
        first.get("profile"),
        int(level) if isinstance(level, int) else None,
        "",
    )


def _ffmpeg_args(url: str, *, passthrough: bool, audio: str) -> list[str]:
    args = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
        "-rtsp_transport",
        "tcp",
        "-fflags",
        "nobuffer",
        "-flags",
        "low_delay",
        "-i",
        url,
    ]
    if audio == "aac":
        args += ["-c:a", "aac", "-b:a", "64k", "-ac", "1"]
    else:
        args += ["-an"]
    args += ["-c:v", "copy"] if passthrough else list(_TRANSCODE_ARGS)
    # empty_moov + frag_keyframe emit a streamable fMP4 with no seekable index,
    # which is exactly what a MediaSource SourceBuffer wants.
    args += [
        "-f",
        "mp4",
        "-movflags",
        "+frag_keyframe+empty_moov+default_base_moof",
        "pipe:1",
    ]
    return args


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()


async def _fail(ws: WebSocket, reason: str, *, code: int = CLOSE_POLICY) -> None:
    with contextlib.suppress(Exception):
        await ws.send_text(json.dumps({"type": "error", "reason": reason}))
    with contextlib.suppress(Exception):
        await ws.close(code=code)


async def _watch_client(ws: WebSocket) -> None:
    """Resolve when the browser goes away, so the pump can stop ffmpeg."""
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        while True:
            await ws.receive()


async def _serve_stream(ws: WebSocket) -> None:
    settings = get_settings()
    await ws.accept()

    if not settings.rtsp_cypher_key:
        await _fail(ws, "rtsp_disabled")
        return

    token = ws.query_params.get("token") or ""
    if not token:
        await _fail(ws, "missing_token")
        return
    try:
        payload = decrypt_token(load_cypher_key(settings.rtsp_cypher_key), token)
        stream: dict[str, Any] = payload["stream"]
        url = str(stream["url"])
    except Exception:
        # A token we cannot decrypt is forged or minted under a stale key.
        log.warning("rtsp token rejected", extra={"action": "blocked"})
        await _fail(ws, "invalid_token")
        return

    user_id = str(stream.get("user_id") or "")
    max_seconds = int(stream.get("max_seconds") or settings.rtsp_max_stream_secs)
    audio = str(stream.get("audio") or "none")
    safe_url = redact(url)

    async with _active_lock:
        if _active.get(user_id, 0) >= settings.rtsp_max_streams_per_user:
            await _fail(ws, "too_many_streams")
            return
        _active[user_id] = _active.get(user_id, 0) + 1
    try:
        await _run_stream(ws, url, safe_url, audio=audio, max_seconds=max_seconds)
    finally:
        async with _active_lock:
            remaining = _active.get(user_id, 1) - 1
            if remaining > 0:
                _active[user_id] = remaining
            else:
                _active.pop(user_id, None)


async def _run_stream(
    ws: WebSocket, url: str, safe_url: str, *, audio: str, max_seconds: int
) -> None:
    codec_name, profile, level, probe_error = await _probe(url)
    if probe_error:
        log.info("rtsp probe failed", extra={"url": safe_url, "reason": probe_error})
        await _fail(ws, probe_error)
        return

    # H.264 remuxes with no transcode. Anything else (H.265, MJPEG) has to be
    # re-encoded, because MSE will not play it.
    passthrough = codec_name == "h264"
    video_codec = _avc_codec_string(profile, level) if passthrough else _TRANSCODE_AVC
    codec = f"{video_codec}, mp4a.40.2" if audio == "aac" else video_codec

    proc = await asyncio.create_subprocess_exec(
        *_ffmpeg_args(url, passthrough=passthrough, audio=audio),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdout is not None and proc.stderr is not None
    log.info(
        "rtsp stream open",
        extra={"url": safe_url, "codec": codec, "transcode": not passthrough},
    )

    # The watcher resolves the moment the browser goes away. Every read races
    # against it, so a viewer closing the tab stops ffmpeg immediately instead
    # of when the next fragment happens to arrive.
    watcher = asyncio.create_task(_watch_client(ws))
    stderr_buf = bytearray()
    stderr_task = asyncio.create_task(_drain(proc.stderr, stderr_buf))
    deadline = asyncio.get_running_loop().time() + max_seconds
    ready = False
    read_task: asyncio.Task[bytes] | None = None
    try:
        while True:
            # Two independent limits: a stall timeout (the camera stopped
            # sending) and the absolute wall-clock cap on the whole session.
            stall = FIRST_BYTE_TIMEOUT if not ready else STALL_TIMEOUT
            budget = min(stall, deadline - asyncio.get_running_loop().time())
            if budget <= 0:
                break
            read_task = asyncio.create_task(proc.stdout.read(READ_CHUNK))
            done, _ = await asyncio.wait(
                {read_task, watcher}, timeout=budget, return_when=asyncio.FIRST_COMPLETED
            )
            if watcher in done or read_task not in done:
                # Client gone, or nothing arrived within the budget. Either way
                # this stream is over; the read is abandoned with the process.
                read_task.cancel()
                if not ready and watcher not in done:
                    await _fail(ws, "rtsp_unreachable")
                    return
                break
            chunk = read_task.result()
            read_task = None
            if not chunk:
                break
            if not ready:
                await ws.send_text(json.dumps({"type": "ready", "codec": codec}))
                ready = True
            try:
                await asyncio.wait_for(ws.send_bytes(chunk), timeout=SEND_TIMEOUT)
            except (TimeoutError, WebSocketDisconnect, RuntimeError):
                break
        if not ready:
            # ffmpeg died before producing a fragment; its stderr says why.
            # Bounded: a silent-but-alive ffmpeg must not wedge the handler.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(stderr_task), timeout=2.0)
            reason = _classify_ffmpeg_error(stderr_buf.decode("utf-8", "replace"))
            log.info("rtsp stream failed", extra={"url": safe_url, "reason": reason})
            await _fail(ws, reason)
            return
    finally:
        if read_task is not None:
            read_task.cancel()
        watcher.cancel()
        stderr_task.cancel()
        await _terminate(proc)
        with contextlib.suppress(Exception):
            await ws.close()
        log.info("rtsp stream closed", extra={"url": safe_url})


async def _drain(reader: asyncio.StreamReader, into: bytearray) -> None:
    """Collect ffmpeg's stderr so a startup failure can be classified. Bounded
    to the first few KB. ffmpeg echoes the input URL (credentials and all) in
    its errors, so this buffer is only ever fed to _classify_ffmpeg_error and
    must never be logged or sent to the browser."""
    with contextlib.suppress(Exception):
        while len(into) < 8192:
            chunk = await reader.read(1024)
            if not chunk:
                return
            into.extend(chunk)


app = create_app()
