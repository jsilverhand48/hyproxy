"""RTSP URL construction.

The SSRF invariant that governs the whole data plane applies here too: the
target host, port and stream path come ONLY from the server-side
ResourceConnection row. The client supplies a username and password and nothing
else, so it can never redirect the bridge at an arbitrary host.
"""

from urllib.parse import quote

from hyproxy.db.models import ResourceConnection

# Cameras vary wildly in stream path (/Streaming/Channels/101 on Hikvision,
# /cam/realmonitor?channel=1&subtype=0 on Dahua), so it is admin-configured.
_PATH_PARAM = "path"


def stream_path(connection: ResourceConnection) -> str:
    raw = str(connection.params_json.get(_PATH_PARAM, "") or "")
    if not raw:
        return "/"
    return raw if raw.startswith("/") else f"/{raw}"


def build_rtsp_url(connection: ResourceConnection, *, username: str, password: str) -> str:
    """Build rtsp://user:pass@host:port/path with credentials percent-encoded.

    Credentials are quoted with an empty safe set so a password containing
    ':', '@' or '/' cannot break out of the userinfo component and rewrite the
    host."""
    userinfo = ""
    if username or password:
        userinfo = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"rtsp://{userinfo}{connection.hostname}:{connection.port}{stream_path(connection)}"


def redact(url: str) -> str:
    """Strip credentials from an RTSP URL for logging. Never log the raw URL."""
    scheme, _, rest = url.partition("://")
    if not rest:
        return url
    _, at, hostpart = rest.rpartition("@")
    if not at:
        return url
    return f"{scheme}://***:***@{hostpart}"
