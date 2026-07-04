"""Client-IP resolution for audit, rate-limiting, and session binding.

Behind the data plane (the single TLS ingress) the socket peer is the proxy,
not the user. The data plane sets a sanitized ``X-Forwarded-For`` on every
proxied request (inbound copies are replaced, so it cannot be spoofed). When
``trust_forwarded_for`` is enabled we take the left-most entry as the real
client; otherwise (direct-TLS / dev) we use the socket peer. Getting this wrong
splits the recorded IP: the IdP would bind a session to the proxy IP while the
data plane's /authz/check reports the browser IP, and every session-liveness
check would then trip source-IP binding and force a re-auth loop.
"""

from fastapi import Request

from hyproxy.config import get_settings


def resolve_client_ip(request: Request) -> str:
    if get_settings().trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",", 1)[0].strip()
            if first:
                return first
    assert request.client is not None
    return request.client.host
