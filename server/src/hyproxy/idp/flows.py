"""Login flow state machine (login_flows table).

A flow is created when an unauthenticated user hits the login surface,
carries the validated OIDC authorize params through the factor steps, and is
deleted when the session is created. The stage can only advance along
password -> (totp | webauthn) -> done; the second factor is chosen strictly
by the user's auth tier, never by request input.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core.crypto import constant_time_equals, new_token, sha256_hex
from hyproxy.db.models import LoginFlow, User


def required_second_factor(user: User) -> Literal["totp", "webauthn"]:
    return "webauthn" if user.auth_tier == "admin" else "totp"


async def create_flow(
    session: AsyncSession,
    *,
    source_ip: str,
    oidc_request: dict[str, Any],
    now: datetime,
) -> tuple[LoginFlow, str]:
    """Returns (flow, csrf_token). Only the hash of the CSRF token is stored."""
    csrf_token = new_token(32)
    flow = LoginFlow(
        csrf_token_hash=sha256_hex(csrf_token),
        source_ip=source_ip,
        stage="password",
        oidc_request=oidc_request,
        expires_at=now + timedelta(seconds=get_settings().login_flow_ttl),
    )
    session.add(flow)
    await session.flush()
    return flow, csrf_token


async def get_valid_flow(
    session: AsyncSession,
    flow_id: str | None,
    *,
    source_ip: str,
    now: datetime,
    for_update: bool = False,
) -> LoginFlow | None:
    """Load a live flow; expired, unknown, or wrong-source flows return None.

    Pass for_update=True on the second-factor submit path to lock the row: it
    serializes a duplicate submit behind the first so the loser observes the
    completed flow and replays it, rather than both racing to burn it.
    """
    if not flow_id:
        return None
    try:
        fid = uuid.UUID(flow_id)
    except ValueError:
        return None
    flow = await session.get(LoginFlow, fid, with_for_update=for_update or None)
    if flow is None or flow.expires_at <= now:
        return None
    if str(flow.source_ip) != source_ip:
        return None  # flow is bound to the IP that started it
    return flow


def verify_flow_csrf(flow: LoginFlow, csrf_token: str) -> bool:
    return constant_time_equals(sha256_hex(csrf_token), flow.csrf_token_hash)


async def rotate_csrf(session: AsyncSession, flow: LoginFlow) -> str:
    """Issue a fresh CSRF token for the next form render (hash stored, token returned)."""
    csrf_token = new_token(32)
    flow.csrf_token_hash = sha256_hex(csrf_token)
    await session.flush()
    return csrf_token


async def delete_flow(session: AsyncSession, flow: LoginFlow) -> None:
    await session.delete(flow)
    await session.flush()
