"""Auth event audit trail.

emit() writes in the caller's transaction, so an audit row exists iff the
state change it describes committed. `detail` accepts only whitelisted keys
and never carries secrets, tokens, codes, or password material.
"""

import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import AuthEvent


class AuthEventType(StrEnum):
    LOGIN_PASSWORD_SUCCESS = "login.password.success"
    LOGIN_PASSWORD_FAILURE = "login.password.failure"
    LOGIN_TOTP_SUCCESS = "login.totp.success"
    LOGIN_TOTP_FAILURE = "login.totp.failure"
    LOGIN_WEBAUTHN_SUCCESS = "login.webauthn.success"
    LOGIN_WEBAUTHN_FAILURE = "login.webauthn.failure"
    LOGIN_RECOVERY_CODE_USED = "login.recovery_code.used"
    LOGIN_RECOVERY_CODE_FAILURE = "login.recovery_code.failure"
    LOGIN_BREAK_GLASS_USED = "login.break_glass.used"
    ENROLL_TOTP = "enroll.totp"
    ENROLL_WEBAUTHN = "enroll.webauthn"
    OIDC_CODE_ISSUED = "oidc.code.issued"
    OIDC_CODE_REPLAY_DETECTED = "oidc.code.replay_detected"
    OIDC_TOKEN_ISSUED = "oidc.token.issued"
    OIDC_TOKEN_REFRESHED = "oidc.token.refreshed"
    OIDC_REFRESH_REUSE_DETECTED = "oidc.refresh.reuse_detected"
    OIDC_TOKEN_REVOKED = "oidc.token.revoked"
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    SESSION_STALE_IP = "session.stale_ip"
    SESSION_IDLE_TIMEOUT = "session.idle_timeout"
    STEPUP_SUCCESS = "stepup.success"
    STEPUP_FAILURE = "stepup.failure"
    THROTTLE_APPLIED = "throttle.applied"
    ADMIN_TOTP_RESET = "admin.totp_reset"
    ADMIN_PASSWORD_RESET = "admin.password_reset"


# Only these keys may appear in detail; values must be short scalars.
ALLOWED_DETAIL_KEYS = frozenset(
    {
        "reason",
        "stage",
        "kid",
        "scope",
        "grant_type",
        "credential_id",
        "friendly_name",
        "batch_id",
        "family_id",
        "entity_type",
        "entity_id",
        "throttle_scope",
        "retry_after",
        "old_ip",
        "new_ip",
        "email",
    }
)


def _validate_detail(detail: dict[str, Any]) -> None:
    bad = set(detail) - ALLOWED_DETAIL_KEYS
    if bad:
        raise ValueError(f"disallowed audit detail keys: {sorted(bad)}")
    for k, v in detail.items():
        if not isinstance(v, str | int | bool | float) or (isinstance(v, str) and len(v) > 256):
            raise ValueError(f"audit detail {k!r} must be a short scalar")


async def emit(
    session: AsyncSession,
    event_type: AuthEventType,
    *,
    source_ip: str,
    success: bool,
    user_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    client_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    detail = detail or {}
    _validate_detail(detail)
    session.add(
        AuthEvent(
            event_type=event_type.value,
            user_id=user_id,
            session_id=session_id,
            client_id=client_id,
            source_ip=source_ip,
            success=success,
            detail=detail,
        )
    )
    await session.flush()
