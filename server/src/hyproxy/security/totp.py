"""TOTP enrollment and verification. Secrets are AES-GCM encrypted at rest."""

import io
from datetime import datetime

import pyotp
import segno
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core.crypto import decrypt_blob, encrypt_blob
from hyproxy.core.secrets import SecretsBackend
from hyproxy.db.models import User, UserTotp

_AAD = "user_totp"


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def provisioning_qr_svg(uri: str) -> str:
    """QR of the otpauth:// URI as an inline-SVG fragment (no XML declaration).

    Inlined into the enrollment page rather than served as an <img>: the auth
    surface's CSP has img-src 'self' with no data: source, and inline SVG
    markup is not fetched, so no CSP widening is needed. omitsize yields a
    viewBox-only SVG the stylesheet can scale.
    """
    buf = io.BytesIO()
    segno.make(uri, error="m").save(
        buf, kind="svg", xmldecl=False, omitsize=True, dark="#000", light="#fff", border=3
    )
    return buf.getvalue().decode("utf-8")


def verify_code(secret: str, code: str, at: datetime | None = None) -> bool:
    totp = pyotp.TOTP(secret)
    # +/- one 30s step of clock drift.
    if at is not None:
        return totp.verify(code, for_time=at, valid_window=1)
    return totp.verify(code, valid_window=1)


async def store_pending_secret(
    session: AsyncSession, backend: SecretsBackend, user_id: object, secret: str
) -> UserTotp:
    """Create or replace the (unconfirmed) TOTP secret for enrollment."""
    existing = await session.get(UserTotp, user_id)
    if existing is not None:
        await session.delete(existing)
        await session.flush()
    key_id, blob = encrypt_blob(backend, secret.encode(), _AAD)
    row = UserTotp(user_id=user_id, secret_ciphertext=blob, key_id=key_id)
    session.add(row)
    await session.flush()
    return row


def decrypt_secret(backend: SecretsBackend, row: UserTotp) -> str:
    return decrypt_blob(backend, row.key_id, row.secret_ciphertext, _AAD).decode()


async def get_totp_row(
    session: AsyncSession, user: User, *, confirmed_only: bool
) -> UserTotp | None:
    row = await session.get(UserTotp, user.id)
    if row is None:
        return None
    if confirmed_only and row.confirmed_at is None:
        return None
    return row
