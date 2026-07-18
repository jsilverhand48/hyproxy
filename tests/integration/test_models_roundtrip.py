import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import (
    AuthThrottle,
    OAuthClient,
    Session,
    SigningKey,
    User,
)

pytestmark = pytest.mark.integration


def make_user(**overrides: object) -> User:
    defaults: dict[str, object] = {
        "external_id": f"u-{uuid.uuid4()}",
        "email": f"{uuid.uuid4()}@example.test",
        "display_name": "Test User",
        "status": "active",
        "auth_tier": "standard",
        "password_hash": "x",
    }
    defaults.update(overrides)
    return User(**defaults)  # type: ignore[arg-type]


async def test_user_roundtrip_and_citext_email(db: AsyncSession) -> None:
    user = make_user(email="CaseFold@Example.Test")
    db.add(user)
    await db.flush()

    found = await db.scalar(select(User).where(User.email == "casefold@example.test"))
    assert found is not None
    assert found.id == user.id
    assert found.status == "active"
    assert found.created_at.tzinfo is not None


async def test_auth_tier_check_constraint(db: AsyncSession) -> None:
    db.add(make_user(auth_tier="superuser"))
    with pytest.raises(IntegrityError):
        await db.flush()


async def test_session_roundtrip(db: AsyncSession) -> None:
    user = make_user()
    db.add(user)
    await db.flush()

    sess = Session(
        user_id=user.id,
        cookie_secret_hash="h" * 64,
        source_ip="203.0.113.7",
        auth_tier="standard",
        amr=["pwd", "otp"],
        absolute_expires_at=datetime.now(UTC) + timedelta(hours=6),
    )
    db.add(sess)
    await db.flush()

    found = await db.get(Session, sess.id)
    assert found is not None
    assert found.amr == ["pwd", "otp"]
    assert found.stale is False
    assert found.dpop_jkt is None
    assert str(found.source_ip) == "203.0.113.7"


async def test_single_active_signing_key_enforced(db: AsyncSession) -> None:
    def key(state: str) -> SigningKey:
        return SigningKey(
            kid=f"kid-{uuid.uuid4()}",
            state=state,
            public_jwk={"kty": "EC"},
            private_key_ciphertext=b"ct",
            key_id="mk-1",
        )

    db.add(key("active"))
    db.add(key("retiring"))
    db.add(key("pending"))
    await db.flush()

    db.add(key("active"))
    with pytest.raises(IntegrityError):
        await db.flush()


async def test_oauth_client_defaults(db: AsyncSession) -> None:
    client = OAuthClient(
        client_id="test-rp",
        client_name="Test RP",
        redirect_uris=["https://rp.example.test/callback"],
    )
    db.add(client)
    await db.flush()
    await db.refresh(client)
    assert client.require_dpop is True
    assert client.token_endpoint_auth_method == "none"
    assert client.allowed_scopes == ["openid", "profile", "email"]


async def test_auth_throttle_composite_pk(db: AsyncSession) -> None:
    db.add(AuthThrottle(scope="ip", key="203.0.113.7"))
    db.add(AuthThrottle(scope="account", key="203.0.113.7"))
    await db.flush()

    db.add(AuthThrottle(scope="ip", key="203.0.113.7"))
    with pytest.raises(IntegrityError):
        await db.flush()
