import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import click
from sqlalchemy import CursorResult, delete
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.secrets import generate_master_key_file, get_secrets_backend
from hyproxy.db.engine import db_session
from hyproxy.db.models import DpopJtiSeen, OAuthClient, User


def run_db[T](fn: Callable[[AsyncSession], Awaitable[T]]) -> T:
    async def runner() -> T:
        async with db_session() as session:
            return await fn(session)

    return asyncio.run(runner())


@click.group()
def cli() -> None:
    """hyproxy management commands."""


@cli.command("gen-keys")
def gen_keys() -> None:
    """Generate (or add a key to) the dev master key file."""
    path = Path(get_settings().master_key_file)
    key_id = generate_master_key_file(path)
    click.echo(f"wrote master key {key_id} to {path}")


@cli.command("rotate-signing-key")
@click.option("--activate", is_flag=True, help="Promote the pending key to active.")
def rotate_signing_key(activate: bool) -> None:
    """Create a pending signing key, or with --activate promote it."""
    now = datetime.now(UTC)
    if activate:

        async def do_activate(session: AsyncSession) -> str:
            row = await key_service.activate_pending(session, now)
            return row.kid

        kid = run_db(do_activate)
        click.echo(f"activated signing key {kid}; previous active key is now retiring")
    else:
        backend = get_secrets_backend()

        async def do_create(session: AsyncSession) -> str:
            row = await key_service.create_pending(session, backend)
            return row.kid

        kid = run_db(do_create)
        click.echo(f"created pending signing key {kid} (published in JWKS; --activate to promote)")


@cli.command("bootstrap-keys")
def bootstrap_keys() -> None:
    """First-run convenience: ensure an active signing key exists."""
    backend = get_secrets_backend()
    now = datetime.now(UTC)

    async def do(session: AsyncSession) -> None:
        await key_service.bootstrap_if_empty(session, backend, now)

    run_db(do)
    click.echo("signing keys ready")


@cli.command("bootstrap-admin")
@click.option("--email", required=True)
@click.option("--name", "display_name", required=True)
def bootstrap_admin(email: str, display_name: str) -> None:
    """Create the first admin user with a one-time temporary password.

    The admin must enroll at least two WebAuthn credentials before real use;
    print the enrollment entry point.
    """
    import secrets as _secrets
    import uuid as _uuid

    from hyproxy.security.passwords import hash_password

    temp_password = _secrets.token_urlsafe(16)
    password_hash = hash_password(temp_password)

    async def do(session: AsyncSession) -> None:
        session.add(
            User(
                external_id=f"user-{_uuid.uuid4()}",
                email=email,
                display_name=display_name,
                status="active",
                auth_tier="admin",
                password_hash=password_hash,
            )
        )

    run_db(do)
    click.echo(f"created admin {email}")
    click.echo(f"temporary password (shown once): {temp_password}")
    click.echo("next: sign in at /auth/login and enroll two passkeys at /auth/enroll/webauthn")


@cli.command("create-client")
@click.option("--client-id", required=True)
@click.option("--name", "client_name", required=True)
@click.option("--redirect-uri", "redirect_uris", multiple=True, required=True)
def create_client(client_id: str, client_name: str, redirect_uris: tuple[str, ...]) -> None:
    """Register an OIDC relying party (public client, PKCE + DPoP required)."""

    async def do(session: AsyncSession) -> None:
        session.add(
            OAuthClient(
                client_id=client_id,
                client_name=client_name,
                redirect_uris=list(redirect_uris),
            )
        )

    run_db(do)
    click.echo(f"registered client {client_id}")


@cli.command("gc")
def gc() -> None:
    """Delete expired DPoP jtis and gateway login states; retire aged-out keys."""
    now = datetime.now(UTC)

    async def do(session: AsyncSession) -> tuple[int, int, int]:
        from hyproxy.authz.gateway import gc_login_states

        res = cast(
            CursorResult[Any],
            await session.execute(delete(DpopJtiSeen).where(DpopJtiSeen.expires_at <= now)),
        )
        retired = await key_service.gc_retired(session, now)
        states = await gc_login_states(session, now)
        return res.rowcount or 0, retired, states

    jtis, retired, states = run_db(do)
    click.echo(
        f"deleted {jtis} expired dpop jtis and {states} login states; "
        f"retired {retired} signing keys"
    )


if __name__ == "__main__":
    cli()
