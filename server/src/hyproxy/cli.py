import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import click
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.secrets import generate_master_key_file, get_secrets_backend
from hyproxy.db.engine import db_session
from hyproxy.db.models import DpopJtiSeen, GuacGrant, LoginFlow, OAuthClient, User
from hyproxy.logs import setup_logging


def run_db[T](fn: Callable[[AsyncSession], Awaitable[T]]) -> T:
    async def runner() -> T:
        async with db_session() as session:
            return await fn(session)

    return asyncio.run(runner())


@click.group()
def cli() -> None:
    """hyproxy management commands."""
    setup_logging("cli")


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

    Idempotent with reset semantics: re-running for an existing email keeps the
    account but sets a fresh temporary password, so every installer pass leaves
    the break-glass admin with a known-once credential.

    The admin must enroll at least two WebAuthn credentials before real use;
    print the enrollment entry point.
    """
    import secrets as _secrets
    import uuid as _uuid

    from hyproxy.security.passwords import hash_password

    temp_password = _secrets.token_urlsafe(16)
    password_hash = hash_password(temp_password)

    async def do(session: AsyncSession) -> bool:
        existing = await session.scalar(select(User).where(User.email == email))
        if existing is not None:
            existing.password_hash = password_hash
            existing.updated_at = datetime.now(UTC)
            return False
        session.add(
            User(
                external_id=f"user-{_uuid.uuid4()}",
                email=email,
                display_name=display_name,
                status="active",
                auth_tier="admin",
                password_hash=password_hash,
                is_protected=True,
            )
        )
        return True

    created = run_db(do)
    if created:
        click.echo(f"created admin {email}")
    else:
        click.echo(f"admin {email} already exists; temporary password reset")
    click.echo(f"temporary password (shown once): {temp_password}")
    click.echo("next: sign in at /auth/login and enroll two passkeys at /auth/enroll/webauthn")


async def _upsert_client(
    session: AsyncSession, client_id: str, client_name: str, redirect_uris: list[str]
) -> bool:
    """Register or update an OIDC client; re-enables a disabled one. Returns
    True when a new row was created, False when an existing one was updated."""
    existing = await session.scalar(select(OAuthClient).where(OAuthClient.client_id == client_id))
    if existing is not None:
        existing.client_name = client_name
        existing.redirect_uris = redirect_uris
        existing.enabled = True
        return False
    session.add(
        OAuthClient(client_id=client_id, client_name=client_name, redirect_uris=redirect_uris)
    )
    return True


@cli.command("create-client")
@click.option("--client-id", required=True)
@click.option("--name", "client_name", required=True)
@click.option("--redirect-uri", "redirect_uris", multiple=True, required=True)
def create_client(client_id: str, client_name: str, redirect_uris: tuple[str, ...]) -> None:
    """Register an OIDC relying party (public client, PKCE + DPoP required).

    Idempotent: re-running for an existing client-id updates its name and
    redirect URIs instead of failing, so bootstrap can safely re-run.
    """

    created = run_db(lambda s: _upsert_client(s, client_id, client_name, list(redirect_uris)))
    click.echo(f"{'registered' if created else 'updated'} client {client_id}")


@cli.command("bootstrap-gateway-client")
def bootstrap_gateway_client() -> None:
    """Register the data plane's forward-auth OIDC client.

    The client-id is settings.gateway_client_id and the redirect_uri is derived
    from the same settings the authz service uses (HYPROXY_AUTH_HOST /
    HYPROXY_EXTERNAL_SCHEME), so it byte-matches gateway_redirect_uri() and the
    IdP's exact-match check passes. Idempotent: safe to run at bootstrap and on
    every deploy. Without this, protected resources dead-end at the IdP's
    /oidc/authorize with 'Unknown application'."""
    from hyproxy.authz.gateway import gateway_redirect_uri

    settings = get_settings()
    client_id = settings.gateway_client_id
    redirect_uri = gateway_redirect_uri()
    created = run_db(lambda s: _upsert_client(s, client_id, "hyproxy gateway", [redirect_uri]))
    click.echo(
        f"{'registered' if created else 'updated'} gateway client "
        f"{client_id} -> {redirect_uri}"
    )


@cli.command("rotate-master-key")
def rotate_master_key() -> None:
    """Re-wrap every sealed blob under the current master key.

    Run after a new master key becomes current (e.g. migrating from the file
    backend to the TPM-sealed key): add the new key, then rotate so all TOTP
    secrets, signing keys, and connection secrets are re-encrypted to it."""
    from hyproxy.core.reencrypt import rotate_to_current

    backend = get_secrets_backend()

    async def do(session: AsyncSession) -> Any:
        return await rotate_to_current(session, backend)

    result = run_db(do)
    per_table = ", ".join(f"{t}={n}" for t, n in result.rewrapped.items())
    click.echo(
        f"re-wrapped {result.total} blobs to master key {result.target_key_id} ({per_table})"
    )


@cli.command("gen-guac-key")
def gen_guac_key() -> None:
    """Generate a base64 32-byte AES-256-CBC key for the Guacamole broker.

    Set it as HYPROXY_GUAC_CYPHER_KEY on the control plane AND as the guacd
    tunnel's key (guacamole-lite); both sides must share the exact value."""
    import base64
    import secrets as _secrets

    click.echo(base64.b64encode(_secrets.token_bytes(32)).decode())


@cli.command("ship-logs")
@click.option("--batch-size", default=500, show_default=True)
@click.option(
    "--to-file",
    is_flag=True,
    help="Write to <log_dir>/audit.log (rotating) instead of stdout.",
)
def ship_logs(batch_size: int, to_file: bool) -> None:
    """Ship new audit rows off-box as JSON lines on stdout (cron it).

    Pipe stdout to your syslog/OTLP forwarder; the per-stream cursor advances
    only after the batch is written, so a failed pipe re-ships (at-least-once).
    With --to-file the destination is the centralized audit.log under
    HYPROXY_LOG_DIR. The summary and high-severity count go to stderr."""
    from hyproxy.audit.shipping import JsonLinesSink, LogSink, RotatingFileSink, ship

    sink: LogSink
    if to_file:
        settings = get_settings()
        if not settings.log_dir:
            raise click.ClickException("--to-file requires HYPROXY_LOG_DIR to be set")
        sink = RotatingFileSink(
            Path(settings.log_dir) / "audit.log",
            settings.log_max_bytes,
            settings.log_backup_count,
        )
    else:
        sink = JsonLinesSink()

    async def do(session: AsyncSession) -> Any:
        return await ship(session, sink, batch_size=batch_size)

    result = run_db(do)
    per = ", ".join(f"{s}={n}" for s, n in result.shipped.items())
    click.echo(f"shipped {result.total} ({per}); {result.high_severity} high-severity", err=True)


@cli.command("gc")
def gc() -> None:
    """Delete expired DPoP jtis, gateway login states, spent guac grants; retire keys."""
    now = datetime.now(UTC)

    async def do(session: AsyncSession) -> tuple[int, int, int, int, int]:
        from hyproxy.authz.gateway import gc_login_states

        res = cast(
            CursorResult[Any],
            await session.execute(delete(DpopJtiSeen).where(DpopJtiSeen.expires_at <= now)),
        )
        # Grants are single-use and short-lived: drop expired or already-consumed.
        grants = cast(
            CursorResult[Any],
            await session.execute(
                delete(GuacGrant).where(
                    (GuacGrant.expires_at <= now) | (GuacGrant.consumed_at.is_not(None))
                )
            ),
        )
        # Login flows are short-lived and retained past completion for idempotent
        # replay; drop them once expired (completed or abandoned alike).
        flows = cast(
            CursorResult[Any],
            await session.execute(delete(LoginFlow).where(LoginFlow.expires_at <= now)),
        )
        retired = await key_service.gc_retired(session, now)
        states = await gc_login_states(session, now)
        return res.rowcount or 0, retired, states, grants.rowcount or 0, flows.rowcount or 0

    jtis, retired, states, grants, flows = run_db(do)
    click.echo(
        f"deleted {jtis} expired dpop jtis, {states} login states, {grants} guac grants, "
        f"{flows} login flows; retired {retired} signing keys"
    )


if __name__ == "__main__":
    cli()
