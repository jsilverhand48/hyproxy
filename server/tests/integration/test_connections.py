"""Per-resource Guacamole connection config: sealed secrets (write-only),
step-up on mutations, and change-log entries that carry no secret values."""

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import PolicyChange, ResourceConnection
from hyproxy.guac.connections import unseal_secret_params

pytestmark = pytest.mark.integration


async def _make_resource(admin_call: Any, dpop: Any, token: str) -> str:
    r = await admin_call(
        dpop,
        token,
        "POST",
        "/api/v1/resources",
        {"name": "lab-rdp", "protocol": "rdp", "host": "10.0.0.20", "ports": [3389]},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_put_get_seals_secrets_and_masks_on_read(
    admin_session: dict[str, Any],
    admin_call: Any,
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
) -> None:
    dpop, token = admin_session["dpop"], admin_session["token"]
    rid = await _make_resource(admin_call, dpop, token)

    put = await admin_call(
        dpop,
        token,
        "PUT",
        f"/api/v1/resources/{rid}/connection",
        {
            "protocol": "rdp",
            "hostname": "10.0.0.20",
            "port": 3389,
            "params": {"security": "nla", "ignore-cert": "true"},
            "secret_params": {"username": "svc", "password": "s3cr3t"},
        },
    )
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["has_secret"] is True
    assert body["secret_keys"] == ["password", "username"]
    assert body["params"] == {"security": "nla", "ignore-cert": "true"}
    # No secret VALUES anywhere in the response.
    assert "s3cr3t" not in put.text and "password" not in str(body["params"])

    got = await admin_call(dpop, token, "GET", f"/api/v1/resources/{rid}/connection")
    assert got.status_code == 200
    assert "s3cr3t" not in got.text

    # The sealed blob round-trips to the original secret params.
    row = await db.scalar(
        select(ResourceConnection).where(ResourceConnection.resource_id == rid)
    )
    assert row is not None
    assert unseal_secret_params(secrets_backend, row) == {"username": "svc", "password": "s3cr3t"}


async def test_secret_absent_keeps_empty_dict_clears(
    admin_session: dict[str, Any],
    admin_call: Any,
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
) -> None:
    dpop, token = admin_session["dpop"], admin_session["token"]
    rid = await _make_resource(admin_call, dpop, token)

    base = {"protocol": "rdp", "hostname": "h", "port": 3389, "params": {}}
    await admin_call(dpop, token, "PUT", f"/api/v1/resources/{rid}/connection",
                     {**base, "secret_params": {"password": "p"}})

    # Absent secret_params: keep the existing sealed secret.
    kept = await admin_call(dpop, token, "PUT", f"/api/v1/resources/{rid}/connection",
                            {**base, "hostname": "h2"})
    assert kept.json()["has_secret"] is True

    # Explicit empty dict: clear the secret.
    cleared = await admin_call(dpop, token, "PUT", f"/api/v1/resources/{rid}/connection",
                               {**base, "secret_params": {}})
    assert cleared.json()["has_secret"] is False
    assert cleared.json()["secret_keys"] == []


async def test_mutations_need_stepup_reads_do_not(
    admin_no_stepup: dict[str, Any],
    admin_call: Any,
    db: AsyncSession,
) -> None:
    from hyproxy.db.models import Resource

    # Seed a resource directly (POST would itself require step-up).
    resource = Resource(name="lab-vnc", protocol="vnc", host="10.0.0.30", ports=[5900])
    db.add(resource)
    await db.flush()
    dpop, token = admin_no_stepup["dpop"], admin_no_stepup["token"]

    # A read is allowed without step-up (404 = no connection yet, not a 403).
    read = await admin_call(dpop, token, "GET", f"/api/v1/resources/{resource.id}/connection")
    assert read.status_code == 404

    # A mutation requires a fresh step-up.
    write = await admin_call(
        dpop,
        token,
        "PUT",
        f"/api/v1/resources/{resource.id}/connection",
        {"protocol": "vnc", "hostname": "h", "port": 5900},
    )
    assert write.status_code == 403 and write.json()["detail"] == "stepup_required"


async def test_change_log_records_no_secret_values(
    admin_session: dict[str, Any],
    admin_call: Any,
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
) -> None:
    dpop, token = admin_session["dpop"], admin_session["token"]
    rid = await _make_resource(admin_call, dpop, token)
    await admin_call(
        dpop,
        token,
        "PUT",
        f"/api/v1/resources/{rid}/connection",
        {"protocol": "ssh", "hostname": "h", "port": 22,
         "secret_params": {"password": "topsecret"}},
    )
    changes = (
        await db.scalars(
            select(PolicyChange).where(PolicyChange.entity_type == "resource_connection")
        )
    ).all()
    assert changes
    for c in changes:
        assert "topsecret" not in str(c.change_json)
