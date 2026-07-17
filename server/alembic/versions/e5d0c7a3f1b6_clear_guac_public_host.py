"""clear guac public_host

Guac (vnc/rdp/ssh) resources are now reached via the portal host's fixed
/guac/tunnel path instead of per-resource public hosts, so any public_host
still set on them is stale routing state.

Revision ID: e5d0c7a3f1b6
Revises: c9b7e5a31d84
Create Date: 2026-07-17

"""
from collections.abc import Sequence

from alembic import op

revision: str = 'e5d0c7a3f1b6'
down_revision: str | None = 'c9b7e5a31d84'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE resources SET public_host = NULL "
        "WHERE protocol IN ('vnc','rdp','ssh') AND public_host IS NOT NULL"
    )


def downgrade() -> None:
    # Data cleanup only; the removed hosts are not restorable.
    pass
