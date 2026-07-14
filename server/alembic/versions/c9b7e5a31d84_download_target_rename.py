"""download_requests target values renamed alpha/bravo -> shows/movies

f2a8c5d17e93 was amended in place after it had already run on staging, so
databases that applied the original still enforce target IN ('alpha','bravo').
Recreate the check constraint with the current values; fresh databases get the
same definition twice, which is a no-op.

Revision ID: c9b7e5a31d84
Revises: f2a8c5d17e93
Create Date: 2026-07-07 23:30:00.000000

"""
from collections.abc import Sequence

from alembic import op

revision: str = 'c9b7e5a31d84'
down_revision: str | None = 'f2a8c5d17e93'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint('download_requests_target_check', 'download_requests', type_='check')
    op.create_check_constraint(
        'download_requests_target_check',
        'download_requests',
        "target IN ('shows','movies')",
    )


def downgrade() -> None:
    op.drop_constraint('download_requests_target_check', 'download_requests', type_='check')
    op.create_check_constraint(
        'download_requests_target_check',
        'download_requests',
        "target IN ('alpha','bravo')",
    )
