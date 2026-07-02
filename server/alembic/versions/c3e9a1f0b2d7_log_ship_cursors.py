"""log_ship_cursors (Phase 5 off-box shipping)

Revision ID: c3e9a1f0b2d7
Revises: a1c4f7e2b9d0
Create Date: 2026-07-02 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c3e9a1f0b2d7'
down_revision: str | None = 'a1c4f7e2b9d0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'log_ship_cursors',
        sa.Column('stream', sa.Text(), nullable=False),
        sa.Column('last_id', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('stream'),
    )


def downgrade() -> None:
    op.drop_table('log_ship_cursors')
