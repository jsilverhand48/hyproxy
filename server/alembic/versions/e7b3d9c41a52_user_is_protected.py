"""user is_protected

Revision ID: e7b3d9c41a52
Revises: d4a2c1e9f8b7
Create Date: 2026-07-04 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = 'e7b3d9c41a52'
down_revision: str | None = 'd4a2c1e9f8b7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('users', sa.Column('is_protected', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    # The bootstrap admin predates this column; mark the earliest-created admin.
    op.execute(
        """
        UPDATE users SET is_protected = true
        WHERE id = (
            SELECT id FROM users WHERE auth_tier = 'admin'
            ORDER BY created_at, id LIMIT 1
        )
        """
    )


def downgrade() -> None:
    op.drop_column('users', 'is_protected')
