"""login flow completed_session_id

Revision ID: d4a2c1e9f8b7
Revises: c3e9a1f0b2d7
Create Date: 2026-07-04 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = 'd4a2c1e9f8b7'
down_revision: str | None = 'c3e9a1f0b2d7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('login_flows', sa.Column('completed_session_id', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'login_flows_completed_session_id_fkey',
        'login_flows',
        'sessions',
        ['completed_session_id'],
        ['id'],
        ondelete='CASCADE',
    )


def downgrade() -> None:
    op.drop_constraint(
        'login_flows_completed_session_id_fkey', 'login_flows', type_='foreignkey'
    )
    op.drop_column('login_flows', 'completed_session_id')
