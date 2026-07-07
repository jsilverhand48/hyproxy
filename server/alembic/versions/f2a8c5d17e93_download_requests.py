"""download_requests (standard-user portal P2P requests)

Revision ID: f2a8c5d17e93
Revises: e7b3d9c41a52
Create Date: 2026-07-07 10:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'f2a8c5d17e93'
down_revision: str | None = 'e7b3d9c41a52'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'download_requests',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('magnet', sa.Text(), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('status', sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('reviewed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.CheckConstraint("target IN ('alpha','bravo')", name='download_requests_target_check'),
        sa.CheckConstraint("status IN ('pending','approved','denied')", name='download_requests_status_check'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_download_requests_user_id', 'download_requests', ['user_id'])
    op.create_index('ix_download_requests_status', 'download_requests', ['status'])


def downgrade() -> None:
    op.drop_index('ix_download_requests_status', table_name='download_requests')
    op.drop_index('ix_download_requests_user_id', table_name='download_requests')
    op.drop_table('download_requests')
