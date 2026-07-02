"""resource_connections + guac_grants (Phase 4 Guacamole)

Revision ID: a1c4f7e2b9d0
Revises: 278129ba7514
Create Date: 2026-07-02 10:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'a1c4f7e2b9d0'
down_revision: str | None = '278129ba7514'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'resource_connections',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('protocol', sa.Text(), nullable=False),
        sa.Column('hostname', sa.Text(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('params_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column('secret_ciphertext', sa.LargeBinary(), nullable=True),
        sa.Column('key_id', sa.Text(), nullable=True),
        sa.Column('secret_keys', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("protocol IN ('vnc','rdp','ssh')", name='resource_connections_protocol_check'),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('resource_id'),
    )
    op.create_table(
        'guac_grants',
        sa.Column('token_hash', sa.Text(), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source_ip', postgresql.INET(), nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('token_hash'),
    )
    op.create_index('ix_guac_grants_expires_at', 'guac_grants', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_guac_grants_expires_at', table_name='guac_grants')
    op.drop_table('guac_grants')
    op.drop_table('resource_connections')
