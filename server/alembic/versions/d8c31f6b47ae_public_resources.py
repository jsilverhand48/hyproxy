"""public password-gated resources

Adds the password-only public access mode to resources: an `enabled` http/https
resource with a routing host can be exposed to anyone on the internet behind a
single generated password, restricted to an explicit allowlist of path globs.
`public_sessions` is the anonymous counterpart to `gateway_sessions`.

Revision ID: d8c31f6b47ae
Revises: b8f21d7c04ae
Create Date: 2026-09-09 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'd8c31f6b47ae'
down_revision: str | None = 'b8f21d7c04ae'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'resources',
        sa.Column('public_access', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    )
    op.add_column('resources', sa.Column('public_paths', postgresql.ARRAY(sa.Text()), nullable=True))
    op.add_column('resources', sa.Column('public_password_hash', sa.Text(), nullable=True))
    op.add_column(
        'resources',
        sa.Column('public_password_set_at', sa.DateTime(timezone=True), nullable=True),
    )
    # Public mode is only coherent for an L7 resource with a routing host and a
    # non-empty path allowlist; a public resource with no patterns would either
    # be unreachable or (worse, if the check were absent) expose the whole host.
    op.create_check_constraint(
        'resources_public_access_shape_check',
        'resources',
        "NOT public_access OR ("
        "protocol IN ('http','https')"
        " AND public_host IS NOT NULL"
        " AND public_paths IS NOT NULL"
        " AND array_length(public_paths, 1) >= 1)",
    )
    op.create_table(
        'public_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('cookie_secret_hash', sa.Text(), nullable=False),
        sa.Column('source_ip', postgresql.INET(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['resource_id'], ['resources.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_public_sessions_resource_id', 'public_sessions', ['resource_id'])


def downgrade() -> None:
    op.drop_index('ix_public_sessions_resource_id', table_name='public_sessions')
    op.drop_table('public_sessions')
    op.drop_constraint('resources_public_access_shape_check', 'resources', type_='check')
    op.drop_column('resources', 'public_password_set_at')
    op.drop_column('resources', 'public_password_hash')
    op.drop_column('resources', 'public_paths')
    op.drop_column('resources', 'public_access')
