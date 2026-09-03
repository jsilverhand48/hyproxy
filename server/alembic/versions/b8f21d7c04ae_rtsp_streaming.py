"""rtsp protocol + rtsp_grants

Adds the 'rtsp' protocol to the resource and connection CHECK constraints and
the single-use grant table backing the RTSP stream bridge. An rtsp connection
row stores only hostname/port/path: viewer credentials are supplied per session
and never persisted, so no sealed-secret column is involved.

Revision ID: b8f21d7c04ae
Revises: e5d0c7a3f1b6
Create Date: 2026-09-02

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'b8f21d7c04ae'
down_revision: str | None = 'e5d0c7a3f1b6'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint('resources_protocol_check', 'resources', type_='check')
    op.create_check_constraint(
        'resources_protocol_check',
        'resources',
        "protocol IN ('http','https','tcp','vnc','rdp','ssh','rtsp')",
    )
    op.drop_constraint(
        'resource_connections_protocol_check', 'resource_connections', type_='check'
    )
    op.create_check_constraint(
        'resource_connections_protocol_check',
        'resource_connections',
        "protocol IN ('vnc','rdp','ssh','rtsp')",
    )
    op.create_table(
        'rtsp_grants',
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
    op.create_index('ix_rtsp_grants_expires_at', 'rtsp_grants', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_rtsp_grants_expires_at', table_name='rtsp_grants')
    op.drop_table('rtsp_grants')
    # Narrowing the constraints again would fail while rtsp rows exist.
    op.execute("DELETE FROM resource_connections WHERE protocol = 'rtsp'")
    op.execute("DELETE FROM resources WHERE protocol = 'rtsp'")
    op.drop_constraint(
        'resource_connections_protocol_check', 'resource_connections', type_='check'
    )
    op.create_check_constraint(
        'resource_connections_protocol_check',
        'resource_connections',
        "protocol IN ('vnc','rdp','ssh')",
    )
    op.drop_constraint('resources_protocol_check', 'resources', type_='check')
    op.create_check_constraint(
        'resources_protocol_check',
        'resources',
        "protocol IN ('http','https','tcp','vnc','rdp','ssh')",
    )
