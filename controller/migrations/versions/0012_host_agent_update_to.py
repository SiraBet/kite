"""Per-host agent update target, for updating one host's agent from the console.

Revision ID: 0012_host_agent_update_to
Revises: 0011_proxmox_guest_flags

Additive: one nullable column.
"""
from alembic import op
import sqlalchemy as sa


revision = '0012_host_agent_update_to'
down_revision = '0011_proxmox_guest_flags'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.add_column(sa.Column('agent_update_to', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.drop_column('agent_update_to')
