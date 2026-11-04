"""A run's Proxmox snapshot can be marked Keep, so cleanup leaves it alone.

Revision ID: 0013_job_snapshot_keep
Revises: 0012_host_agent_update_to

Additive: one nullable column.
"""
from alembic import op
import sqlalchemy as sa


revision = '0013_job_snapshot_keep'
down_revision = '0012_host_agent_update_to'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('jobs') as batch:
        batch.add_column(sa.Column('snapshot_keep', sa.Boolean(), nullable=True))


def downgrade():
    with op.batch_alter_table('jobs') as batch:
        batch.drop_column('snapshot_keep')
