"""What OS each Proxmox guest runs, so Enroll can open the right install tab.

Revision ID: 0014_proxmox_guest_os
Revises: 0013_job_snapshot_keep

Additive: one new table. The feature was reverted; 0015 drops the table.
Kept so databases that already ran it still have a path to head.
"""
from alembic import op
import sqlalchemy as sa


revision = '0014_proxmox_guest_os'
down_revision = '0013_job_snapshot_keep'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('proxmox_guest_os',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('connection_id', sa.Integer(), nullable=True),
    sa.Column('vmid', sa.Integer(), nullable=False),
    sa.Column('guest_type', sa.String(), nullable=True),
    sa.Column('ostype', sa.String(), nullable=True),
    sa.Column('agent_enabled', sa.Boolean(), nullable=True),
    sa.Column('os_id', sa.String(), nullable=True),
    sa.Column('os_name', sa.String(), nullable=True),
    sa.Column('os_read_at', sa.DateTime(), nullable=True),
    sa.Column('agent_note', sa.String(), nullable=True),
    sa.Column('refreshed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('connection_id', 'vmid', name='uq_guest_os_conn_vmid')
    )


def downgrade():
    op.drop_table('proxmox_guest_os')
