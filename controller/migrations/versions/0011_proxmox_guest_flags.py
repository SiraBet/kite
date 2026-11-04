"""Gateway promotion/dismissal per Proxmox guest, for the topology tree.

Revision ID: 0011_proxmox_guest_flags
Revises: 0010_proxmox_connections

Additive: one new table.
"""
from alembic import op
import sqlalchemy as sa


revision = '0011_proxmox_guest_flags'
down_revision = '0010_proxmox_connections'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('proxmox_guest_flags',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('connection_id', sa.Integer(), nullable=True),
    sa.Column('vmid', sa.Integer(), nullable=False),
    sa.Column('gateway', sa.Boolean(), nullable=False),
    sa.Column('set_by', sa.String(), nullable=True),
    sa.Column('set_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('connection_id', 'vmid', name='uq_guest_flag_conn_vmid')
    )


def downgrade():
    op.drop_table('proxmox_guest_flags')
