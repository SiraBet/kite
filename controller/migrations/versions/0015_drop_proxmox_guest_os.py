"""Drop proxmox_guest_os: the guest-OS detection that used it was reverted.

Revision ID: 0015_drop_proxmox_guest_os
Revises: 0014_proxmox_guest_os
"""
from alembic import op
import sqlalchemy as sa


revision = '0015_drop_proxmox_guest_os'
down_revision = '0014_proxmox_guest_os'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('proxmox_guest_os')


def downgrade():
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
