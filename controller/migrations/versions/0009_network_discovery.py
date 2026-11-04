"""Network discovery: host interfaces and listening ports (agent-reported),
Proxmox bridges and guest NICs (controller-discovered).

Revision ID: 0009_network_discovery
Revises: 0008_proxmox_ignored_guests

Additive: four new tables and four nullable columns on hosts. Hosts on
an older agent simply have no network rows, which reads as "not
reported", never as "no open ports".
"""
from alembic import op
import sqlalchemy as sa


revision = '0009_network_discovery'
down_revision = '0008_proxmox_ignored_guests'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('network_ok', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('network_error', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('network_reported_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('default_gateway', sa.String(), nullable=True))

    op.create_table('host_interfaces',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('mac', sa.String(), nullable=True),
    sa.Column('kind', sa.String(), nullable=True),
    sa.Column('is_up', sa.Boolean(), nullable=True),
    sa.Column('addresses', sa.Text(), nullable=True),
    sa.Column('reported_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('host_listening_ports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('proto', sa.String(), nullable=False),
    sa.Column('address', sa.String(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('process', sa.String(), nullable=True),
    sa.Column('loopback', sa.Boolean(), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=True),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('proxmox_bridges',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('node', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('vlan_id', sa.Integer(), nullable=True),
    sa.Column('vlan_aware', sa.Boolean(), nullable=True),
    sa.Column('ports', sa.String(), nullable=True),
    sa.Column('cidr', sa.String(), nullable=True),
    sa.Column('comments', sa.String(), nullable=True),
    sa.Column('refreshed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('proxmox_guest_nics',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vmid', sa.Integer(), nullable=False),
    sa.Column('node', sa.String(), nullable=True),
    sa.Column('guest_type', sa.String(), nullable=True),
    sa.Column('iface', sa.String(), nullable=True),
    sa.Column('mac', sa.String(), nullable=True),
    sa.Column('bridge', sa.String(), nullable=True),
    sa.Column('vlan_tag', sa.Integer(), nullable=True),
    sa.Column('firewall', sa.Boolean(), nullable=True),
    sa.Column('config_ip', sa.String(), nullable=True),
    sa.Column('refreshed_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('proxmox_guest_nics')
    op.drop_table('proxmox_bridges')
    op.drop_table('host_listening_ports')
    op.drop_table('host_interfaces')
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_column('default_gateway')
        batch_op.drop_column('network_reported_at')
        batch_op.drop_column('network_error')
        batch_op.drop_column('network_ok')
