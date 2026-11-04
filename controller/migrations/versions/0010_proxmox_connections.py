"""Several Proxmox connections: clusters and standalone hosts side by side.

Revision ID: 0010_proxmox_connections
Revises: 0009_network_discovery

- proxmox_connections: one row per Proxmox API endpoint.
- hosts.proxmox_connection_id, proxmox_bridges.connection_id,
  proxmox_guest_nics.connection_id: which connection a VM id or bridge
  belongs to, since VM ids repeat across clusters.
- proxmox_ignored_guests: unique per (connection, vmid) instead of vmid.
  SQLite can't alter a unique constraint in place, so the table is
  rebuilt with its rows copied over.

The existing single connection (Settings or .env) becomes the first row
on the next startup -- see app/proxmox_connections.adopt_legacy_connection
-- which also points existing rows at it. Until then everything reads as
connection None, which the code treats as "the only connection".
"""
from alembic import op
import sqlalchemy as sa


revision = '0010_proxmox_connections'
down_revision = '0009_network_discovery'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('proxmox_connections',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('host', sa.String(), nullable=False),
    sa.Column('node', sa.String(), nullable=True),
    sa.Column('token_id', sa.String(), nullable=False),
    sa.Column('token_secret_enc', sa.String(), nullable=True),
    sa.Column('verify_ssl', sa.Boolean(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('proxmox_connection_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_hosts_proxmox_connection', 'proxmox_connections',
                                    ['proxmox_connection_id'], ['id'])
    with op.batch_alter_table('proxmox_bridges', schema=None) as batch_op:
        batch_op.add_column(sa.Column('connection_id', sa.Integer(), nullable=True))
    with op.batch_alter_table('proxmox_guest_nics', schema=None) as batch_op:
        batch_op.add_column(sa.Column('connection_id', sa.Integer(), nullable=True))

    op.create_table('proxmox_ignored_guests_new',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('connection_id', sa.Integer(), nullable=True),
    sa.Column('vmid', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('connection_id', 'vmid', name='uq_ignored_conn_vmid')
    )
    op.execute("INSERT INTO proxmox_ignored_guests_new (id, connection_id, vmid, reason, created_by, created_at) "
               "SELECT id, NULL, vmid, reason, created_by, created_at FROM proxmox_ignored_guests")
    op.drop_table('proxmox_ignored_guests')
    op.rename_table('proxmox_ignored_guests_new', 'proxmox_ignored_guests')


def downgrade():
    op.create_table('proxmox_ignored_guests_old',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vmid', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vmid')
    )
    # Several connections can ignore the same vmid; keep the first.
    op.execute("INSERT INTO proxmox_ignored_guests_old (id, vmid, reason, created_by, created_at) "
               "SELECT MIN(id), vmid, reason, created_by, created_at FROM proxmox_ignored_guests GROUP BY vmid")
    op.drop_table('proxmox_ignored_guests')
    op.rename_table('proxmox_ignored_guests_old', 'proxmox_ignored_guests')
    with op.batch_alter_table('proxmox_guest_nics', schema=None) as batch_op:
        batch_op.drop_column('connection_id')
    with op.batch_alter_table('proxmox_bridges', schema=None) as batch_op:
        batch_op.drop_column('connection_id')
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_constraint('fk_hosts_proxmox_connection', type_='foreignkey')
        batch_op.drop_column('proxmox_connection_id')
    op.drop_table('proxmox_connections')
