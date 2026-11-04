"""Installed software per host, the base for vulnerability matching.

Revision ID: 0018_host_software
Revises: 0017_users_must_change_password

Additive: one new table, two nullable columns on hosts.
"""
from alembic import op
import sqlalchemy as sa


revision = '0018_host_software'
down_revision = '0017_users_must_change_password'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('host_software',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
    sa.Column('kind', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('version', sa.String(), nullable=True),
    sa.Column('arch', sa.String(), nullable=True),
    sa.Column('source_name', sa.String(), nullable=True),
    sa.Column('source_version', sa.String(), nullable=True),
    sa.Column('publisher', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_host_software_host_id', 'host_software', ['host_id'])
    with op.batch_alter_table('hosts') as batch:
        batch.add_column(sa.Column('software_hash', sa.String(), nullable=True))
        batch.add_column(sa.Column('software_reported_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.drop_column('software_reported_at')
        batch.drop_column('software_hash')
    op.drop_index('ix_host_software_host_id', 'host_software')
    op.drop_table('host_software')
