"""Container inventory.

Revision ID: 0002_containers
Revises: 0001_baseline

Adds the table agents report their observed containers into. Purely
additive: an existing install gains an empty table, and hosts running an
older agent that reports nothing simply have no rows.
"""
from alembic import op
import sqlalchemy as sa


revision = '0002_containers'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('hosts', sa.Column('container_runtime', sa.String(), nullable=True))
    op.create_table('containers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('container_id', sa.String(), nullable=True),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('image', sa.String(), nullable=False),
    sa.Column('image_digest', sa.String(), nullable=True),
    sa.Column('state', sa.String(), nullable=True),
    sa.Column('managed_by', sa.String(), nullable=True),
    sa.Column('compose_project', sa.String(), nullable=True),
    sa.Column('pinned', sa.Boolean(), nullable=True),
    sa.Column('update_available', sa.Boolean(), nullable=True),
    sa.Column('reported_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('containers')
    op.drop_column('hosts', 'container_runtime')
