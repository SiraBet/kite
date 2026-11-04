"""Batches: several machines patched together, one at a time or in parallel.

Revision ID: 0016_batches
Revises: 0015_drop_proxmox_guest_os

Additive: one new table, one nullable column on jobs.
"""
from alembic import op
import sqlalchemy as sa


revision = '0016_batches'
down_revision = '0015_drop_proxmox_guest_os'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('batches',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rollout', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('paused_reason', sa.String(), nullable=True),
    sa.Column('host_ids', sa.Text(), nullable=True),
    sa.Column('next_index', sa.Integer(), nullable=True),
    sa.Column('skipped', sa.Text(), nullable=True),
    sa.Column('settings', sa.Text(), nullable=True),
    sa.Column('operator', sa.String(), nullable=True),
    sa.Column('operator_role', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('jobs') as batch:
        batch.add_column(sa.Column('batch_id', sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table('jobs') as batch:
        batch.drop_column('batch_id')
    op.drop_table('batches')
