"""Pending updates, and the severity filter a run can apply.

Revision ID: 0005_risk
Revises: 0004_container_rollback

Additive. Existing jobs and schedules keep an empty severity filter,
which means every available update -- what they already did.
"""
from alembic import op
import sqlalchemy as sa


revision = '0005_risk'
down_revision = '0004_container_rollback'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('pending_updates',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('package', sa.String(), nullable=False),
    sa.Column('new_version', sa.String(), nullable=True),
    sa.Column('advisory', sa.String(), nullable=True),
    sa.Column('severity', sa.String(), nullable=True),
    sa.Column('is_security', sa.Boolean(), nullable=True),
    sa.Column('reported_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('updates_assessed_ok', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('updates_assessed_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('updates_error', sa.String(), nullable=True))

    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('severity_filter', sa.String(), nullable=True))

    with op.batch_alter_table('schedules', schema=None) as batch_op:
        batch_op.add_column(sa.Column('severity_filter', sa.String(), nullable=True))



def downgrade():
    with op.batch_alter_table('schedules', schema=None) as batch_op:
        batch_op.drop_column('severity_filter')

    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_column('severity_filter')

    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_column('updates_error')
        batch_op.drop_column('updates_assessed_at')
        batch_op.drop_column('updates_assessed_ok')

    op.drop_table('pending_updates')
