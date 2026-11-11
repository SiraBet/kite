"""A schedule can roll out one machine at a time.

Revision ID: 0027_schedule_rollout
Revises: 0026_one_active_run_per_host

Additive: one nullable column. Existing schedules keep NULL and fire on
every machine at once, as before.
"""
from alembic import op
import sqlalchemy as sa


revision = '0027_schedule_rollout'
down_revision = '0026_one_active_run_per_host'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('schedules') as batch:
        batch.add_column(sa.Column('rollout', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('schedules') as batch:
        batch.drop_column('rollout')
