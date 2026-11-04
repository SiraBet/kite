"""Run scope, and the compose details needed to act on a container.

Revision ID: 0003_run_scope
Revises: 0002_containers

Additive. Existing jobs and schedules are backfilled to the 'os' scope,
which is what they were: container updates did not exist when they were
created, so anything already recorded patched the guest only.
"""
from alembic import op
import sqlalchemy as sa


revision = '0003_run_scope'
down_revision = '0002_containers'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('containers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('compose_service', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('compose_working_dir', sa.String(), nullable=True))

    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scope', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('container_selection', sa.Text(), nullable=True))

    with op.batch_alter_table('schedules', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scope', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('container_selection', sa.Text(), nullable=True))



    # Existing rows predate container support, so 'os' is not a guess.
    op.execute("UPDATE jobs SET scope = 'os' WHERE scope IS NULL")
    op.execute("UPDATE schedules SET scope = 'os' WHERE scope IS NULL")


def downgrade():
    with op.batch_alter_table('schedules', schema=None) as batch_op:
        batch_op.drop_column('container_selection')
        batch_op.drop_column('scope')

    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_column('container_selection')
        batch_op.drop_column('scope')

    with op.batch_alter_table('containers', schema=None) as batch_op:
        batch_op.drop_column('compose_working_dir')
        batch_op.drop_column('compose_service')

