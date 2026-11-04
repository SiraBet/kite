"""Pre-update capture of container images.

Revision ID: 0004_container_rollback
Revises: 0003_run_scope

Additive. Existing jobs are backfilled to the 'update' action, which is
what they did — rolling back did not exist when they ran.
"""
from alembic import op
import sqlalchemy as sa


revision = '0004_container_rollback'
down_revision = '0003_run_scope'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('containers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rollback_available', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('rollback_captured_at', sa.DateTime(), nullable=True))

    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('container_action', sa.String(), nullable=True))



    op.execute("UPDATE jobs SET container_action = 'update' WHERE container_action IS NULL")


def downgrade():
    with op.batch_alter_table('jobs', schema=None) as batch_op:
        batch_op.drop_column('container_action')

    with op.batch_alter_table('containers', schema=None) as batch_op:
        batch_op.drop_column('rollback_captured_at')
        batch_op.drop_column('rollback_available')

