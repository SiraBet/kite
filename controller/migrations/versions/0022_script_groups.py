"""Custom script groups: machines assigned to a named set of stage scripts.

Revision ID: 0022_script_groups
Revises: 0021_windows_os_vulns

Additive: one nullable column.
"""
from alembic import op
import sqlalchemy as sa


revision = '0022_script_groups'
down_revision = '0021_windows_os_vulns'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.add_column(sa.Column('script_group', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.drop_column('script_group')
