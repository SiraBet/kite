"""Windows itself in vulnerability matching: the KB that fixes a CVE.

Revision ID: 0021_windows_os_vulns
Revises: 0020_third_party_vulns

Additive: one nullable column.
"""
from alembic import op
import sqlalchemy as sa


revision = '0021_windows_os_vulns'
down_revision = '0020_third_party_vulns'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vuln_packages') as batch:
        batch.add_column(sa.Column('kb', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('vuln_packages') as batch:
        batch.drop_column('kb')
