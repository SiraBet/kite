"""Third-party software in vulnerability matching: NVD platforms, match source.

Revision ID: 0020_third_party_vulns
Revises: 0019_vulnerabilities

Additive: two nullable columns.
"""
from alembic import op
import sqlalchemy as sa


revision = '0020_third_party_vulns'
down_revision = '0019_vulnerabilities'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vuln_packages') as batch:
        batch.add_column(sa.Column('platforms', sa.String(), nullable=True))
    with op.batch_alter_table('host_vulns') as batch:
        batch.add_column(sa.Column('source', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('host_vulns') as batch:
        batch.drop_column('source')
    with op.batch_alter_table('vuln_packages') as batch:
        batch.drop_column('platforms')
