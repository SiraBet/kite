"""Vulnerability data (OSV) and each host's matches against it.

Revision ID: 0019_vulnerabilities
Revises: 0018_host_software

Additive: four new tables, one nullable column on hosts.
"""
from alembic import op
import sqlalchemy as sa


revision = '0019_vulnerabilities'
down_revision = '0018_host_software'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('vuln_feeds',
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('ecosystems', sa.Text(), nullable=True),
    sa.Column('cursor', sa.String(), nullable=True),
    sa.Column('records', sa.Integer(), nullable=True),
    sa.Column('loaded_at', sa.DateTime(), nullable=True),
    sa.Column('refreshed_at', sa.DateTime(), nullable=True),
    sa.Column('attempted_at', sa.DateTime(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('name')
    )
    op.create_table('vuln_records',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('feed', sa.String(), nullable=False),
    sa.Column('osv_id', sa.String(), nullable=False),
    sa.Column('cves', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(), nullable=True),
    sa.Column('score', sa.String(), nullable=True),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('url', sa.String(), nullable=True),
    sa.Column('modified', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('feed', 'osv_id')
    )
    op.create_index('ix_vuln_records_feed', 'vuln_records', ['feed'])
    op.create_table('vuln_packages',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('record_id', sa.Integer(), sa.ForeignKey('vuln_records.id'), nullable=False),
    sa.Column('ecosystem', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('introduced', sa.String(), nullable=True),
    sa.Column('fixed', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vuln_packages_record_id', 'vuln_packages', ['record_id'])
    op.create_index('ix_vuln_packages_ecosystem_name', 'vuln_packages', ['ecosystem', 'name'])
    op.create_table('host_vulns',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
    sa.Column('cve', sa.String(), nullable=False),
    sa.Column('advisories', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(), nullable=True),
    sa.Column('score', sa.String(), nullable=True),
    sa.Column('package', sa.String(), nullable=False),
    sa.Column('installed', sa.String(), nullable=True),
    sa.Column('fixed', sa.String(), nullable=True),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('url', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_host_vulns_host_id', 'host_vulns', ['host_id'])
    op.create_index('ix_host_vulns_cve', 'host_vulns', ['cve'])
    with op.batch_alter_table('hosts') as batch:
        batch.add_column(sa.Column('vulns_matched_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.drop_column('vulns_matched_at')
    op.drop_index('ix_host_vulns_cve', 'host_vulns')
    op.drop_index('ix_host_vulns_host_id', 'host_vulns')
    op.drop_table('host_vulns')
    op.drop_index('ix_vuln_packages_ecosystem_name', 'vuln_packages')
    op.drop_index('ix_vuln_packages_record_id', 'vuln_packages')
    op.drop_table('vuln_packages')
    op.drop_index('ix_vuln_records_feed', 'vuln_records')
    op.drop_table('vuln_records')
    op.drop_table('vuln_feeds')
