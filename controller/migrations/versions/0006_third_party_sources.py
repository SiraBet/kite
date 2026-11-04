"""Third-party update sources: where a pending update came from.

Revision ID: 0006_third_party_sources
Revises: 0005_risk

Additive. Adds two columns to pending_updates:

  - source: 'os' (dnf/apt/Windows Update) or a third-party manager
    ('winget', 'flatpak', 'snap'). Existing rows are backfilled to 'os',
    which is what every update reported before this migration was.
  - current_version: the installed version, where the source reports one.
    Blank for OS package managers, which only ever gave the target.

No data is dropped and no existing column changes, so a host that has
not re-reported since the upgrade keeps exactly the pending list it had.
"""
from alembic import op
import sqlalchemy as sa


revision = '0006_third_party_sources'
down_revision = '0005_risk'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('pending_updates', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source', sa.String(), nullable=True, server_default='os'))
        batch_op.add_column(sa.Column('current_version', sa.String(), nullable=True, server_default=''))
    # Backfill explicitly rather than leaning on the server_default alone,
    # so the value is right whether or not the DB applied the default to
    # existing rows.
    op.execute("UPDATE pending_updates SET source = 'os' WHERE source IS NULL")
    op.execute("UPDATE pending_updates SET current_version = '' WHERE current_version IS NULL")


def downgrade():
    with op.batch_alter_table('pending_updates', schema=None) as batch_op:
        batch_op.drop_column('current_version')
        batch_op.drop_column('source')
