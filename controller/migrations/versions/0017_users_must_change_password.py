"""Users whose password someone else chose must replace it at sign-in.

Revision ID: 0017_users_must_change_password
Revises: 0016_batches

Additive: one column, false for every existing account.
"""
from alembic import op
import sqlalchemy as sa


revision = '0017_users_must_change_password'
down_revision = '0016_batches'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('must_change_password', sa.Boolean(), nullable=False,
                                   server_default=sa.false()))


def downgrade():
    with op.batch_alter_table('users') as batch:
        batch.drop_column('must_change_password')
