"""API tokens: bearer credentials for non-browser clients (the MCP server).

Revision ID: 0007_api_tokens
Revises: 0006_third_party_sources

Additive: one new table, nothing existing changes. An install that never
creates a token is unaffected.
"""
from alembic import op
import sqlalchemy as sa


revision = '0007_api_tokens'
down_revision = '0006_third_party_sources'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('api_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('token_hash', sa.String(), nullable=False),
    sa.Column('prefix', sa.String(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('scope', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('last_used_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )


def downgrade():
    op.drop_table('api_tokens')
