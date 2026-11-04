"""Proxmox guests deliberately left unmanaged, for the coverage view.

Revision ID: 0008_proxmox_ignored_guests
Revises: 0007_api_tokens

Additive: one new table.
"""
from alembic import op
import sqlalchemy as sa


revision = '0008_proxmox_ignored_guests'
down_revision = '0007_api_tokens'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('proxmox_ignored_guests',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vmid', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('vmid')
    )


def downgrade():
    op.drop_table('proxmox_ignored_guests')
