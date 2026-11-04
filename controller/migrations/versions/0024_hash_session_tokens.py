"""Store session and enrollment tokens as SHA-256 digests.

Revision ID: 0024_hash_session_tokens
Revises: 0023_machine_groups

Sessions and one-time enrollment tokens were stored as issued, so any
copy of the database -- a backup, which an admin's read-only API token
could download -- held live admin sessions. Each existing value is
replaced by its digest (security.hash_secret), so everyone stays signed
in and unused enrollment tokens keep working. One-way: a downgrade can't
recover the tokens, so it just signs everyone out and drops unused
enrollment tokens.
"""
import hashlib

from alembic import op
import sqlalchemy as sa


revision = '0024_hash_session_tokens'
down_revision = '0023_machine_groups'
branch_labels = None
depends_on = None


def _digest_column(conn, table):
    for row_id, token in conn.execute(sa.text(f"SELECT id, token FROM {table}")).fetchall():
        conn.execute(sa.text(f"UPDATE {table} SET token = :t WHERE id = :i"),
                     {"t": hashlib.sha256(token.encode()).hexdigest(), "i": row_id})


def upgrade():
    conn = op.get_bind()
    _digest_column(conn, "sessions")
    _digest_column(conn, "enrollment_tokens")


def downgrade():
    conn = op.get_bind()
    conn.execute(sa.text("DELETE FROM sessions"))
    conn.execute(sa.text("DELETE FROM enrollment_tokens WHERE used = 0"))
