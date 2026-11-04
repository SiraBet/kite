"""Indexes on the columns lookups filter on.

Revision ID: 0025_indexes
Revises: 0024_hash_session_tokens

Every agent poll looks up its host's running job, every run page its
stages, every host page its containers and pending updates, and the
activity log is read newest first -- and none of these columns had an
index, so each was a full table scan that grew with the fleet's history.
Names follow SQLAlchemy's index=True convention (ix_<table>_<column>), as
declared on the models.
"""
from alembic import op
import sqlalchemy as sa


revision = '0025_indexes'
down_revision = '0024_hash_session_tokens'
branch_labels = None
depends_on = None

INDEXES = [
    ("jobs", "host_id"),
    ("jobs", "batch_id"),
    ("job_stages", "job_id"),
    ("checklist_confirmations", "job_id"),
    ("audit_log", "ts"),
    ("def_history", "def_id"),
    ("containers", "host_id"),
    ("pending_updates", "host_id"),
    ("host_interfaces", "host_id"),
    ("host_listening_ports", "host_id"),
]


def upgrade():
    existing = {(t, i["name"]) for t in {t for t, _ in INDEXES}
                for i in sa.inspect(op.get_bind()).get_indexes(t)}
    for table, column in INDEXES:
        name = f"ix_{table}_{column}"
        if (table, name) not in existing:
            op.create_index(name, table, [column])


def downgrade():
    for table, column in INDEXES:
        op.drop_index(f"ix_{table}_{column}", table_name=table)
