"""At most one active run per host, enforced by the database.

Revision ID: 0026_one_active_run_per_host
Revises: 0025_indexes

Starting a run checked for an active one and then inserted, so two
requests at the same moment (a double click, a schedule firing while
someone starts a run) could both pass the check. Agents are only ever
handed the newest, so the other sat "running" forever. A partial unique
index makes the second insert fail instead.

Any host that already has more than one queued/running job keeps the
newest; the others are marked cancelled, with a note, since nothing
was ever going to run them.
"""
from alembic import op
import sqlalchemy as sa


revision = '0026_one_active_run_per_host'
down_revision = '0025_indexes'
branch_labels = None
depends_on = None

INDEX = "uq_jobs_one_active_per_host"


def upgrade():
    conn = op.get_bind()
    extra = conn.execute(sa.text("""
        SELECT j.id FROM jobs j
        WHERE j.status IN ('queued', 'running')
          AND j.id < (SELECT MAX(k.id) FROM jobs k
                      WHERE k.host_id = j.host_id AND k.status IN ('queued', 'running'))
    """)).fetchall()
    for (job_id,) in extra:
        conn.execute(sa.text("UPDATE jobs SET status = 'cancelled' WHERE id = :i"), {"i": job_id})
        conn.execute(sa.text("""UPDATE job_stages SET status = 'failed',
                                 output = 'cancelled: a newer run was started on the same machine'
                                 WHERE job_id = :i AND status IN ('pending', 'running')"""), {"i": job_id})
    op.create_index(INDEX, "jobs", ["host_id"], unique=True,
                    sqlite_where=sa.text("status IN ('queued', 'running')"))


def downgrade():
    op.drop_index(INDEX, table_name="jobs")
