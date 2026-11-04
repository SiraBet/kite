"""Baseline schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-05

This is the first migration this project has ever had, so it has to cope
with a database created by ANY earlier kite — not just an empty one.
Before migrations existed, startup called `Base.metadata.create_all()`,
which creates missing TABLES but never adds missing COLUMNS. Columns
added to existing tables over time (Host.proxmox_node,
Host.rollback_backend, Host.agent_version, Job.hostname,
Job.rollback_backend, User.auth_source) therefore reached the models
and every fresh install, but no database that already existed:
create_all() returned successfully and the next query against the old
table raised "no such column".

So this revision reconciles rather than assuming a blank slate:
  - tables that don't exist are created,
  - tables that do exist get any columns they're missing added.

Both halves are driven by FROZEN below, which is a point-in-time COPY of
app/models.py as of this revision. It is frozen on purpose and must
never be edited to track later model changes: a fresh install runs this
revision and then every later one in order, so if this file kept up with
the models it would create a column that a later revision then tries to
add again. Schema changes after this point are ordinary Alembic
revisions -- `alembic revision -m "..."` -- and only this one is
reconciliation.
"""
from alembic import op
import sqlalchemy as sa

revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None

# Point-in-time copy of app/models.py. Frozen — see the module docstring.
FROZEN = sa.MetaData()

sa.Table(
    'audit_log', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ts', sa.DateTime(), nullable=True),
    sa.Column('actor', sa.String(), nullable=False),
    sa.Column('role', sa.String(), nullable=True),
    sa.Column('action', sa.String(), nullable=False),
    sa.Column('detail', sa.String(), nullable=True),
    sa.Column('tone', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'checklist_items', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('text', sa.String(), nullable=False),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'enrollment_tokens', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(), nullable=False),
    sa.Column('hostname', sa.String(), nullable=False),
    sa.Column('team', sa.String(), nullable=True),
    sa.Column('role', sa.String(), nullable=True),
    sa.Column('used', sa.Boolean(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
)

sa.Table(
    'hosts', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('hostname', sa.String(), nullable=False),
    sa.Column('role', sa.String(), nullable=True),
    sa.Column('team', sa.String(), nullable=True),
    sa.Column('os_version', sa.String(), nullable=True),
    sa.Column('os_family', sa.String(), nullable=True),
    sa.Column('smbios_uuid', sa.String(), nullable=True),
    sa.Column('poll_interval_seconds', sa.Integer(), nullable=True),
    sa.Column('proxmox_vmid', sa.Integer(), nullable=True),
    sa.Column('proxmox_node', sa.String(), nullable=True),
    sa.Column('rollback_backend', sa.String(), nullable=True),
    sa.Column('agent_secret_hash', sa.String(), nullable=True),
    sa.Column('agent_version', sa.String(), nullable=True),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('last_patched', sa.DateTime(), nullable=True),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('enrolled_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('hostname')
)

sa.Table(
    'os_script_history', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('os_family', sa.String(), nullable=False),
    sa.Column('stage_name', sa.String(), nullable=False),
    sa.Column('filename', sa.String(), nullable=True),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('uploaded_by', sa.String(), nullable=True),
    sa.Column('uploaded_at', sa.DateTime(), nullable=True),
    sa.Column('note', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'os_scripts', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('os_family', sa.String(), nullable=False),
    sa.Column('stage_name', sa.String(), nullable=False),
    sa.Column('filename', sa.String(), nullable=True),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('tested', sa.Boolean(), nullable=True),
    sa.Column('uploaded_by', sa.String(), nullable=True),
    sa.Column('uploaded_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('os_family', 'stage_name', name='uq_os_family_stage')
)

sa.Table(
    'patch_defs', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('pkg_pattern', sa.String(), nullable=False),
    sa.Column('mode', sa.String(), nullable=False),
    sa.Column('version', sa.String(), nullable=True),
    sa.Column('reason', sa.String(), nullable=True),
    sa.Column('reviewed', sa.String(), nullable=True),
    sa.Column('os_family', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'schedules', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('team', sa.String(), nullable=True),
    sa.Column('day_of_week', sa.Integer(), nullable=False),
    sa.Column('hour', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.Column('ticket_id', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_fired_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'settings', FROZEN,
    sa.Column('key', sa.String(), nullable=False),
    sa.Column('value', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('key')
)

sa.Table(
    'tickets', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ticket_id', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('window_start', sa.Integer(), nullable=True),
    sa.Column('window_end', sa.Integer(), nullable=True),
    sa.Column('requester', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ticket_id')
)

sa.Table(
    'users', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('password_hash', sa.String(), nullable=False),
    sa.Column('role', sa.String(), nullable=False),
    sa.Column('display_name', sa.String(), nullable=True),
    sa.Column('auth_source', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
)

sa.Table(
    'def_history', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('def_id', sa.Integer(), nullable=True),
    sa.Column('pkg_pattern', sa.String(), nullable=True),
    sa.Column('change', sa.String(), nullable=True),
    sa.Column('by', sa.String(), nullable=True),
    sa.Column('at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['def_id'], ['patch_defs.id'], ),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'jobs', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('hostname', sa.String(), nullable=True),
    sa.Column('ticket_id', sa.String(), nullable=False),
    sa.Column('operator', sa.String(), nullable=True),
    sa.Column('operator_role', sa.String(), nullable=True),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('current_stage_index', sa.Integer(), nullable=True),
    sa.Column('window_override_reason', sa.String(), nullable=True),
    sa.Column('rollback_backend', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'sessions', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
)

sa.Table(
    'checklist_confirmations', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('job_id', sa.Integer(), nullable=False),
    sa.Column('item_index', sa.Integer(), nullable=False),
    sa.Column('item_text', sa.String(), nullable=False),
    sa.Column('confirmed_by', sa.String(), nullable=False),
    sa.Column('confirmed_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['job_id'], ['jobs.id'], ),
    sa.PrimaryKeyConstraint('id')
)

sa.Table(
    'job_stages', FROZEN,
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('job_id', sa.Integer(), nullable=False),
    sa.Column('stage_index', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('executor', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=True),
    sa.Column('output', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['job_id'], ['jobs.id'], ),
    sa.PrimaryKeyConstraint('id')
)

# A column added to a table that already has rows needs a value for those
# rows. Only matters where the model declares the column NOT NULL —
# anything nullable is fine left as NULL. Exactly one column needs it:
# User.auth_source, where every row predating the column is by
# definition a local account.
BACKFILL_DEFAULTS = {
    ("users", "auth_source"): "local",
}


def _addable(table_name: str, column: sa.Column) -> sa.Column:
    """
    A detached copy of `column` safe to hand to op.add_column — a Column
    object can only be attached to one Table, and FROZEN already owns
    these. Deliberately relaxed to nullable unless a backfill value is
    known: SQLite refuses "ADD COLUMN ... NOT NULL" outright when there's
    no default to give existing rows, and a stricter constraint is not
    worth failing an upgrade over.
    """
    default = BACKFILL_DEFAULTS.get((table_name, column.name))
    return sa.Column(
        column.name,
        column.type,
        nullable=column.nullable or default is None,
        server_default=sa.text(repr(default)) if default is not None else None,
    )


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    preexisting = set(inspector.get_table_names())

    FROZEN.create_all(bind, checkfirst=True)

    for table in FROZEN.sorted_tables:
        if table.name not in preexisting:
            continue  # just created from FROZEN, so it's already complete
        present = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name not in present:
                op.add_column(table.name, _addable(table.name, column))


def downgrade():
    raise NotImplementedError(
        "0001_baseline is the schema itself — downgrading past it would mean "
        "dropping every table and all fleet history with them. Restore a backup "
        "instead (see controller/INSTALL.md)."
    )
