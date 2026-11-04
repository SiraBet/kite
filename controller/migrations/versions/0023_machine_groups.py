"""Machine groups, and update rules that apply to OS families, groups or machines.

Revision ID: 0023_machine_groups
Revises: 0022_script_groups

Script groups were a name on each host (hosts.script_group); they become
real groups a machine can be in several of. Each name in use becomes a
group with the same machines, and its scripts stay where they are (they
are keyed by the group's name). An update rule limited to one OS family
gets that as its target; a rule for every OS family keeps no targets,
which still means every machine.
"""
from datetime import datetime

from alembic import op
import sqlalchemy as sa


revision = '0023_machine_groups'
down_revision = '0022_script_groups'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('machine_groups',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(), nullable=False),
                    sa.Column('description', sa.String(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('name'))
    op.create_table('machine_group_members',
                    sa.Column('group_id', sa.Integer(), nullable=False),
                    sa.Column('host_id', sa.Integer(), nullable=False),
                    sa.ForeignKeyConstraint(['group_id'], ['machine_groups.id']),
                    sa.ForeignKeyConstraint(['host_id'], ['hosts.id']),
                    sa.PrimaryKeyConstraint('group_id', 'host_id'))
    op.create_index('ix_machine_group_members_host_id', 'machine_group_members', ['host_id'])
    op.create_table('patch_def_targets',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('def_id', sa.Integer(), nullable=False),
                    sa.Column('kind', sa.String(), nullable=False),
                    sa.Column('value', sa.String(), nullable=False),
                    sa.ForeignKeyConstraint(['def_id'], ['patch_defs.id']),
                    sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_patch_def_targets_def_id', 'patch_def_targets', ['def_id'])

    conn = op.get_bind()
    now = datetime.utcnow()
    for (name,) in conn.execute(sa.text(
            "SELECT DISTINCT script_group FROM hosts WHERE script_group IS NOT NULL AND script_group != ''")).fetchall():
        conn.execute(sa.text("INSERT INTO machine_groups (name, description, created_at) VALUES (:n, '', :t)"),
                     {"n": name, "t": now})
        gid = conn.execute(sa.text("SELECT id FROM machine_groups WHERE name = :n"), {"n": name}).scalar()
        conn.execute(sa.text("INSERT INTO machine_group_members (group_id, host_id) "
                             "SELECT :g, id FROM hosts WHERE script_group = :n"), {"g": gid, "n": name})
    conn.execute(sa.text("INSERT INTO patch_def_targets (def_id, kind, value) "
                         "SELECT id, 'os', os_family FROM patch_defs WHERE os_family IS NOT NULL AND os_family != ''"))
    with op.batch_alter_table('hosts') as batch:
        batch.drop_column('script_group')


def downgrade():
    with op.batch_alter_table('hosts') as batch:
        batch.add_column(sa.Column('script_group', sa.String(), nullable=True))
    op.drop_index('ix_patch_def_targets_def_id', 'patch_def_targets')
    op.drop_table('patch_def_targets')
    op.drop_index('ix_machine_group_members_host_id', 'machine_group_members')
    op.drop_table('machine_group_members')
    op.drop_table('machine_groups')
