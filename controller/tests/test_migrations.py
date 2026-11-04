"""
Covers the upgrade path — a database created by an OLDER kite being
brought forward by a NEWER one.

This is the case the project had no coverage for and no mechanism for:
startup used to call Base.metadata.create_all(), which creates missing
tables but never adds missing columns, so an existing install picking up
a newer release got a clean startup followed by "no such column" on the
first query. These tests build genuinely old schemas by hand rather than
from the current models, since building them from the models is exactly
what would hide the bug.

Runs against its own temp database file, not the session-wide one — the
whole point is controlling what schema exists before init_db() runs.
"""
import os
import sqlite3
import subprocess
import sys
import tempfile

import pytest

# An early schema: a hosts table without proxmox_node, rollback_backend
# or agent_version; a users table without auth_source; a jobs table
# before Job.hostname was denormalized onto it.
_PRE_PHASE_7_SCHEMA = """
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, hostname VARCHAR NOT NULL UNIQUE, role VARCHAR, team VARCHAR,
    os_version VARCHAR, os_family VARCHAR, smbios_uuid VARCHAR, poll_interval_seconds INTEGER,
    proxmox_vmid INTEGER, agent_secret_hash VARCHAR, last_seen DATETIME, last_patched DATETIME,
    status VARCHAR, enrolled_at DATETIME, created_at DATETIME);
CREATE TABLE users (
    id INTEGER PRIMARY KEY, username VARCHAR NOT NULL UNIQUE, password_hash VARCHAR NOT NULL,
    role VARCHAR NOT NULL, display_name VARCHAR, created_at DATETIME);
CREATE TABLE jobs (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, ticket_id VARCHAR NOT NULL,
    operator VARCHAR, operator_role VARCHAR, status VARCHAR, current_stage_index INTEGER,
    window_override_reason VARCHAR, created_at DATETIME, updated_at DATETIME);
INSERT INTO hosts (hostname, status, os_family) VALUES ('web01', 'healthy', 'rocky8');
INSERT INTO users (username, password_hash, role, display_name) VALUES ('admin', 'salt$digest', 'admin', 'Admin');
INSERT INTO jobs (host_id, ticket_id, status) VALUES (1, 'CHG-1', 'done');
"""


def _run_in_subprocess(db_path: str, code: str):
    """
    app/db.py binds its engine to KITE_DB at import time, and the
    test session has already imported it against the shared test DB — so
    pointing at a different database means a fresh interpreter, not just
    a different env var.
    """
    env = {**os.environ, "KITE_DB": db_path, "KITE_ENROLL_SECRET": "test-enroll-secret"}
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    return result.stdout


@pytest.fixture
def old_db():
    path = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(path)
    con.executescript(_PRE_PHASE_7_SCHEMA)
    con.commit()
    con.close()
    yield path
    _cleanup(path)


def _cleanup(path: str):
    """Removes the DB, its WAL sidecars, and any pre-migration backup of it."""
    import glob
    from pathlib import Path

    db = Path(path)
    for leftover in [path + s for s in ("", "-wal", "-shm")] + glob.glob(
        str(db.with_name(db.stem + ".pre-migration-*"))
    ):
        try:
            os.remove(leftover)
        except OSError:
            pass


def test_upgrading_an_old_database_adds_the_missing_columns(old_db):
    out = _run_in_subprocess(old_db, """
from app.db import init_db, SessionLocal
from app import models
init_db()
db = SessionLocal()
host = db.query(models.Host).one()
print("hostname", host.hostname)
print("agent_version", repr(host.agent_version))
print("proxmox_node", repr(host.proxmox_node))
print("rollback_backend", repr(host.rollback_backend))
print("job_hostname", repr(db.query(models.Job).one().hostname))
""")
    # Querying at all is the assertion that matters — this raised
    # "no such column" before migrations existed.
    assert "hostname web01" in out
    assert "agent_version None" in out
    assert "proxmox_node None" in out
    assert "job_hostname None" in out


def test_upgrade_preserves_existing_rows(old_db):
    out = _run_in_subprocess(old_db, """
from app.db import init_db, SessionLocal
from app import models
init_db()
db = SessionLocal()
print("hosts", db.query(models.Host).count())
print("users", db.query(models.User).count())
print("jobs", db.query(models.Job).count())
print("password_hash", db.query(models.User).one().password_hash)
""")
    assert "hosts 1" in out
    assert "users 1" in out
    assert "jobs 1" in out
    assert "password_hash salt$digest" in out  # untouched, not reset by the upgrade


def test_not_null_column_added_to_populated_table_is_backfilled(old_db):
    """
    User.auth_source is NOT NULL in the model but was added to an
    already-populated table. A row that predates it has to end up
    'local'; a plain ADD COLUMN would leave it NULL, or fail outright
    on SQLite.
    """
    out = _run_in_subprocess(old_db, """
from app.db import init_db, SessionLocal
from app import models
init_db()
print("auth_source", repr(SessionLocal().query(models.User).one().auth_source))
""")
    assert "auth_source 'local'" in out


def test_init_db_is_idempotent(old_db):
    """Startup runs this every time, so a second run must be a no-op."""
    out = _run_in_subprocess(old_db, """
from app.db import init_db, SessionLocal
from app import models
init_db()
init_db()
init_db()
print("hosts", SessionLocal().query(models.Host).count())
""")
    assert "hosts 1" in out


def test_fresh_database_gets_the_full_schema():
    path = tempfile.mktemp(suffix=".db")
    try:
        out = _run_in_subprocess(path, """
import sqlalchemy as sa
from app.db import init_db, engine
from app.models import Base
init_db()
missing = set(Base.metadata.tables) - set(sa.inspect(engine).get_table_names())
print("missing", sorted(missing))
""")
        assert "missing []" in out
    finally:
        _cleanup(path)


def test_pending_migration_takes_a_backup_first(old_db):
    """
    Migrations apply unattended on startup, so the copy taken before one
    lands is the only thing standing between a bad upgrade and a lost
    fleet history.
    """
    out = _run_in_subprocess(old_db, """
import glob
from pathlib import Path
from app.db import init_db, DB_PATH
# Scoped to this database's own name -- every test here uses a temp file
# in the same shared directory, so a bare *.pre-migration-* glob would
# also count copies other tests left behind.
db = Path(DB_PATH).resolve()
pattern = str(db.with_name(db.stem + ".pre-migration-*"))
init_db()
print("after_migrating", len(glob.glob(pattern)))
init_db()
print("after_noop", len(glob.glob(pattern)))
""")
    assert "after_migrating 1" in out
    # Nothing left to apply the second time, so no second copy piles up.
    assert "after_noop 1" in out


def test_backup_captures_rows_committed_in_wal(old_db):
    """
    A plain file copy can miss commits still sitting in the -wal file.
    backup_database() uses sqlite3's online backup API precisely so it
    doesn't — assert on a row written after WAL mode is active.
    """
    out = _run_in_subprocess(old_db, """
import sqlite3
from app.db import init_db, backup_database, SessionLocal
from app import models
init_db()
db = SessionLocal()
db.add(models.Host(hostname="written-into-wal", status="healthy"))
db.commit()
path = backup_database()
con = sqlite3.connect(str(path))
print("in_backup", con.execute("select count(*) from hosts where hostname='written-into-wal'").fetchone()[0])
""")
    assert "in_backup 1" in out


def test_models_and_migrations_have_not_drifted():
    """
    Fails when app/models.py has a table or column that no migration
    creates — i.e. someone changed the models and forgot the revision.
    Catching that here is the whole point of having migrations: without
    it, the change works on the author's fresh DB and breaks on every
    existing install, which is exactly the bug this suite exists for.
    """
    path = tempfile.mktemp(suffix=".db")
    try:
        out = _run_in_subprocess(path, """
import sqlalchemy as sa
from app.db import init_db, engine
from app.models import Base
init_db()
inspector = sa.inspect(engine)
live = {t: {c["name"] for c in inspector.get_columns(t)} for t in inspector.get_table_names()}
drift = []
for name, table in Base.metadata.tables.items():
    if name not in live:
        drift.append(name + " (whole table)")
        continue
    for column in table.columns:
        if column.name not in live[name]:
            drift.append(name + "." + column.name)
print("drift", sorted(drift))
""")
        assert "drift []" in out, (
            "app/models.py has schema no migration creates — add an Alembic "
            f"revision for it (`cd controller && alembic revision -m ...`).\n{out}"
        )
    finally:
        _cleanup(path)


def test_only_the_newest_backups_are_kept(tmp_path):
    from app.db import prune_backups

    db = tmp_path / "fleet.db"
    db.write_bytes(b"")
    stamps = ["20250101-000000", "20250102-000000", "20250103-000000", "20250104-000000"]
    for s in stamps:
        (tmp_path / f"fleet.pre-migration-{s}.db").write_bytes(b"x")
    other = tmp_path / "other.pre-migration-20240101-000000.db"
    other.write_bytes(b"x")

    removed = prune_backups(db, keep=2)
    assert sorted(p.name for p in removed) == [f"fleet.pre-migration-{s}.db" for s in stamps[:2]]
    left = sorted(p.name for p in tmp_path.glob("fleet.pre-migration-*"))
    assert left == [f"fleet.pre-migration-{s}.db" for s in stamps[2:]]
    # another database's copies are not this one's to delete
    assert other.exists()
    # 0 turns the cleanup off
    assert prune_backups(db, keep=0) == []


def test_console_files_are_rechecked_after_an_upgrade(client):
    """
    A browser must not keep running the previous release's JavaScript
    against the new API: the console's files say no-cache, and an
    unchanged one is a cheap 304.
    """
    r = client.get("/ui/js/app.js")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"
    again = client.get("/ui/js/app.js", headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304
    assert "no-cache" in client.get("/").headers.get("cache-control", "")
    assert "cache-control" not in client.get("/health").headers


def test_existing_sessions_and_enrollment_tokens_are_hashed_in_place():
    """
    0024: stored session and enrollment tokens become their SHA-256
    digests, so a database copy holds nothing a browser could replay --
    and nobody is signed out, since a cookie still hashes to its row.
    """
    path = tempfile.mktemp(suffix=".db")
    try:
        out = _run_in_subprocess(path, """
import hashlib, sqlite3
from alembic import command
from alembic.config import Config
from app.db import PROJECT_ROOT, DB_PATH
cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
command.upgrade(cfg, "0023_machine_groups")
con = sqlite3.connect(DB_PATH)
con.execute("INSERT INTO users (id, username, password_hash, role, auth_source, must_change_password) VALUES (1, 'a', 'x', 'admin', 'local', 0)")
con.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ('cookie-value', 1, '2026-01-01', '2099-01-01')")
con.execute("INSERT INTO enrollment_tokens (token, hostname, used) VALUES ('enrol-value', 'h', 0)")
con.commit(); con.close()
command.upgrade(cfg, "head")
con = sqlite3.connect(DB_PATH)
print("session", con.execute("select token from sessions").fetchone()[0] == hashlib.sha256(b"cookie-value").hexdigest())
print("enrol", con.execute("select token from enrollment_tokens").fetchone()[0] == hashlib.sha256(b"enrol-value").hexdigest())
""")
        assert "session True" in out and "enrol True" in out
    finally:
        _cleanup(path)


def test_lookup_columns_are_indexed_and_match_the_models():
    """0025: the columns polls, run pages and the activity log filter on are indexed."""
    path = tempfile.mktemp(suffix=".db")
    try:
        out = _run_in_subprocess(path, """
import sqlite3
from alembic import command
from alembic.config import Config
from app.db import PROJECT_ROOT, DB_PATH
from app import models
cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
command.upgrade(cfg, "head")
con = sqlite3.connect(DB_PATH)
have = {r[0] for r in con.execute("select name from sqlite_master where type='index'")}
declared = {ix.name for t in models.Base.metadata.tables.values() for ix in t.indexes}
print("missing", sorted(declared - have))
print("jobs", "ix_jobs_host_id" in have, "audit", "ix_audit_log_ts" in have)
plan = " ".join(str(r) for r in con.execute("explain query plan select id from jobs where host_id = 1 and status = 'running'"))
print("uses_index", "ix_jobs_host_id" in plan)
command.downgrade(cfg, "0024_hash_session_tokens")
command.upgrade(cfg, "head")
print("roundtrip ok")
""")
        assert "missing []" in out and "jobs True audit True" in out and "uses_index True" in out
        assert "roundtrip ok" in out
    finally:
        _cleanup(path)


def test_older_duplicate_active_runs_are_cancelled_then_one_is_enforced():
    """0026: keep the newest active run per host, cancel the rest, then enforce one."""
    path = tempfile.mktemp(suffix=".db")
    try:
        out = _run_in_subprocess(path, """
import sqlite3
from alembic import command
from alembic.config import Config
from app.db import PROJECT_ROOT, DB_PATH
cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
command.upgrade(cfg, "0025_indexes")
con = sqlite3.connect(DB_PATH)
for i, status in ((1, 'running'), (2, 'queued'), (3, 'done')):
    con.execute("INSERT INTO jobs (id, host_id, ticket_id, status, current_stage_index) VALUES (?, 7, '', ?, 0)", (i, status))
con.execute("INSERT INTO job_stages (job_id, stage_index, name, executor, status) VALUES (1, 0, 'patch', 'agent', 'running')")
con.commit(); con.close()
command.upgrade(cfg, "head")
con = sqlite3.connect(DB_PATH)
print("jobs", con.execute("select id, status from jobs order by id").fetchall())
print("stage", con.execute("select status from job_stages where job_id = 1").fetchone()[0])
try:
    con.execute("INSERT INTO jobs (host_id, ticket_id, status, current_stage_index) VALUES (7, '', 'running', 0)")
    print("second active allowed")
except sqlite3.IntegrityError:
    print("second active refused")
""")
        assert "jobs [(1, 'cancelled'), (2, 'queued'), (3, 'done')]" in out
        assert "stage failed" in out and "second active refused" in out
    finally:
        _cleanup(path)
