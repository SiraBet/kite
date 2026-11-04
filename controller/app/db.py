import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DB_PATH = os.environ.get("KITE_DB", "kite.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """
    This app's real traffic shape is many enrolled agents polling/
    reporting around the same time, each doing a quick write
    (host.last_seen etc.) -- a load test simulating 40 concurrent agent
    check-ins against SQLAlchemy's plain defaults reproduced a ~6.5%
    hard-failure rate ("database is locked") and multi-second p99
    latency. Two pragmas fix that at negligible cost to everyone else:

    - WAL mode lets readers and a writer run concurrently instead of
      blocking each other on every write (SQLite's default rollback
      journal serializes all of that). Sticky in the DB file once set,
      but cheap/idempotent to re-set on every new connection.
    - synchronous=NORMAL is WAL mode's standard pairing -- still safe
      against corruption on an app crash, only risks losing the last
      few not-yet-checkpointed commits on an OS crash/power loss, a
      trade a self-hosted deployment on its own hardware can accept.
    - busy_timeout makes a connection that finds the DB locked wait and
      retry (up to this many ms) instead of raising immediately --
      SQLAlchemy's default is 0 (fail instantly).
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# How many pre-migration copies to keep; 0 keeps every one.
BACKUPS_KEEP = int(os.environ.get("KITE_DB_BACKUPS_KEEP", "5"))


def _pending_revision(cfg) -> bool:
    """Whether `upgrade head` would actually change anything."""
    from alembic.migration import MigrationContext
    from alembic.script import ScriptDirectory

    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
    return current != ScriptDirectory.from_config(cfg).get_current_head()


def backup_database() -> Path:
    """
    Consistent copy of the SQLite database, via sqlite3's online backup
    API rather than a file copy. That distinction matters here: this
    project runs in WAL mode (see the pragmas above), where recent
    commits live in a separate -wal file — so `cp kite.db backup.db`
    can silently produce a backup missing the newest writes, or a torn
    one if an agent commits mid-copy. The backup API takes care of both.

    Returns the path written. Backups land beside the database itself,
    which is the one directory the service is already guaranteed to be
    able to write to.
    """
    import sqlite3
    from datetime import datetime

    db_file = Path(DB_PATH).resolve()
    target = db_file.with_name(f"{db_file.stem}.pre-migration-{datetime.now():%Y%m%d-%H%M%S}{db_file.suffix}")
    source = sqlite3.connect(str(db_file))
    try:
        destination = sqlite3.connect(str(target))
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()
    prune_backups(db_file)
    return target


def prune_backups(db_file: Path, keep: int = None) -> list:
    """
    Delete all but the newest `keep` pre-migration copies of `db_file`.
    Each one is a full copy of the database, and nothing else ever
    removes them, so on an install that upgrades often they would grow
    without limit. The timestamp in the name sorts in time order.
    Returns the paths removed.
    """
    keep = BACKUPS_KEEP if keep is None else keep
    if keep <= 0:
        return []
    copies = sorted(db_file.parent.glob(f"{db_file.stem}.pre-migration-*{db_file.suffix}"))
    removed = []
    for old in copies[:-keep]:
        try:
            old.unlink()
            removed.append(old)
        except OSError:
            pass
    return removed


def init_db():
    """
    Bring the schema up to date, then hand back a usable database.

    Alembic rather than create_all(): create_all() only creates missing
    *tables*, and silently ignores a table that exists but is missing
    columns. An install upgrading to a newer kite would get no error
    from it and then fail on the first query with "no such column".
    See migrations/versions/0001_baseline.py.

    Run automatically at startup, on purpose: the audience here is
    self-hosters whose upgrade is `git pull` + restart, or
    `docker compose up -d --build`. A migration step they have to know
    to run by hand is a step that gets skipped, and skipping it here
    breaks the controller rather than merely delaying a feature.
    Migrations are cheap and idempotent when there's nothing to do.
    """
    from alembic import command
    from alembic.config import Config

    from .logging_config import logger

    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))

    # Migrations run unattended on startup, which is the right trade for
    # this audience (see the docstring) but does mean a schema change
    # lands without anyone watching. Take a copy first whenever there's
    # actually something to apply, so a bad upgrade is recoverable rather
    # than merely regrettable. Skipped for a brand-new database, where
    # there is nothing yet to lose.
    if Path(DB_PATH).exists() and _pending_revision(cfg):
        backup = backup_database()
        logger.info("schema_migration_pending backup=%s", backup)

    command.upgrade(cfg, "head")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
