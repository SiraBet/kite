"""
Daily backups of the controller's database -- fleet history, settings,
scripts, users -- so a failed disk or a bad change isn't the end of it.

Once a day (and on demand from Settings) the live SQLite database is
copied with sqlite's online backup API (consistent even mid-write; see
app/db.py backup_database) and gzipped into STATE_DIR/backups, readable
by the service only. The newest `db_backup_keep` are kept (default 7)
and older ones deleted after every backup; 0 turns backups off.

Restoring is deliberately a manual step on the host (README "Backups"):
stop the service, gunzip one over the database, start it again.
"""
import asyncio
import gzip
import os
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path

from .config import STATE_DIR
from .db import DB_PATH, SessionLocal
from .logging_config import logger
from .settings_store import get_setting

BACKUP_DIR = Path(os.environ.get("KITE_BACKUP_DIR") or (STATE_DIR / "backups"))
NAME = re.compile(r"^kite-(\d{8}-\d{6})\.db\.gz$")
STARTUP_DELAY_SECONDS = 600
PASS_SECONDS = 24 * 3600


def keep_count(db) -> int:
    value = get_setting(db, "db_backup_keep")
    return int(value) if (value or "").isdigit() else 7


def list_backups(backup_dir: Path = None) -> list:
    """Newest first: [{name, size_bytes, taken_at}]."""
    d = backup_dir or BACKUP_DIR
    rows = []
    for f in d.glob("kite-*.db.gz") if d.is_dir() else []:
        m = NAME.match(f.name)
        if m:
            rows.append({"name": f.name, "size_bytes": f.stat().st_size,
                         "taken_at": datetime.strptime(m.group(1), "%Y%m%d-%H%M%S")})
    return sorted(rows, key=lambda r: r["name"], reverse=True)


def take(backup_dir: Path = None, db_file: Path = None) -> Path:
    """One consistent, compressed copy of the live database. Returns its path."""
    d = backup_dir or BACKUP_DIR
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    target = d / f"kite-{datetime.utcnow():%Y%m%d-%H%M%S}.db.gz"
    with tempfile.TemporaryDirectory(dir=d) as tmp:
        raw = Path(tmp) / "copy.db"
        source = sqlite3.connect(str(db_file or Path(DB_PATH).resolve()))
        try:
            dest = sqlite3.connect(str(raw))
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
        part = target.with_suffix(".gz.part")
        with open(raw, "rb") as src, gzip.open(part, "wb", compresslevel=6) as out:
            shutil.copyfileobj(src, out, 1 << 20)
        os.chmod(part, 0o600)
        part.rename(target)
    return target


def prune(keep: int, backup_dir: Path = None) -> list:
    """Delete all but the newest `keep`. Returns the names removed."""
    removed = []
    for row in list_backups(backup_dir)[max(keep, 0):]:
        try:
            ((backup_dir or BACKUP_DIR) / row["name"]).unlink()
            removed.append(row["name"])
        except OSError:
            pass
    return removed


def daily_pass():
    db = SessionLocal()
    try:
        keep = keep_count(db)
        if keep > 0:
            path = take()
            removed = prune(keep)
            logger.info("db_backup taken=%s removed=%d", path.name, len(removed))
        # After the backup, so the day's copy still holds what goes.
        _prune_activity(db)
    finally:
        db.close()


def _prune_activity(db):
    """The activity log is kept for audit_keep_days (Settings → Backups); older entries go once a day."""
    from . import audit
    try:
        days = int(get_setting(db, "audit_keep_days") or 0)
        gone = audit.prune(db, days)
        if gone:
            logger.info("activity_log_pruned removed=%d older_than_days=%d", gone, days)
    except Exception:  # noqa: BLE001 -- never stops the backup loop
        logger.exception("pruning the activity log failed")


async def backup_loop():
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            await asyncio.to_thread(daily_pass)
        except Exception:  # noqa: BLE001 -- one bad pass must never kill the loop
            logger.exception("database backup failed")
        await asyncio.sleep(PASS_SECONDS)
