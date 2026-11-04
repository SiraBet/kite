"""
app/db_backups.py and /backups: a daily, compressed, consistent copy of
the database, only the newest kept; admins list, take and download them.
"""
import gzip
import sqlite3
from unittest.mock import patch

from app import db_backups, models


def _db(path, rows=3):
    con = sqlite3.connect(str(path))
    con.execute("create table t (x)")
    con.executemany("insert into t values (?)", [(i,) for i in range(rows)])
    con.commit()
    con.close()


def test_a_backup_is_a_compressed_owner_only_copy(tmp_path):
    src = tmp_path / "live.db"
    _db(src)
    out = db_backups.take(tmp_path / "backups", src)
    assert db_backups.NAME.match(out.name) and oct(out.stat().st_mode)[-3:] == "600"
    assert oct((tmp_path / "backups").stat().st_mode)[-3:] == "700"
    restored = tmp_path / "restored.db"
    restored.write_bytes(gzip.decompress(out.read_bytes()))
    assert sqlite3.connect(str(restored)).execute("select count(*) from t").fetchone()[0] == 3
    assert [p.name for p in (tmp_path / "backups").iterdir()] == [out.name]   # no temp files left


def test_only_the_newest_are_kept(tmp_path):
    d = tmp_path / "backups"
    d.mkdir()
    for stamp in ("20261020-010000", "20261021-010000", "20261022-010000", "20261023-010000"):
        (d / f"kite-{stamp}.db.gz").write_bytes(b"x")
    (d / "notes.txt").write_text("not ours")
    assert db_backups.prune(2, d) == ["kite-20261021-010000.db.gz", "kite-20261020-010000.db.gz"]
    assert [b["name"] for b in db_backups.list_backups(d)] == ["kite-20261023-010000.db.gz", "kite-20261022-010000.db.gz"]
    assert (d / "notes.txt").exists()


def test_the_daily_pass_follows_the_setting(db, tmp_path):
    from app.settings_store import set_setting

    src = tmp_path / "live.db"
    _db(src)
    with patch.object(db_backups, "BACKUP_DIR", tmp_path / "b"), patch.object(db_backups, "DB_PATH", str(src)):
        set_setting(db, "db_backup_keep", "0")
        db_backups.daily_pass()
        assert not (tmp_path / "b").exists()                     # off: nothing taken
        set_setting(db, "db_backup_keep", "1")
        db_backups.daily_pass()
        assert len(db_backups.list_backups(tmp_path / "b")) == 1
    set_setting(db, "db_backup_keep", "7")


def test_admins_list_take_and_download_backups(client, logged_in, db, tmp_path):
    src = tmp_path / "live.db"
    _db(src)
    with patch.object(db_backups, "BACKUP_DIR", tmp_path / "b"), patch.object(db_backups, "DB_PATH", str(src)):
        logged_in("lead")
        assert client.get("/backups").status_code == 403
        assert client.post("/backups").status_code == 403
        logged_in("admin")
        name = client.post("/backups").json()["name"]
        listed = client.get("/backups").json()
        assert listed["keep"] == 7 and [b["name"] for b in listed["backups"]] == [name]
        got = client.get(f"/backups/{name}")
        assert got.status_code == 200 and gzip.decompress(got.content)[:15] == b"SQLite format 3"
        assert client.get("/backups/..%2Fkite.db").status_code == 404
        assert client.get("/backups/kite-20990101-000000.db.gz").status_code == 404
        assert client.put("/settings/db_backup_keep", json={"value": "999"}).status_code == 400
    actions = {a for (a,) in db.query(models.AuditLog.action).filter(models.AuditLog.action.like("db_backup_%"))}
    assert actions >= {"db_backup_taken", "db_backup_downloaded"}


def test_backups_need_a_console_login_not_an_api_token(client, logged_in, db, tmp_path):
    """
    A backup is the whole database. An admin's read-only API token (the
    kind an MCP client or script holds) must not be able to fetch one.
    """
    src = tmp_path / "live.db"
    _db(src)
    with patch.object(db_backups, "BACKUP_DIR", tmp_path / "b"), patch.object(db_backups, "DB_PATH", str(src)):
        logged_in("admin")
        name = client.post("/backups").json()["name"]
        token = client.post("/tokens", json={"name": "script", "scope": "read", "expires_in_days": 1}).json()["token"]
        cookies = dict(client.cookies)
        client.cookies.clear()
        try:
            for path in ("/backups", f"/backups/{name}"):
                r = client.get(path, headers={"Authorization": f"Bearer {token}"})
                assert r.status_code == 403, (path, r.status_code)
        finally:
            for k, v in cookies.items():
                client.cookies.set(k, v)


def test_sessions_and_enrollment_tokens_are_stored_hashed(client, logged_in, db):
    from app.security import hash_secret

    logged_in("admin")
    cookie = client.cookies.get("kite_session")
    rows = [t for (t,) in db.query(models.Session.token).all()]
    assert cookie not in rows and hash_secret(cookie) in rows
    token = client.post("/enroll/tokens", json={"hostname": "hashed-host"}).json()["token"]
    stored = db.query(models.EnrollmentToken).filter_by(hostname="hashed-host").one().token
    assert stored == hash_secret(token) and stored != token


def test_old_activity_is_pruned_daily_even_without_backups(db):
    from datetime import datetime, timedelta
    from app import audit, db_backups
    from app.settings_store import set_setting
    old = models.AuditLog(actor="t", role="admin", action="prune_test_old", detail="", ts=datetime.utcnow() - timedelta(days=400))
    new = models.AuditLog(actor="t", role="admin", action="prune_test_new", detail="", ts=datetime.utcnow() - timedelta(days=10))
    db.add_all([old, new])
    db.commit()
    set_setting(db, "db_backup_keep", "0")      # backups off: pruning still runs
    try:
        db_backups.daily_pass()
        db.expire_all()
        kept = {a.action for a in db.query(models.AuditLog).filter(models.AuditLog.action.like("prune_test_%"))}
        assert kept == {"prune_test_new"}
        assert audit.prune(db, 0) == 0          # 0 keeps everything
    finally:
        set_setting(db, "db_backup_keep", "7")
        db.query(models.AuditLog).filter(models.AuditLog.action.like("prune_test_%")).delete(synchronize_session=False)
        db.commit()


def test_activity_retention_is_validated(client, logged_in):
    logged_in("admin")
    assert client.put("/settings/audit_keep_days", json={"value": "abc"}).status_code == 400
    assert client.put("/settings/audit_keep_days", json={"value": "90"}).status_code == 200
    client.put("/settings/audit_keep_days", json={"value": "365"})
