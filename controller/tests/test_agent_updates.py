"""
Updating Linux agents from the console (app/agent_releases.py,
routers/agent_updates.py): what's published, who's behind, and the
self-update signal each agent gets on an idle poll.
"""
import pytest

from app import agent_releases, models
from conftest import make_host

HEADER = "X-Kite-Self-Update"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for name in ["kite-agent-0.1.9-1.noarch.rpm", "kite-agent-0.1.10-1.noarch.rpm",
                 "kite-agent-0.1.6-1.el9.noarch.rpm", "README", "kite-agent-x.rpm"]:
        (tmp_path / name).write_text("")
    monkeypatch.setattr(agent_releases, "REPO_DIR", tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def _no_fleet_target(db):
    yield
    db.query(models.Setting).filter_by(key="agent_target_version").delete()
    db.commit()


def _poll(client, host, secret, version):
    return client.get(f"/agent/{host.id}/jobs/next", params={"agent_version": version},
                      headers={"Authorization": f"Bearer {secret}"})


def test_published_versions_come_from_the_repo_newest_first(repo):
    assert agent_releases.published() == ["0.1.10", "0.1.9", "0.1.6"]     # 0.1.10 > 0.1.9, not string order


def test_update_one_host_then_it_stops_asking(client, logged_in, db, repo):
    host, secret = make_host(db)
    host.os_family = "rocky8"
    db.commit()
    assert HEADER not in _poll(client, host, secret, "0.1.9").headers           # nothing asked yet
    logged_in("admin")
    assert client.post("/agents/updates", json={"version": "0.1.10", "host_id": host.id}).status_code == 200
    assert _poll(client, host, secret, "0.1.9").headers[HEADER] == "0.1.10"
    assert HEADER not in _poll(client, host, secret, "0.1.10").headers          # there: done
    db.refresh(host)
    assert host.agent_update_to is None


def test_the_fleet_target_never_downgrades(client, logged_in, db, repo):
    host, secret = make_host(db)
    host.os_family = "rocky9"
    db.commit()
    logged_in("admin")
    client.post("/agents/updates", json={"version": "0.1.9"})
    assert _poll(client, host, secret, "0.1.8").headers[HEADER] == "0.1.9"
    assert HEADER not in _poll(client, host, secret, "0.1.10").headers          # already newer: left alone


def _bundle(dist, version):
    import io
    import tarfile
    data = f'AGENT_VERSION = "{version}"\n'.encode()
    with tarfile.open(dist / agent_releases.LINUX_AGENT_BUNDLE, "w:gz") as tar:
        info = tarfile.TarInfo("agent-linux/agent.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


@pytest.fixture
def dist(tmp_path, monkeypatch):
    d = tmp_path / "dist"
    d.mkdir()
    monkeypatch.setattr(agent_releases, "DIST_DIR", d)
    from app.routers import downloads
    monkeypatch.setattr(downloads, "DIST_DIR", d)
    return d


def test_status_lists_who_is_behind_on_each_channel(client, logged_in, db, repo, dist):
    _bundle(dist, "0.1.10")
    old, s1 = make_host(db)
    old.os_family = "rocky8"
    deb, s2 = make_host(db)
    deb.os_family = "ubuntu24"
    win, s3 = make_host(db)
    win.os_family = "windows"
    db.commit()
    _poll(client, old, s1, "0.1.8")
    _poll(client, deb, s2, "0.1.8")
    _poll(client, win, s3, "0.4.0")
    logged_in("viewer")
    st = client.get("/agents/updates").json()
    assert st["latest"] == "0.1.10" and st["bundle"] == "0.1.10"
    rows = {r["host_id"]: r for r in st["hosts"]}
    assert rows[old.id]["behind"] and rows[old.id]["can_self_update"]
    assert rows[deb.id]["behind"] and rows[deb.id]["can_self_update"] and rows[deb.id]["latest"] == "0.1.10"
    assert not rows[win.id]["behind"] and not rows[win.id]["can_self_update"]   # its own version line


def test_ubuntu_agents_update_only_to_the_version_the_bundle_holds(client, logged_in, db, repo, dist):
    host, secret = make_host(db)
    host.os_family = "debian12"
    db.commit()
    logged_in("admin")
    assert client.post("/agents/updates", json={"version": "0.1.10", "host_id": host.id}).status_code == 400  # no bundle
    _bundle(dist, "0.1.9")
    client.post("/agents/updates", json={"version": "0.1.10"})          # fleet target the bundle doesn't hold
    assert HEADER not in _poll(client, host, secret, "0.1.8").headers
    client.post("/agents/updates", json={"version": "0.1.9"})
    assert _poll(client, host, secret, "0.1.8").headers[HEADER] == "0.1.9"


def test_the_bundle_download_carries_its_checksum_and_version(client, dist):
    import hashlib
    _bundle(dist, "0.1.12")
    r = client.get("/download/agent-linux")
    assert r.status_code == 200
    assert r.headers["X-Kite-Sha256"] == hashlib.sha256(r.content).hexdigest()
    assert r.headers["X-Kite-Agent-Version"] == "0.1.12"


def test_only_published_versions_and_only_admins(client, logged_in, db, repo):
    host, _ = make_host(db)
    host.os_family = "ubuntu22"
    host.agent_version = "0.1.8"
    db.commit()
    logged_in("lead")
    assert client.post("/agents/updates", json={"version": "0.1.10"}).status_code == 403
    logged_in("admin")
    assert client.post("/agents/updates", json={"version": "9.9.9"}).status_code == 400
    assert client.post("/agents/updates", json={"version": "0.1.10", "host_id": host.id}).status_code == 400  # no bundle here
    assert client.post("/agents/updates", json={"version": "0.1.10"}).json()["fleet_target"] == "0.1.10"
    assert client.delete("/agents/updates").json()["fleet_target"] == ""


def _windows_exe(dist, version, content=b"MZ-agent"):
    (dist / agent_releases.WINDOWS_AGENT).write_bytes(content)
    (dist / (agent_releases.WINDOWS_AGENT + ".version")).write_text(version + "\n")


def test_windows_agents_have_their_own_version_line(client, logged_in, db, repo, dist):
    _windows_exe(dist, "0.5.0")
    new, s1 = make_host(db)
    old, s2 = make_host(db)
    new.os_family = old.os_family = "windows"
    db.commit()
    _poll(client, new, s1, "0.4.9")       # hypothetically self-updating, behind
    _poll(client, old, s2, "0.4.0")       # predates self-update
    logged_in("viewer")
    st = client.get("/agents/updates").json()
    assert st["windows"] == "0.5.0" and st["latest"] == "0.1.10"     # the Linux line isn't mixed in
    rows = {r["host_id"]: r for r in st["hosts"]}
    assert rows[old.id]["behind"] and not rows[old.id]["can_self_update"]   # by hand: 0.4.0 only logs
    assert rows[new.id]["latest"] == "0.5.0"


def test_update_all_means_each_to_the_newest_of_its_kind(client, logged_in, db, repo, dist):
    _windows_exe(dist, "0.6.0")
    _bundle(dist, "0.1.10")
    win, s1 = make_host(db)
    win.os_family = "windows"
    rpm, s2 = make_host(db)
    rpm.os_family = "rocky9"
    deb, s3 = make_host(db)
    deb.os_family = "ubuntu24"
    db.commit()
    logged_in("admin")
    assert client.post("/agents/updates", json={"version": "latest"}).status_code == 200
    assert _poll(client, win, s1, "0.5.0").headers[HEADER] == "0.6.0"
    assert _poll(client, rpm, s2, "0.1.8").headers[HEADER] == "0.1.10"
    assert _poll(client, deb, s3, "0.1.8").headers[HEADER] == "0.1.10"
    assert HEADER not in _poll(client, win, s1, "0.6.0").headers


def test_the_windows_download_carries_its_checksum_and_version(client, dist):
    import hashlib
    _windows_exe(dist, "0.5.0", b"MZ-0.5.0")
    r = client.get("/download/agent/windows")
    assert r.status_code == 200
    assert r.headers["X-Kite-Sha256"] == hashlib.sha256(b"MZ-0.5.0").hexdigest()
    assert r.headers["X-Kite-Agent-Version"] == "0.5.0"
