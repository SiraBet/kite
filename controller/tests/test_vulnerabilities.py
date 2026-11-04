"""
Vulnerability matching (app/vulnerabilities.py): OSV records read into
version ranges, a host's packages matched against them, the first
download and the daily incremental refresh, and the opt-in.

The OSV bucket is replaced by a fake that serves a zip, a
modified_id.csv and single records; nothing goes to the network.
"""
import io
import json
import zipfile
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app import models, vulnerabilities
from app.settings_store import set_setting
from conftest import make_host

H = "c" * 64


def rocky(osv_id, pkgs, cves, summary="Important: security update", modified="2026-01-01T00:00:00Z", major="9"):
    return {"id": osv_id, "upstream": cves, "summary": summary, "modified": modified,
            "references": [{"url": f"https://errata.example/{osv_id}"}],
            "affected": [{"package": {"name": n, "ecosystem": f"Rocky Linux:{major}"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}
                         for n, fixed in pkgs]}


class FakeOSV:
    """Serves {ecosystem: [records]} the way the bucket does."""

    def __init__(self, feeds):
        self.feeds = feeds
        self.calls = []

    def get(self, url, stream=False):
        self.calls.append(url)
        path = url.split(vulnerabilities.BASE_URL + "/", 1)[1]
        top, _, rest = path.replace("%20", " ").partition("/")
        recs = self.feeds.get(top)
        if recs is None:
            raise RuntimeError(f"no vulnerability data published at {url}")
        if rest == "all.zip":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for r in recs:
                    z.writestr(f"{r['id']}.json", json.dumps(r))
            return _Resp(buf.getvalue())
        if rest == "modified_id.csv":
            rows = sorted(((r["modified"], r["id"]) for r in recs), reverse=True)
            return _Resp("\n".join(f"{m},{i}" for m, i in rows).encode())
        return _Resp(json.dumps(next(r for r in recs if f"{r['id']}.json" == rest)).encode())


class _Resp:
    def __init__(self, body):
        self.body = body
        self.text = body.decode("latin-1")
        self.headers = {"Content-Length": str(len(body))}

    def json(self):
        return json.loads(self.body)

    def iter_content(self, n):
        yield self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def feature(db):
    set_setting(db, "vuln_feed_enabled", "true")
    yield
    set_setting(db, "vuln_feed_enabled", "false")
    db.query(models.HostVuln).delete()
    db.query(models.VulnPackage).delete()
    db.query(models.VulnRecord).delete()
    db.query(models.VulnFeed).delete()
    db.commit()


def _software(db, host, items):
    db.query(models.HostSoftware).filter(models.HostSoftware.host_id == host.id).delete()
    for i in items:
        db.add(models.HostSoftware(host_id=host.id, **i))
    host.software_reported_at = datetime.utcnow()
    db.commit()


ROCKY_HOST = [
    {"kind": "rpm", "name": "openssl-libs", "version": "1:3.0.7-25.el9", "source_name": "openssl",
     "source_version": "3.0.7-25.el9"},
    {"kind": "rpm", "name": "curl", "version": "7.76.1-29.el9", "source_name": "curl", "source_version": "7.76.1-29.el9"},
    {"kind": "rpm", "name": "kernel-core", "version": "5.14.0-400.el9"},
    {"kind": "rpm", "name": "perl-DBI", "version": "1.641-10.module+el9.2.0+40+bc090241"},
    {"kind": "rpm", "name": "kernel-core", "version": "5.14.0-500.el9"},
    {"kind": "os", "name": "rocky", "version": "9.4"},
]


def test_records_become_ranges_with_a_severity():
    row, pkgs = vulnerabilities.parse_record(
        rocky("RLSA-1", [("openssl", "1:3.0.7-27.el9")], ["CVE-2026-1"]), {"Rocky Linux:9"})
    assert row["severity"] == "important" and row["cves"] == "CVE-2026-1"
    assert pkgs == [{"ecosystem": "Rocky Linux:9", "name": "openssl", "introduced": "0", "fixed": "1:3.0.7-27.el9"}]
    # another release, no fix named, or withdrawn: nothing kept
    assert vulnerabilities.parse_record(dict(rocky("RLSA-3", [("x", "1-1")], []), withdrawn="2026-01-02T00:00:00Z"),
                                        {"Rocky Linux:9"}) is None
    assert vulnerabilities.parse_record(rocky("RLSA-2", [("x", "1-1")], [], major="8"), {"Rocky Linux:9"}) is None
    unfixed = {"id": "UBUNTU-CVE-1", "affected": [{"package": {"name": "x", "ecosystem": "Ubuntu:24.04:LTS"},
                                                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert vulnerabilities.parse_record(unfixed, {"Ubuntu:24.04:LTS"}) is None
    # Ubuntu's own priority, Debian's urgency, then CVSS
    assert vulnerabilities.record_severity({"severity": [{"type": "Ubuntu", "score": "medium"}]})[0] == "moderate"
    assert vulnerabilities.record_severity({"affected": [{"ecosystem_specific": {"urgency": "high"}}]})[0] == "important"
    assert vulnerabilities.record_severity(
        {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == ("critical", 9.8)
    # RHEL's repo suffix doesn't matter
    rhel = {"id": "RHSA-1", "affected": [{"package": {"name": "x", "ecosystem": "Red Hat:enterprise_linux:9::appstream"},
                                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:1-2"}]}]}]}
    assert vulnerabilities.parse_record(rhel, {"Red Hat:enterprise_linux:9"})


def test_which_data_each_os_needs():
    assert vulnerabilities.target_for("rocky", "9.4")[:2] == ("Rocky Linux", "Rocky Linux:9")
    assert vulnerabilities.target_for("almalinux", "8.10")[:2] == ("AlmaLinux", "AlmaLinux:8")
    assert vulnerabilities.target_for("rhel", "9.2")[:2] == ("Red Hat", "Red Hat:enterprise_linux:9")
    assert vulnerabilities.target_for("ubuntu", "24.04")[:2] == ("Ubuntu", "Ubuntu:24.04:LTS")
    assert vulnerabilities.target_for("ubuntu", "24.10")[:2] == ("Ubuntu", "Ubuntu:24.10")
    assert vulnerabilities.target_for("debian", "12")[:2] == ("Debian", "Debian:12")
    assert vulnerabilities.target_for("Windows 10 Pro", "10.0.19045") is None


def test_download_match_and_daily_refresh(client, logged_in, db, feature):
    host, _ = make_host(db)
    _software(db, host, ROCKY_HOST)
    osv = FakeOSV({"Rocky Linux": [
        rocky("RLSA-1", [("openssl", "1:3.0.7-27.el9"), ("openssl-libs", "1:3.0.7-27.el9")], ["CVE-2026-1", "CVE-2026-2"]),
        rocky("RLSA-2", [("curl", "7.76.1-29.el9")], ["CVE-2026-3"]),                    # already fixed
        rocky("RLSA-3", [("kernel-core", "5.14.0-450.el9")], ["CVE-2026-4"]),            # only the old kernel has it
        rocky("RLSA-4", [("openssl", "1:3.0.7-30.el9")], ["CVE-2026-5"], major="8"),     # other release
        rocky("RLSA-6", [("curl", "7.76.1-30.module+el9.2.0+12+abc")], ["CVE-2026-8"]),  # a module stream's curl
        rocky("RLSA-7", [("perl-DBI", "0:1.641-10.module+el9.2.0+40+0878361a")], ["CVE-2026-9"]),  # same build, other context
    ]})
    with patch.object(vulnerabilities, "_get", osv.get):
        vulnerabilities.refresh_all(db)
    logged_in("viewer")
    got = client.get(f"/hosts/{host.id}/vulnerabilities").json()
    assert got["covered"] and got["feed"] == "Rocky Linux"
    assert [v["cve"] for v in got["items"]] == ["CVE-2026-1", "CVE-2026-2"]
    assert got["counts"]["important"] == 2 and got["counts"]["total"] == 2
    [pkg] = got["items"][0]["packages"]        # binary and source name both hit: shown once
    assert pkg == {"name": "openssl-libs", "installed": "1:3.0.7-25.el9", "fixed": "1:3.0.7-27.el9"}
    assert got["items"][0]["advisories"] == ["RLSA-1"]

    fleet = client.get("/vulnerabilities?cve=2026-1").json()
    assert [v["cve"] for v in fleet["items"]] == ["CVE-2026-1"]
    assert [h["hostname"] for h in fleet["items"][0]["hosts"]] == [host.hostname]
    assert client.get("/vulnerabilities?cve=openssl-libs").json()["total"] == 2
    status = client.get("/vulnerabilities/status").json()
    rocky_feed = next(f for f in status["feeds"] if f["name"] == "Rocky Linux")
    assert rocky_feed["records"] == 5 and rocky_feed["ecosystems"] == ["Rocky Linux:9"] and not rocky_feed["error"]

    # next day: one new advisory, one withdrawn fix -- fetched one by one, no new zip
    osv.feeds["Rocky Linux"].append(rocky("RLSA-5", [("curl", "7.76.1-31.el9")], ["CVE-2026-6"],
                                          summary="Critical: curl", modified="2026-02-01T00:00:00Z"))
    osv.feeds["Rocky Linux"].append(rocky("RLSA-8", [("bash", "5.1.8-10.el9")], ["CVE-2026-10"],
                                          modified="2026-02-02T00:00:00Z"))
    osv.calls.clear()
    writing = []

    def get(url, stream=False):
        # no write may be open while downloading: it would lock the whole database meanwhile
        writing.append(db.connection().connection.dbapi_connection.in_transaction)
        return osv.get(url, stream)

    with patch.object(vulnerabilities, "_get", get):
        vulnerabilities.refresh_all(db)
    assert writing and not any(writing)
    assert not any(u.endswith("Rocky%20Linux/all.zip") for u in osv.calls)
    assert any(u.endswith("RLSA-5.json") for u in osv.calls)
    got = client.get(f"/hosts/{host.id}/vulnerabilities").json()
    assert got["items"][0]["cve"] == "CVE-2026-6" and got["items"][0]["severity"] == "critical"

    # after FULL_RELOAD_DAYS, the whole file again
    db.query(models.VulnFeed).filter(models.VulnFeed.name == "Rocky Linux").update(
        {"loaded_at": datetime.utcnow() - timedelta(days=vulnerabilities.FULL_RELOAD_DAYS + 1)})
    db.commit()
    osv.calls.clear()
    with patch.object(vulnerabilities, "_get", osv.get):
        vulnerabilities.refresh_all(db)
    assert any(u.endswith("Rocky%20Linux/all.zip") for u in osv.calls)
    assert client.get(f"/hosts/{host.id}/vulnerabilities").json()["counts"]["total"] == 3


def test_a_software_report_is_matched_straight_away(client, logged_in, db, feature):
    host, secret = make_host(db)
    osv = FakeOSV({"Rocky Linux": [rocky("RLSA-9", [("openssl-libs", "1:3.0.7-27.el9")], ["CVE-2026-9"])]})
    _software(db, host, ROCKY_HOST)
    with patch.object(vulnerabilities, "_get", osv.get):
        vulnerabilities.refresh_all(db)
    items = [dict(i, version="1:3.0.7-27.el9") if i["name"] == "openssl-libs" else i for i in ROCKY_HOST]
    r = client.post(f"/agent/{host.id}/inventory", headers={"Authorization": f"Bearer {secret}"},
                    json={"runtime": "", "containers": [], "software": {"hash": H, "items": items}})
    assert r.status_code == 200
    logged_in("viewer")
    assert client.get(f"/hosts/{host.id}/vulnerabilities").json()["counts"]["total"] == 0


def test_a_matching_failure_keeps_the_rest_of_the_report(client, db, feature):
    """Matching rolled back the whole inventory report, while the agent was told ok."""
    host, secret = make_host(db)
    with patch.object(vulnerabilities, "match_host", side_effect=RuntimeError("bad record")):
        r = client.post(f"/agent/{host.id}/inventory", headers={"Authorization": f"Bearer {secret}"},
                        json={"runtime": "docker", "software": {"hash": H, "items": ROCKY_HOST},
                              "containers": [{"name": "web", "image": "nginx:1", "state": "running"}]})
    assert r.status_code == 200
    db.expire_all()
    assert db.query(models.HostSoftware).filter_by(host_id=host.id).count() == len(ROCKY_HOST)
    assert db.query(models.Container).filter_by(host_id=host.id).count() == 1
    assert db.get(models.Host, host.id).software_hash == H


def test_a_failed_download_is_reported_and_keeps_the_old_data(client, logged_in, db, feature):
    host, _ = make_host(db)
    _software(db, host, ROCKY_HOST)
    osv = FakeOSV({"Rocky Linux": [rocky("RLSA-1", [("openssl-libs", "1:3.0.7-27.el9")], ["CVE-2026-1"])]})
    with patch.object(vulnerabilities, "_get", osv.get):
        vulnerabilities.refresh_all(db)
    db.query(models.VulnFeed).update({"loaded_at": datetime.utcnow() - timedelta(days=vulnerabilities.FULL_RELOAD_DAYS + 1)})
    db.commit()
    with patch.object(vulnerabilities, "_get", FakeOSV({}).get):
        vulnerabilities.refresh_all(db)
    logged_in("viewer")
    feed = next(f for f in client.get("/vulnerabilities/status").json()["feeds"] if f["name"] == "Rocky Linux")
    assert "no vulnerability data" in feed["error"] and feed["records"] == 1
    assert client.get(f"/hosts/{host.id}/vulnerabilities").json()["counts"]["total"] == 1


def test_off_by_default_and_uncovered_hosts_say_why(client, logged_in, db):
    host, _ = make_host(db)
    _software(db, host, ROCKY_HOST)
    logged_in("viewer")
    got = client.get(f"/hosts/{host.id}/vulnerabilities").json()
    assert not got["covered"] and "off" in got["reason"] and got["items"] == []
    win, _ = make_host(db, os_family="windows")
    _software(db, win, [{"kind": "os", "name": "Windows 10 Pro", "version": "10.0.19045.5011"}])
    other, _ = make_host(db, os_family="other")
    _software(db, other, [{"kind": "os", "name": "opensuse-leap", "version": "15.6"}])
    set_setting(db, "vuln_feed_enabled", "true")
    try:
        assert "operating system itself isn't checked" in client.get(f"/hosts/{other.id}/vulnerabilities").json()["reason"]
        assert "Microsoft's data for Windows 10 Version 22H2 for x64-based Systems hasn't been downloaded" in \
            client.get(f"/hosts/{win.id}/vulnerabilities").json()["reason"]
        assert "hasn't been downloaded" in client.get(f"/hosts/{host.id}/vulnerabilities").json()["reason"]
    finally:
        set_setting(db, "vuln_feed_enabled", "false")


def test_only_an_admin_turns_it_on_and_off_clears_matches(client, logged_in, db, feature):
    set_setting(db, "vuln_feed_enabled", "false")
    logged_in("lead")
    assert client.put("/settings/vuln_feed_enabled", json={"value": "true"}).status_code == 403
    assert client.post("/vulnerabilities/refresh").status_code == 403
    logged_in("admin")
    assert client.post("/vulnerabilities/refresh").status_code == 400
    assert client.put("/settings/vuln_feed_enabled", json={"value": "yes"}).status_code == 400
    with patch.object(vulnerabilities, "refresh_in_background") as started:
        assert client.put("/settings/vuln_feed_enabled", json={"value": "true"}).status_code == 200
    started.assert_called_once()
    host, _ = make_host(db)
    db.add(models.HostVuln(host_id=host.id, cve="CVE-2026-7", package="x"))
    db.commit()
    assert client.put("/settings/vuln_feed_enabled", json={"value": "false"}).status_code == 200
    assert db.query(models.HostVuln).count() == 0
