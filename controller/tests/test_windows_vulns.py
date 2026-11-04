"""
Windows itself in vulnerability matching (app/windows_os.py): which
Security Update Guide product a machine is, reading the guide's entries,
and the end-to-end match of a machine's build and installed KBs.

Microsoft's API is faked; nothing goes to the network.
"""
import json
from datetime import datetime
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest

from app import models, vulnerabilities, windows_os
from app.settings_store import set_setting
from conftest import make_host


@pytest.mark.parametrize("name,version,release,arch,install,product", [
    ("Windows 10 Pro", "10.0.19045.6000", "22H2", "", "", "Windows 10 Version 22H2 for x64-based Systems"),
    ("Windows 10 Pro", "10.0.19045.6000", "", "AMD64", "Client", "Windows 10 Version 22H2 for x64-based Systems"),
    ("Windows 10 Enterprise", "10.0.19045.6000", "22H2", "x86", "Client", "Windows 10 Version 22H2 for 32-bit Systems"),
    # Windows 11 still calls itself Windows 10 in ProductName
    ("Windows 10 Pro", "10.0.26100.4000", "24H2", "ARM64", "Client", "Windows 11 Version 24H2 for ARM64-based Systems"),
    ("Windows 10 Enterprise LTSC 2019", "10.0.17763.5000", "", "AMD64", "Client", "Windows 10 Version 1809 for x64-based Systems"),
    ("Windows 10 Pro", "10.0.29999.100", "", "AMD64", "Client", None),                       # unknown build, no release
    ("Windows 10 Pro", "10.0.29999.100", "27H1", "AMD64", "Client", "Windows 11 Version 27H1 for x64-based Systems"),
    ("Windows Server 2022 Standard", "10.0.20348.3000", "21H2", "AMD64", "Server", "Windows Server 2022"),
    ("Windows Server 2019 Datacenter", "10.0.17763.5000", "", "AMD64", "Server Core",
     "Windows Server 2019 (Server Core installation)"),
    ("Windows Server 2012 R2 Standard", "..9600.21000", "", "AMD64", "Server", "Windows Server 2012 R2"),
    ("Windows Server 2008 R2", "..7601.27000", "", "AMD64", "Server", None),                  # not in the guide's list here
    ("rocky", "9.4", "", "", "", None),
])
def test_products(name, version, release, arch, install, product):
    assert windows_os.product_for(name, version, release, arch, install) == product


def test_open_when_below_the_fixed_build_and_the_kb_is_missing():
    is_open = windows_os.is_open
    fixes = [("10.0.19045.6100", "KB5000001")]
    assert is_open("10.0.19045.6000", fixes, set()) == ("10.0.19045.6100", "KB5000001")
    assert is_open("10.0.19045.6100", fixes, set()) is None
    assert is_open("10.0.19045.6250", fixes, set()) is None
    assert is_open("10.0.19045.6000", fixes, {"KB5000001"}) is None              # hotpatch: KB in, build unchanged
    assert is_open("10.0.19045.6000", [("10.0.22631.4000", "KB5000002")], set()) is None   # another build line
    # several updates fix it: any one will do, the nearest is the one shown
    assert is_open("10.0.19045.6000", [("10.0.19045.6300", "KB5000003"), ("10.0.19045.6100", "KB5000001")],
                   set()) == ("10.0.19045.6100", "KB5000001")
    assert is_open("10.0.19045.6200", [("10.0.19045.6300", "KB5000003"), ("10.0.19045.6100", "KB5000001")],
                   set()) is None


def _entry(cve, fixed, kb, severity="Important", score="7.8", impact="Elevation of Privilege"):
    return {"cveNumber": cve, "severity": severity, "baseScore": score, "impact": impact,
            "releaseDate": "2026-09-08T07:00:00-07:00",
            "kbArticles": [{"articleName": kb, "fixedBuildNumber": fixed}] if kb else []}


def test_entries_are_read_per_cve():
    product = "Windows 10 Version 22H2 for x64-based Systems"
    parsed = windows_os.parse([
        _entry("CVE-2026-5001", "10.0.19045.6100", "5000001"),
        _entry("CVE-2026-5001", "10.0.19045.6100", "5000001", severity="Critical", score="9.8"),
        _entry("CVE-2026-5002", "", "5000001"),                    # no fixed build: nothing to compare with
        _entry("CVE-2026-5003", "10.0.19045.6100", None),          # no update named
    ], product)
    assert len(parsed) == 1
    row, packages = parsed[0]
    assert row["osv_id"] == "CVE-2026-5001" and row["severity"] == "critical" and row["score"] == "9.8"
    assert row["url"].endswith("/CVE-2026-5001") and "elevation of privilege" in row["summary"]
    assert packages == [{"ecosystem": "msrc", "name": product, "introduced": "0", "fixed": "10.0.19045.6100",
                         "kb": "KB5000001"}]


class FakeGuide:
    """The Security Update Guide's affectedProduct API: {product: [entry, ...]}, 2 per page."""

    def __init__(self, products):
        self.products, self.asked = products, []

    def get(self, url, timeout=None, **kw):
        q = parse_qs(urlparse(url).query)
        product = q["$filter"][0].split("'", 1)[1].rsplit("'", 1)[0]
        skip = int(q.get("$skip", ["0"])[0])
        self.asked.append(product)
        entries = self.products.get(product, [])
        page = {"@odata.count": len(entries), "value": entries[skip:skip + 2]}
        if skip + 2 < len(entries):
            page["@odata.nextLink"] = f"{windows_os.SUG_URL}?$filter={q['$filter'][0]}&$skip={skip + 2}"
        return _Resp(page)


class _Resp:
    status_code = 200

    def __init__(self, data):
        self.data = data

    def json(self):
        return json.loads(json.dumps(self.data))

    def raise_for_status(self):
        pass


@pytest.fixture
def feature(db):
    set_setting(db, "vuln_feed_enabled", "true")
    hosts = []
    yield hosts
    set_setting(db, "vuln_feed_enabled", "false")
    for m in (models.HostVuln, models.VulnPackage, models.VulnRecord, models.VulnFeed):
        db.query(m).delete()
    db.query(models.HostSoftware).filter(models.HostSoftware.host_id.in_(hosts)).delete(synchronize_session=False)
    db.commit()


def _software(db, host, items, hosts):
    hosts.append(host.id)
    for i in items:
        db.add(models.HostSoftware(host_id=host.id, **i))
    host.software_reported_at = datetime.utcnow()
    db.commit()


def test_windows_matched_by_build_and_installed_updates(client, logged_in, db, feature):
    desktop, _ = make_host(db, os_family="windows")
    _software(db, desktop, [
        {"kind": "os", "name": "Windows 10 Pro", "version": "10.0.19045.6000", "publisher": "22H2"},
        {"kind": "kb", "name": "KB5000003", "publisher": "Microsoft"}], feature)
    server, _ = make_host(db, os_family="windows")
    _software(db, server, [
        {"kind": "os", "name": "Windows 10 Pro", "version": "10.0.29999.100", "publisher": "27H1",
         "arch": "ARM64", "source_name": "Client"}], feature)
    win10 = "Windows 10 Version 22H2 for x64-based Systems"
    guide = FakeGuide({
        win10: [
            _entry("CVE-2026-5001", "10.0.19045.6100", "5000001", severity="Critical", score="9.8"),
            _entry("CVE-2026-5002", "10.0.19045.5900", "5000002"),          # fixed by a build it already has
            _entry("CVE-2026-5003", "10.0.19045.6200", "5000003"),          # its KB is installed
            _entry("CVE-2026-5004", "10.0.19045.6200", "5000004", severity="Moderate", score="5.5")],
        # listed in lower case: the second spelling tried
        "Windows 11 version 27H1 for ARM64-based Systems": [_entry("CVE-2026-5005", "10.0.29999.200", "5000005")]})
    with patch.object(vulnerabilities, "_http", guide):
        vulnerabilities.refresh_all(db)
    # only the Windows versions the fleet runs are asked about
    assert set(guide.asked) == {win10, "Windows 11 Version 27H1 for ARM64-based Systems",
                                "Windows 11 version 27H1 for ARM64-based Systems"}

    logged_in("viewer")
    got = client.get(f"/hosts/{desktop.id}/vulnerabilities").json()
    assert got["covered"] and got["ecosystem"] == win10 and got["refreshed_at"]
    assert "Extended Security Updates" in got["os_note"]
    # cumulative: the newest update named fixes them all
    assert got["windows_fix"] == {"fix": "10.0.19045.6200 (KB5000004)", "count": 2}
    assert [v["cve"] for v in got["items"]] == ["CVE-2026-5001", "CVE-2026-5004"]
    top = got["items"][0]
    assert top["source"] == "msrc" and top["severity"] == "critical" and top["advisories"] == ["KB5000001"]
    assert top["packages"] == [{"name": "Windows 10 Pro", "installed": "10.0.19045.6000",
                                "fixed": "10.0.19045.6100 (KB5000001)"}]

    other = client.get(f"/hosts/{server.id}/vulnerabilities").json()
    assert [v["cve"] for v in other["items"]] == ["CVE-2026-5005"] and "Extended Security" not in other["os_note"]

    fleet = client.get("/vulnerabilities?cve=KB5000001").json()
    assert [v["cve"] for v in fleet["items"]] == ["CVE-2026-5001"]
    status = client.get("/vulnerabilities/status").json()
    row = next(f for f in status["feeds"] if f["name"] == "Windows")
    assert row["records"] == 5 and row["refreshed_at"] and not row["error"]
    assert row["ecosystems"] == sorted([win10, "Windows 11 Version 27H1 for ARM64-based Systems"])
    assert not any(f["name"].startswith("MSRC:") for f in status["feeds"])

    # Microsoft unreachable on the next pass: the error shows, the old data still matches
    class Down:
        def get(self, url, **kw):
            import requests
            raise requests.ConnectionError("no route")
    with patch.object(vulnerabilities, "_http", Down()):
        vulnerabilities.refresh_all(db)
    row = next(f for f in client.get("/vulnerabilities/status").json()["feeds"] if f["name"] == "Windows")
    assert "Couldn't connect to Microsoft" in row["error"] and "internet" in row["error"]
    assert "no route" not in row["error"]       # the raw exception goes to the log only
    assert len(client.get(f"/hosts/{desktop.id}/vulnerabilities").json()["items"]) == 2
