"""
Third-party software in vulnerability matching (app/third_party.py):
which installed packages are a vendor's rather than the distribution's,
their upstream versions, NVD's CPE ranges, and the end-to-end match of a
vendor package against OSV's Go advisories and against NVD.

The OSV bucket and NVD's API are both faked; nothing goes to the network.
"""
import io
import json
import zipfile
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app import models, third_party, vulnerabilities
from app.settings_store import set_setting
from conftest import make_host


def _item(kind, name, version, publisher="", source_name=""):
    return SimpleNamespace(kind=kind, name=name, version=version, publisher=publisher, source_name=source_name)


def test_vendor_packages_are_told_from_the_distributions():
    tp = third_party.third_party
    assert tp(_item("rpm", "docker-ce", "3:26.1.2-1.el8", "Docker"), set())
    assert tp(_item("rpm", "nodejs", "2:20.11.1-1nodesource"), set())              # no vendor at all
    assert not tp(_item("rpm", "nodejs", "1:20.11.0-1.module+el9.4.0", "Rocky Enterprise Software Foundation"), set())
    assert tp(_item("deb", "docker-ce", "5:27.3.1-1~ubuntu.24.04~noble"), set())
    assert tp(_item("deb", "nodejs", "18.20.4-1nodesource1"), {"nodejs"})
    assert not tp(_item("deb", "nodejs", "18.19.1+dfsg-6ubuntu5"), {"nodejs"})
    assert not tp(_item("deb", "postgresql-15", "15.8-0+deb12u1"), {"postgresql-15"})
    assert not tp(_item("deb", "nginx", "1.22.1-9", source_name="nginx"), {"nginx"})   # Debian's own, plain version
    assert tp(_item("deb", "nginx", "1.26.2-1~bookworm"), {"nginx"})                   # nginx.org's
    assert tp(_item("app", "Google Chrome", "130.0.6723.92"), set())


def test_products_and_versions():
    assert third_party.product_for("rpm", "docker-ce").label == "Docker Engine"
    assert third_party.product_for("app", "Mozilla Firefox (x64 en-US)").label == "Firefox"
    assert third_party.product_for("app", "Mozilla Firefox ESR (x64 en-US)").label == "Firefox ESR"
    assert third_party.product_for("deb", "libssl3") is None
    assert third_party.product_for("app", "docker-ce") is None                      # kind matters
    uv = third_party.upstream_version
    assert uv("rpm", "3:26.1.2-1.el8") == "26.1.2"
    assert uv("deb", "5:27.3.1-1~ubuntu.24.04~noble") == "27.3.1"
    assert uv("rpm", "2:20.11.1-1nodesource") == "20.11.1"
    assert uv("rpm", "16.4-1PGDG.rhel9") == "16.4"
    assert uv("snap", "130.0-1") == "130"
    assert uv("app", "0.81.0.0") == "0.81"
    assert third_party.compare("26.1.2", "26.1.5") < 0 and third_party.compare("1.10", "1.9") > 0
    assert third_party.clean_version("v26.1.5+incompatible") == "26.1.5"


@pytest.mark.parametrize("version,introduced,fixed,hit", [
    ("26.1.2", "26.0.0", "26.1.5", True),             # Go/OSV: plain bounds
    ("26.1.5", "26.0.0", "26.1.5", False),
    ("25.0.1", "26.0.0", "26.1.5", False),
    ("1.6.32", "", "<1.6.38", True),                  # NVD: operators
    ("12.21", "[12.0", "<12.21", False),
    ("6.0.30", "[6.0.0", "<=6.0.30", True),
    ("6.0.30", "(6.0.30", "<=7", False),
    ("11.0.0", "", "=11.0.0", True),
    ("11.0.1", "", "=11.0.0", False),
])
def test_ranges(version, introduced, fixed, hit):
    assert third_party.in_range(version, introduced, fixed) is hit


def _nvd(cve_id, configurations, score=7.5, status="Analyzed"):
    return {"id": cve_id, "vulnStatus": status, "lastModified": "2026-10-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": f"{cve_id} in a product"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}]},
            "configurations": configurations}


def _conf(*matches, operator="OR"):
    return {"nodes": [{"operator": operator, "cpeMatch": list(matches)}]}


def _m(cpe, vulnerable=True, **bounds):
    return dict({"criteria": cpe, "vulnerable": vulnerable}, **bounds)


def test_nvd_records_read_ranges_platforms_and_skip_unbounded():
    chrome = "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
    rec = _nvd("CVE-2026-2001", [
        {"nodes": [{"cpeMatch": [_m(chrome, versionEndExcluding="130.0.6723.91")]},
                   {"cpeMatch": [_m("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vulnerable=False)]}],
         "operator": "AND"},
        _conf(_m("cpe:2.3:a:google:chrome:129.0.1:*:*:*:*:*:*:*")),
        _conf(_m(chrome)),                                              # every version: no bound
        _conf(_m("cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*", versionEndExcluding="130"))])
    row, pkgs = third_party.parse_nvd(rec, "google:chrome")
    assert row["severity"] == "important" and row["url"].endswith("CVE-2026-2001")
    assert [(p["fixed"], p["platforms"]) for p in pkgs] == [("<130.0.6723.91", "windows"), ("=129.0.1", "")]
    assert third_party.parse_nvd(_nvd("CVE-2026-2002", [], status="Rejected"), "google:chrome") is None
    assert third_party.parse_nvd(_nvd("CVE-2026-2003", []), "google:chrome") is None   # NVD hasn't analysed it


class FakeNVD:
    """NVD's API: {cpe: [cve, ...]}, paged; the first answer for `flaky` is cut off mid-way."""

    def __init__(self, products, flaky=()):
        self.products, self.flaky, self.calls = products, set(flaky), []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(dict(params))
        cpe = params["virtualMatchString"][len("cpe:2.3:a:"):]
        if cpe in self.flaky:
            self.flaky.discard(cpe)
            return _Resp(b'{"totalResults": 3, "vulnerabilities": [{"cve": {"id"', 200)
        cves = self.products.get(cpe, [])
        start, n = params["startIndex"], params["resultsPerPage"]
        return _Resp(json.dumps({"totalResults": len(cves),
                                 "vulnerabilities": [{"cve": c} for c in cves[start:start + n]]}).encode(), 200)


class _Resp:
    def __init__(self, body, status):
        self.body, self.status_code = body, status
        self.text = body.decode("latin-1")
        self.headers = {"Content-Length": str(len(body))}

    def json(self):
        return json.loads(self.body)

    def raise_for_status(self):
        pass

    def iter_content(self, n):
        yield self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_nvd_paging_and_a_cut_off_answer_retried():
    cves = [_nvd(f"CVE-2026-3{i:03d}", [_conf(_m("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
                                                  versionEndExcluding="20.11.2"))]) for i in range(5)]
    fake = FakeNVD({"nodejs:node.js": cves}, flaky={"nodejs:node.js"})
    with patch.object(third_party, "NVD_PAGE", 2), patch.object(third_party, "NVD_GAP_SECONDS", 0):
        got = list(third_party.nvd_fetch(fake, "nodejs:node.js"))
    assert [c["id"] for c in got] == [c["id"] for c in cves]
    assert [c["startIndex"] for c in fake.calls] == [0, 0, 2, 4]


GO_DOCKER = {"id": "GHSA-0000-docker", "aliases": ["CVE-2024-41110"], "summary": "AuthZ plugin bypass",
             "modified": "2026-01-01T00:00:00Z", "database_specific": {"severity": "CRITICAL"},
             "affected": [{"package": {"name": "github.com/docker/docker", "ecosystem": "Go"},
                           "ranges": [{"type": "SEMVER", "events": [{"introduced": "26.0.0"}, {"fixed": "26.1.5"}]}]},
                          {"package": {"name": "github.com/some/other", "ecosystem": "Go"},
                           "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}


class FakeOSV:
    def __init__(self, feeds):
        self.feeds = feeds

    def get(self, url, stream=False):
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
            return _Resp(buf.getvalue(), 200)
        if rest == "modified_id.csv":
            return _Resp("\n".join(f"{r['modified']},{r['id']}" for r in recs).encode(), 200)
        return _Resp(json.dumps(next(r for r in recs if f"{r['id']}.json" == rest)).encode(), 200)


_HOSTS = []


@pytest.fixture
def feature(db):
    set_setting(db, "vuln_feed_enabled", "true")
    yield
    set_setting(db, "vuln_feed_enabled", "false")
    for m in (models.HostVuln, models.VulnPackage, models.VulnRecord, models.VulnFeed):
        db.query(m).delete()
    # what these machines run would change which data other tests' refreshes fetch
    db.query(models.HostSoftware).filter(models.HostSoftware.host_id.in_(_HOSTS)).delete(synchronize_session=False)
    _HOSTS.clear()
    db.commit()


def _software(db, host, items):
    _HOSTS.append(host.id)
    for i in items:
        db.add(models.HostSoftware(host_id=host.id, **i))
    host.software_reported_at = datetime.utcnow()
    db.commit()


def test_vendor_software_matched_from_go_advisories_and_nvd(client, logged_in, db, feature):
    linux, _ = make_host(db)
    _software(db, linux, [
        {"kind": "rpm", "name": "docker-ce", "version": "3:26.1.2-1.el8", "publisher": "Docker"},
        {"kind": "rpm", "name": "nodejs", "version": "2:20.11.1-1nodesource", "publisher": ""},
        {"kind": "rpm", "name": "postgresql16-server", "version": "16.4-1PGDG.rhel9", "publisher": "PostgreSQL Global Development Group"},
        {"kind": "os", "name": "rocky", "version": "9.4"}])
    win, _ = make_host(db, os_family="windows")
    _software(db, win, [
        {"kind": "app", "name": "Google Chrome", "version": "130.0.6723.70", "publisher": "Google LLC"},
        {"kind": "os", "name": "Windows 10 Pro", "version": "10.0.19045.1000"}])
    chrome = "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
    nvd = FakeNVD({
        "nodejs:node.js": [_nvd("CVE-2026-4001", [_conf(_m("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
                                                           versionStartIncluding="18.0.0", versionEndExcluding="20.11.2"))])],
        "postgresql:postgresql": [_nvd("CVE-2026-4002", [_conf(_m("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
                                                                  versionStartIncluding="16.0", versionEndExcluding="16.4"))])],
        "google:chrome": [
            _nvd("CVE-2026-4003", [_conf(_m(chrome, versionEndExcluding="130.0.6723.91"))], score=8.8),
            _nvd("CVE-2026-4004", [{"operator": "AND", "nodes": [
                {"cpeMatch": [_m(chrome, versionEndExcluding="131")]},
                {"cpeMatch": [_m("cpe:2.3:o:google:android:-:*:*:*:*:*:*:*", vulnerable=False)]}]}])]})
    with patch.object(vulnerabilities, "_get", FakeOSV({"Go": [GO_DOCKER], "Rocky Linux": []}).get), \
         patch.object(vulnerabilities, "_http", nvd), patch.object(third_party, "NVD_GAP_SECONDS", 0):
        vulnerabilities.refresh_all(db)
    logged_in("viewer")
    got = client.get(f"/hosts/{linux.id}/vulnerabilities").json()
    by = {v["cve"]: v for v in got["items"]}
    assert set(by) == {"CVE-2024-41110", "CVE-2026-4001"}                 # PostgreSQL 16.4 is the fix: not affected
    docker = by["CVE-2024-41110"]
    assert docker["source"] == "go" and docker["severity"] == "critical" and docker["advisories"] == ["GHSA-0000-docker"]
    assert docker["packages"] == [{"name": "docker-ce", "installed": "3:26.1.2-1.el8", "fixed": "26.1.5"}]
    assert by["CVE-2026-4001"]["source"] == "nvd" and by["CVE-2026-4001"]["packages"][0]["fixed"] == "20.11.2"

    w = client.get(f"/hosts/{win.id}/vulnerabilities").json()
    assert w["covered"] and "hasn't been downloaded yet" in w["os_note"]   # Microsoft's data isn't faked here
    assert [v["cve"] for v in w["items"]] == ["CVE-2026-4003"]            # the Android-only one isn't Windows'
    status = client.get("/vulnerabilities/status").json()
    nvd_row = next(f for f in status["feeds"] if f["name"] == "NVD")
    assert nvd_row["records"] == 4 and nvd_row["refreshed_at"] and not nvd_row["error"]
    assert next(f for f in status["feeds"] if f["name"] == "Go")["records"] == 1   # only modules on the list are kept
    # the queries are the fixed list, whatever the fleet runs
    assert {c["virtualMatchString"] for c in nvd.calls} == {f"cpe:2.3:a:{c}" for c in third_party.nvd_products()}

    # the next day: only what changed, per product
    nvd.calls.clear()
    with patch.object(vulnerabilities, "_get", FakeOSV({"Go": [GO_DOCKER], "Rocky Linux": []}).get), \
         patch.object(vulnerabilities, "_http", nvd), patch.object(third_party, "NVD_GAP_SECONDS", 0):
        vulnerabilities.refresh_all(db)
    assert all("lastModStartDate" in c for c in nvd.calls)


def test_a_distribution_package_of_a_listed_product_is_left_to_the_distribution(db, feature):
    host, _ = make_host(db)
    _software(db, host, [{"kind": "rpm", "name": "nodejs", "version": "1:20.11.0-1.module+el9.4.0",
                          "publisher": "Rocky Enterprise Software Foundation"},
                         {"kind": "os", "name": "rocky", "version": "9.4"}])
    nvd = FakeNVD({"nodejs:node.js": [_nvd("CVE-2026-5001", [_conf(_m("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
                                                                       versionEndExcluding="20.11.2"))])]})
    with patch.object(vulnerabilities, "_get", FakeOSV({"Rocky Linux": []}).get), \
         patch.object(vulnerabilities, "_http", nvd), patch.object(third_party, "NVD_GAP_SECONDS", 0):
        vulnerabilities.refresh_all(db)
    assert db.query(models.HostVuln).filter(models.HostVuln.host_id == host.id).count() == 0


def test_go_major_version_modules():
    applies = third_party.go_module_applies
    assert applies("github.com/containerd/containerd", "1.6.32") and not applies("github.com/containerd/containerd/v2", "1.6.32")
    assert applies("github.com/containerd/containerd/v2", "2.0.1")
    assert applies("github.com/docker/docker", "26.1.2")                  # +incompatible: every major
    assert third_party.product_for("deb", "wazuh-agent") is None           # NVD's "wazuh" is mostly the manager
    assert third_party.product_for("deb", "wazuh-manager").label == "Wazuh"
